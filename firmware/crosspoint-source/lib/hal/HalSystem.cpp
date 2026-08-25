#include "HalSystem.h"

#include <string>

#include "Arduino.h"
#include "HalStorage.h"
#include "Logging.h"
#include "esp_private/esp_cpu_internal.h"
#include "esp_private/esp_system_attr.h"
#include "esp_private/panic_internal.h"

// Never retain panic_abort's verbatim message: assert text can contain paths,
// tokens or arbitrary application data even when every byte is printable.
RTC_NOINIT_ATTR char panicMessage[16];
// These are control-flow metadata, not a register or stack dump. Keeping only
// PC/RA/cause preserves a symbolizable crash signature without retaining
// arbitrary RAM that may hold the Daily Cards bearer or Wi-Fi passwords.
RTC_NOINIT_ATTR uint32_t panicProgramCounter;
RTC_NOINIT_ATTR uint32_t panicReturnAddress;
RTC_NOINIT_ATTR uint32_t panicMachineCause;
// abort() supplies its caller separately from the exception frame. Retain it
// only as a parsed 32-bit value; never retain any bytes from the abort message.
RTC_NOINIT_ATTR uint32_t panicAbortCallerProgramCounter;
RTC_NOINIT_ATTR uint32_t panicAbortCallerPcValidMarker;
// Newlib's assertion handler receives source text that may contain private
// paths or application data. Retain only the wrapper's control-flow return
// address, which is the exact callsite immediately after __assert_func.
RTC_NOINIT_ATTR uint32_t panicAssertCallerProgramCounter;
RTC_NOINIT_ATTR uint32_t panicAssertCallerPcValidMarker;

extern "C" {

void __real_panic_abort(const char* message);
void __real_panic_print_backtrace(const void* frame, int core);
void __real___assert_func(const char* file, int line, const char* function, const char* expression);

static DRAM_ATTR const char PANIC_REASON_ASSERT[] = "assert";
static DRAM_ATTR const char PANIC_REASON_ABORT[] = "abort";
static DRAM_ATTR const char PANIC_REASON_STACK_SMASH[] = "stack-smash";
static DRAM_ATTR const char PANIC_REASON_OTHER[] = "other";
static DRAM_ATTR const char PANIC_PREFIX_STACK_SMASH[] = "stack smashing";
static DRAM_ATTR const char PANIC_ABORT_PC_PREFIX[] = "abort() was called at PC 0x";
static DRAM_ATTR const char PANIC_ABORT_PC_CORE_SUFFIX[] = " on core ";
static constexpr uint32_t PANIC_ABORT_CALLER_PC_VALID = 0x58415043U;  // "XAPC"
static constexpr uint32_t PANIC_ASSERT_CALLER_PC_VALID = 0x58535043U;  // "XSPC"

static char IRAM_ATTR panicAsciiLower(const char value) {
  return value >= 'A' && value <= 'Z' ? static_cast<char>(value + ('a' - 'A')) : value;
}

static bool IRAM_ATTR panicStartsWith(const char* message, const char* prefix) {
  if (!message) return false;
  for (size_t index = 0; prefix[index] != '\0'; ++index) {
    if (message[index] == '\0' || panicAsciiLower(message[index]) != prefix[index]) return false;
  }
  return true;
}

static bool IRAM_ATTR panicHexNibble(const char value, uint32_t* nibble) {
  if (value >= '0' && value <= '9') {
    *nibble = static_cast<uint32_t>(value - '0');
    return true;
  }
  if (value >= 'a' && value <= 'f') {
    *nibble = static_cast<uint32_t>(value - 'a' + 10);
    return true;
  }
  if (value >= 'A' && value <= 'F') {
    *nibble = static_cast<uint32_t>(value - 'A' + 10);
    return true;
  }
  return false;
}

static bool IRAM_ATTR parsePanicAbortCallerPc(const char* message, uint32_t* parsedPc) {
  if (!message || !parsedPc) return false;

  size_t offset = 0;
  while (PANIC_ABORT_PC_PREFIX[offset] != '\0') {
    if (message[offset] != PANIC_ABORT_PC_PREFIX[offset]) return false;
    ++offset;
  }

  uint32_t value = 0;
  for (size_t index = 0; index < 8; ++index) {
    uint32_t nibble = 0;
    if (!panicHexNibble(message[offset + index], &nibble)) return false;
    value = (value << 4U) | nibble;
  }
  offset += 8;

  // Current ESP-IDF appends exactly " on core N". Requiring the complete
  // fixed grammar prevents a secret-bearing lookalike from being accepted.
  size_t suffixIndex = 0;
  while (PANIC_ABORT_PC_CORE_SUFFIX[suffixIndex] != '\0') {
    if (message[offset + suffixIndex] != PANIC_ABORT_PC_CORE_SUFFIX[suffixIndex]) return false;
    ++suffixIndex;
  }
  offset += suffixIndex;
  if (message[offset] < '0' || message[offset] > '9' || message[offset + 1] != '\0') return false;

  *parsedPc = value;
  return true;
}

static void IRAM_ATTR storePanicReasonCode(const char* reason) {
  size_t index = 0;
  for (; index + 1 < sizeof(panicMessage) && reason[index] != '\0'; ++index) panicMessage[index] = reason[index];
  panicMessage[index] = '\0';
}

static bool storedPanicReasonEquals(const char* expected) {
  size_t index = 0;
  while (index < sizeof(panicMessage)) {
    if (panicMessage[index] != expected[index]) return false;
    if (expected[index] == '\0') return true;
    ++index;
  }
  return false;
}

static bool storedPanicReasonIsValid() {
  return storedPanicReasonEquals(PANIC_REASON_ASSERT) || storedPanicReasonEquals(PANIC_REASON_ABORT) ||
         storedPanicReasonEquals(PANIC_REASON_STACK_SMASH) || storedPanicReasonEquals(PANIC_REASON_OTHER);
}

void IRAM_ATTR __wrap_panic_abort(const char* message) {
  // Classification is fixed, single-line and IRAM-safe. In particular, the
  // default branch never copies an unknown printable message into RTC memory.
  const char* reason = PANIC_REASON_OTHER;
  if (panicStartsWith(message, PANIC_REASON_ASSERT)) {
    reason = PANIC_REASON_ASSERT;
  } else if (panicStartsWith(message, PANIC_REASON_ABORT)) {
    reason = PANIC_REASON_ABORT;
  } else if (panicStartsWith(message, PANIC_PREFIX_STACK_SMASH) ||
             panicStartsWith(message, PANIC_REASON_STACK_SMASH)) {
    reason = PANIC_REASON_STACK_SMASH;
  }
  storePanicReasonCode(reason);

  // An assertion reaches panic_abort after __wrap___assert_func has retained
  // its callsite. Every other panic must clear that field so stale RTC state
  // cannot be mistaken for evidence from this reboot.
  if (reason != PANIC_REASON_ASSERT) {
    panicAssertCallerProgramCounter = 0;
    panicAssertCallerPcValidMarker = 0;
  }

  // Clear first so a malformed or unrelated panic cannot reuse a retained PC.
  panicAbortCallerProgramCounter = 0;
  panicAbortCallerPcValidMarker = 0;
  uint32_t parsedAbortCallerPc = 0;
  if (parsePanicAbortCallerPc(message, &parsedAbortCallerPc)) {
    panicAbortCallerProgramCounter = parsedAbortCallerPc;
    panicAbortCallerPcValidMarker = PANIC_ABORT_CALLER_PC_VALID;
  }

  __real_panic_abort(message);
}

void IRAM_ATTR __attribute__((noinline))
__wrap___assert_func(const char* file, int line, const char* function, const char* expression) {
  // Never inspect or copy file/function/expression. The return address is
  // bounded control-flow metadata and points directly at the assertion call.
  (void)file;
  (void)line;
  (void)function;
  (void)expression;
  panicAssertCallerProgramCounter =
      static_cast<uint32_t>(reinterpret_cast<uintptr_t>(__builtin_return_address(0)));
  panicAssertCallerPcValidMarker = PANIC_ASSERT_CALLER_PC_VALID;
  storePanicReasonCode(PANIC_REASON_ASSERT);
  __real___assert_func(file, line, function, expression);
}

void IRAM_ATTR __wrap_panic_print_backtrace(const void* frame, int core) {
  if (!frame) {
    __real_panic_print_backtrace(frame, core);
    return;
  }

#if !defined(__riscv)
  __real_panic_print_backtrace(frame, core);
  return;
#else
  const auto* registers = static_cast<const esp_cpu_frame_t*>(frame);
  panicProgramCounter = registers->mepc;
  panicReturnAddress = registers->ra;
  panicMachineCause = registers->mcause;

  __real_panic_print_backtrace(frame, core);
#endif
}
}

namespace HalSystem {

void begin() {
  // Initialize the bounded panic summary and log ring on ordinary boots. After
  // a panic, preserve only the summary until checkPanic() writes it to SD.
  if (!isRebootFromPanic()) {
    clearPanic();
  } else {
    // A CPU lockup may reset without reaching panic_abort. Never construct a
    // std::string from uninitialized RTC bytes: replace anything other than an
    // exact fixed code and discard stale control-flow metadata.
    if (!storedPanicReasonIsValid()) {
      storePanicReasonCode(PANIC_REASON_OTHER);
      panicProgramCounter = 0;
      panicReturnAddress = 0;
      panicMachineCause = 0;
      panicAbortCallerProgramCounter = 0;
      panicAbortCallerPcValidMarker = 0;
      panicAssertCallerProgramCounter = 0;
      panicAssertCallerPcValidMarker = 0;
    } else {
      if (!storedPanicReasonEquals(PANIC_REASON_ABORT) ||
          panicAbortCallerPcValidMarker != PANIC_ABORT_CALLER_PC_VALID) {
        // Only an exact ESP-IDF abort() message may contribute this field.
        panicAbortCallerProgramCounter = 0;
        panicAbortCallerPcValidMarker = 0;
      }
      if (!storedPanicReasonEquals(PANIC_REASON_ASSERT) ||
          panicAssertCallerPcValidMarker != PANIC_ASSERT_CALLER_PC_VALID) {
        // Only the allocation-free __assert_func wrapper may contribute this.
        panicAssertCallerProgramCounter = 0;
        panicAssertCallerPcValidMarker = 0;
      }
    }
    // Retained logs are never exported in a crash report, but still sanitize
    // their index so normal post-reboot logging cannot read corrupt RTC data.
    if (sanitizeLogHead()) {
      clearLastLogs();
    }
  }
}

void checkPanic() {
  if (isRebootFromPanic()) {
    auto panicInfo = getPanicInfo(true);
    auto file = Storage.open("/crash_report.txt", O_WRITE | O_CREAT | O_TRUNC);
    if (file) {
      file.write(panicInfo.c_str(), panicInfo.size());
      file.close();
      LOG_INF("SYS", "Dumped panic info to SD card");
    } else {
      LOG_ERR("SYS", "Failed to open crash_report.txt for writing");
    }
  }
}

void clearPanic() {
  panicMessage[0] = '\0';
  panicProgramCounter = 0;
  panicReturnAddress = 0;
  panicMachineCause = 0;
  panicAbortCallerProgramCounter = 0;
  panicAbortCallerPcValidMarker = 0;
  panicAssertCallerProgramCounter = 0;
  panicAssertCallerPcValidMarker = 0;
  clearLastLogs();
}

std::string getPanicInfo(bool full) {
  if (!full) {
    return panicMessage;
  } else {
    std::string info;

    info += "CrossPoint version: " CROSSPOINT_VERSION;
    info += "\n\nPanic reason: " + std::string(panicMessage);

    auto toHex = [](uint32_t value) {
      char buffer[9];
      snprintf(buffer, sizeof(buffer), "%08X", value);
      return std::string(buffer);
    };
    info += "\n\nFault PC: 0x" + toHex(panicProgramCounter);
    info += "\nReturn address: 0x" + toHex(panicReturnAddress);
    info += "\nMachine cause: 0x" + toHex(panicMachineCause);
    info += "\nAbort caller PC: 0x" + toHex(panicAbortCallerProgramCounter);
    info += "\nAssert caller PC: 0x" + toHex(panicAssertCallerProgramCounter);
    info += "\n\nRaw stack memory and retained logs are intentionally omitted.";

    return info;
  }
}

bool isRebootFromPanic() {
  const auto resetReason = esp_reset_reason();
  return resetReason == ESP_RST_PANIC || resetReason == ESP_RST_CPU_LOCKUP;
}

}  // namespace HalSystem
