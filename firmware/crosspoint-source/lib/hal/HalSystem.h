#pragma once

#include <string>

namespace HalSystem {
void begin();

// Persist a sanitized crash summary (fixed reason code and code addresses only) to SD.
// Raw stacks, registers other than control-flow/cause, and retained logs are
// deliberately excluded because they may contain credentials or bearer data.
void checkPanic();
void clearPanic();

std::string getPanicInfo(bool full = false);
bool isRebootFromPanic();
}  // namespace HalSystem
