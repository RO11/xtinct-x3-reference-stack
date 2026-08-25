#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace xtinct::file_transfer {

enum class PathIntent : uint8_t { Existing, CreateLeaf };
enum class ResolveStatus : uint8_t { Found, Missing, Error };
enum class PathDecision : uint8_t { Allowed, Protected, Invalid };

constexpr size_t MAX_PATH_BYTES = 512;
constexpr size_t MAX_PATH_COMPONENTS = 32;
constexpr size_t MAX_COMPONENT_BYTES = 255;
constexpr size_t MAX_LFN_UTF8_BYTES = 767;
constexpr uint64_t MAX_TRANSFER_FILE_BYTES = 0xffffffffULL;
constexpr size_t MAX_WS_CONTROL_BYTES = 6 + MAX_COMPONENT_BYTES + 1 + 10 + 1 + MAX_PATH_BYTES;
inline constexpr uint8_t CPFONT_MAGIC_BYTES[8] = {'C', 'P', 'F', 'O', 'N', 'T', 0, 0};

// Multipart callbacks may split the cpfont signature at any byte boundary.
// Accumulate and validate the fixed prefix without assuming that the first
// callback contains all eight bytes or buffering any unbounded input.
struct CpfontMagicAccumulator {
  uint8_t bytes[sizeof(CPFONT_MAGIC_BYTES)] = {};
  size_t count = 0;
  bool rejected = false;

  constexpr bool feed(const uint8_t* input, const size_t inputBytes) {
    if (rejected || (!input && inputBytes != 0)) return false;
    size_t index = 0;
    while (index < inputBytes && count < sizeof(bytes)) {
      const uint8_t value = input[index++];
      bytes[count] = value;
      if (value != CPFONT_MAGIC_BYTES[count]) {
        rejected = true;
        return false;
      }
      ++count;
    }
    return true;
  }

  constexpr bool complete() const { return !rejected && count == sizeof(bytes); }
};

constexpr bool canAppendTransferBytes(const uint64_t received, const uint64_t incoming) {
  return received <= MAX_TRANSFER_FILE_BYTES && incoming <= MAX_TRANSFER_FILE_BYTES - received;
}

constexpr bool isCompleteFontPayload(const bool magicComplete, const uint64_t received,
                                     const uint64_t written) {
  return magicComplete && received >= sizeof(CPFONT_MAGIC_BYTES) && written == received;
}

constexpr bool mayReportCommittedUploadSuccess(const bool streamValid, const bool promotionCommitted,
                                               const bool ownsTemporary) {
  return streamValid && promotionCommitted && !ownsTemporary;
}

struct WsStartControl {
  char filename[MAX_COMPONENT_BYTES + 1] = {};
  char path[MAX_PATH_BYTES + 1] = {};
  uint64_t bytes = 0;
};

constexpr char asciiLower(const char value) {
  return value >= 'A' && value <= 'Z' ? static_cast<char>(value + ('a' - 'A')) : value;
}

constexpr bool asciiEqualsIgnoreCase(const std::string_view left, const std::string_view right) {
  if (left.size() != right.size()) return false;
  for (size_t index = 0; index < left.size(); ++index) {
    if (asciiLower(left[index]) != asciiLower(right[index])) return false;
  }
  return true;
}

constexpr bool isProtectedComponent(const std::string_view component) {
  return component.empty() || component.front() == '.' ||
         asciiEqualsIgnoreCase(component, "System Volume Information") ||
         asciiEqualsIgnoreCase(component, "XTCache");
}

constexpr bool isHexDigit(const char value) {
  return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f') || (value >= 'A' && value <= 'F');
}

constexpr uint8_t hexDigitValue(const char value) {
  return value >= '0' && value <= '9' ? static_cast<uint8_t>(value - '0')
         : value >= 'a' && value <= 'f' ? static_cast<uint8_t>(10 + value - 'a')
                                        : static_cast<uint8_t>(10 + value - 'A');
}

constexpr bool isBoundedRawPath(const std::string_view rawPath) {
  if (rawPath.empty() || rawPath.size() > MAX_PATH_BYTES) return false;
  for (size_t index = 0; index < rawPath.size(); ++index) {
    const uint8_t raw = static_cast<uint8_t>(rawPath[index]);
    if (raw < 0x20U || raw == 0x7fU) return false;
    if (rawPath[index] != '%') continue;
    if (index + 2 >= rawPath.size() || !isHexDigit(rawPath[index + 1]) || !isHexDigit(rawPath[index + 2])) {
      return false;
    }
    const uint8_t decoded = static_cast<uint8_t>((hexDigitValue(rawPath[index + 1]) << 4) |
                                                  hexDigitValue(rawPath[index + 2]));
    if (decoded < 0x20U || decoded == 0x7fU || decoded == '/' || decoded == '\\') return false;
    index += 2;
  }
  return true;
}

// Parse the WebSocket START frame directly from the callback's explicit byte
// span. The frame is never assumed to be NUL terminated and no dynamic String
// is constructed until every token and the decimal size have been bounded.
constexpr bool parseWsStartControl(const std::string_view control, WsStartControl& parsed) {
  constexpr std::string_view prefix = "START:";
  if (control.size() <= prefix.size() || control.size() > MAX_WS_CONTROL_BYTES ||
      control.substr(0, prefix.size()) != prefix) {
    return false;
  }
  for (const char value : control) {
    const uint8_t byte = static_cast<uint8_t>(value);
    if (byte < 0x20U || byte == 0x7fU) return false;
  }

  const size_t firstColon = control.find(':', prefix.size());
  if (firstColon == std::string_view::npos) return false;
  const size_t secondColon = control.find(':', firstColon + 1);
  if (secondColon == std::string_view::npos) return false;
  const std::string_view filename = control.substr(prefix.size(), firstColon - prefix.size());
  const std::string_view sizeToken = control.substr(firstColon + 1, secondColon - firstColon - 1);
  const std::string_view path = control.substr(secondColon + 1);
  if (filename.empty() || filename.size() > MAX_COMPONENT_BYTES || sizeToken.empty() || sizeToken.size() > 10 ||
      path.empty() || path.size() > MAX_PATH_BYTES) {
    return false;
  }

  uint64_t bytes = 0;
  for (const char digit : sizeToken) {
    if (digit < '0' || digit > '9') return false;
    const uint64_t value = static_cast<uint64_t>(digit - '0');
    if (bytes > (MAX_TRANSFER_FILE_BYTES - value) / 10U) return false;
    bytes = bytes * 10U + value;
  }

  for (size_t index = 0; index < filename.size(); ++index) parsed.filename[index] = filename[index];
  parsed.filename[filename.size()] = '\0';
  for (size_t index = 0; index < path.size(); ++index) parsed.path[index] = path[index];
  parsed.path[path.size()] = '\0';
  parsed.bytes = bytes;
  return true;
}

// Resolver contract:
//   ResolveStatus resolve(std::string_view submittedPath,
//                         char* actualLongName, size_t capacity,
//                         size_t& actualLength)
//
// Every component which already exists is opened through the backing FAT
// implementation and checked under its actual LFN. Consequently a submitted
// 8.3 alias such as CROSSP~7 cannot bypass protection for an entry whose LFN is
// .crosspoint. Only the final component of a creation destination may be
// missing, and that lexical leaf is checked before creation.
template <typename Resolver>
PathDecision checkNormalizedPath(const std::string_view path, const PathIntent intent, Resolver& resolver) {
  if (path.empty() || path.size() > MAX_PATH_BYTES || path.front() != '/') return PathDecision::Invalid;
  if (path == "/") return intent == PathIntent::Existing ? PathDecision::Allowed : PathDecision::Invalid;
  if (path.back() == '/') return PathDecision::Invalid;

  char cumulative[MAX_PATH_BYTES + 1] = {};
  size_t cumulativeLength = 0;
  size_t componentCount = 0;
  size_t start = 1;
  while (start < path.size()) {
    const size_t slash = path.find('/', start);
    const size_t end = slash == std::string_view::npos ? path.size() : slash;
    const std::string_view submitted = path.substr(start, end - start);
    if (++componentCount > MAX_PATH_COMPONENTS || submitted.size() > MAX_COMPONENT_BYTES) {
      return PathDecision::Invalid;
    }
    if (isProtectedComponent(submitted)) return PathDecision::Protected;

    if (cumulativeLength + 1 + submitted.size() > MAX_PATH_BYTES) return PathDecision::Invalid;
    cumulative[cumulativeLength++] = '/';
    for (const char value : submitted) cumulative[cumulativeLength++] = value;
    cumulative[cumulativeLength] = '\0';

    char actualLongName[MAX_LFN_UTF8_BYTES + 1] = {};
    size_t actualLength = 0;
    const ResolveStatus status = resolver.resolve(std::string_view(cumulative, cumulativeLength), actualLongName,
                                                  sizeof(actualLongName), actualLength);
    const bool finalComponent = end == path.size();
    if (status == ResolveStatus::Found) {
      if (actualLength == 0 || actualLength > MAX_LFN_UTF8_BYTES || actualLongName[actualLength] != '\0') {
        return PathDecision::Invalid;
      }
      const std::string_view actual(actualLongName, actualLength);
      if (actual.find('/') != std::string_view::npos || actual.find('\\') != std::string_view::npos) {
        return PathDecision::Invalid;
      }
      if (isProtectedComponent(actual)) return PathDecision::Protected;
    } else if (status == ResolveStatus::Missing) {
      return intent == PathIntent::CreateLeaf && finalComponent ? PathDecision::Allowed : PathDecision::Invalid;
    } else {
      return PathDecision::Invalid;
    }

    if (finalComponent) return PathDecision::Allowed;
    start = end + 1;
  }
  return PathDecision::Invalid;
}

enum class ReplaceResult : uint8_t { Failed, RestoreFailed, Committed, CommittedBackupRetained };

constexpr bool isCommitted(const ReplaceResult result) {
  return result == ReplaceResult::Committed || result == ReplaceResult::CommittedBackupRetained;
}

constexpr bool mayReportPutSuccess(const bool receivedEnd, const bool pathMatches, const bool streamOk,
                                   const bool promotionCommitted, const bool ownsTemporary) {
  return receivedEnd && pathMatches && streamOk && promotionCommitted && !ownsTemporary;
}

// Atomically promotes an already-written, checked temp file. FAT rename cannot
// replace an existing destination, so overwrite first parks the old file under
// a unique owned backup. A failed promote restores that backup; the old
// destination is never deleted before the replacement is guaranteed.
template <typename Ops>
ReplaceResult promotePrepared(Ops& ops, const char* temp, const char* destination, const char* backup,
                              const bool destinationExisted) {
  if (!temp || !destination || !ops.exists(temp)) return ReplaceResult::Failed;
  bool backupOwnsOldDestination = false;
  if (destinationExisted) {
    if (!backup || ops.exists(backup) || !ops.exists(destination) || !ops.rename(destination, backup)) {
      return ReplaceResult::Failed;
    }
    backupOwnsOldDestination = true;
  } else if (ops.exists(destination)) {
    return ReplaceResult::Failed;
  }

  if (!ops.rename(temp, destination)) {
    if (backupOwnsOldDestination && !ops.rename(backup, destination)) return ReplaceResult::RestoreFailed;
    return ReplaceResult::Failed;
  }

  if (backupOwnsOldDestination && !ops.remove(backup)) return ReplaceResult::CommittedBackupRetained;
  return ReplaceResult::Committed;
}

template <typename Source, typename Destination>
bool copyExactly(Source& source, Destination& destination, const uint64_t expectedBytes, uint8_t* buffer,
                 const size_t bufferBytes) {
  if (!buffer || bufferBytes == 0) return false;
  uint64_t copied = 0;
  while (copied < expectedBytes) {
    const uint64_t remaining = expectedBytes - copied;
    const size_t request = remaining < bufferBytes ? static_cast<size_t>(remaining) : bufferBytes;
    const int bytesRead = source.read(buffer, request);
    // A non-positive read before expectedBytes is an I/O error/truncation, not
    // EOF success. This distinction prevents promoting a partial copy.
    if (bytesRead <= 0 || static_cast<size_t>(bytesRead) > request) return false;
    if (destination.write(buffer, static_cast<size_t>(bytesRead)) != static_cast<size_t>(bytesRead)) return false;
    copied += static_cast<size_t>(bytesRead);
  }
  return destination.sync() && !destination.getWriteError();
}

// Always close, even when an earlier write failed. Promotion is permitted only
// when write, sync, sticky-error and close phases all succeed.
template <typename File>
bool finishDurableWrite(File& file, const bool writesOk = true) {
  bool durable = writesOk;
  if (durable) durable = file.sync() && !file.getWriteError();
  const bool closeOk = file.close();
  return durable && closeOk;
}

}  // namespace xtinct::file_transfer
