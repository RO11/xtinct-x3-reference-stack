#include "FileTransferPathPolicy.h"

#include <HalStorage.h>

#include <WebServer.h>

#include <array>

namespace xtinct::file_transfer {
namespace {

class FatLongNameResolver {
 public:
  ResolveStatus resolve(const std::string_view submittedPath, char* actualLongName, const size_t capacity,
                        size_t& actualLength) const {
    if (!actualLongName || capacity < MAX_LFN_UTF8_BYTES + 1 || submittedPath.size() > MAX_PATH_BYTES) {
      return ResolveStatus::Error;
    }
    std::array<char, MAX_PATH_BYTES + 1> path{};
    for (size_t index = 0; index < submittedPath.size(); ++index) path[index] = submittedPath[index];
    path[submittedPath.size()] = '\0';

    HalFile entry = Storage.open(path.data());
    if (!entry) {
      return Storage.exists(path.data()) ? ResolveStatus::Error : ResolveStatus::Missing;
    }

    // FAT LFNs are at most 255 UTF-16 code units. The UTF-8 expansion can be
    // larger, so keep a fail-closed 768-byte buffer rather than the common
    // 8.3-sized or 256-byte shortcuts.
    const size_t length = entry.getName(actualLongName, capacity);
    entry.close();
    if (length == 0 || length >= capacity || actualLongName[length] != '\0') return ResolveStatus::Error;
    actualLength = length;
    return ResolveStatus::Found;
  }
};

}  // namespace

PathDecision checkTransferPath(const String& path, const PathIntent intent) {
  FatLongNameResolver resolver;
  return checkNormalizedPath(std::string_view(path.c_str(), path.length()), intent, resolver);
}

bool isProtectedTransferComponent(const String& component) {
  return isProtectedComponent(std::string_view(component.c_str(), component.length()));
}

bool normalizeTransferPath(const String& rawPath, String& normalized) {
  normalized = "";
  if (!isBoundedRawPath(std::string_view(rawPath.c_str(), rawPath.length()))) return false;

  const String decoded = WebServer::urlDecode(rawPath);
  if (decoded.isEmpty() || decoded.length() > MAX_PATH_BYTES) return false;
  if (!normalized.reserve(decoded.length() + 1)) return false;
  normalized = "/";
  size_t components = 0;
  int start = decoded.startsWith("/") ? 1 : 0;
  while (start < static_cast<int>(decoded.length())) {
    while (start < static_cast<int>(decoded.length()) && decoded.charAt(start) == '/') ++start;
    if (start >= static_cast<int>(decoded.length())) break;
    int end = decoded.indexOf('/', start);
    if (end < 0) end = decoded.length();
    const String component = decoded.substring(start, end);
    if (component.isEmpty() || component == "." || component == ".." || component.indexOf('\\') >= 0 ||
        component.length() > MAX_COMPONENT_BYTES || ++components > MAX_PATH_COMPONENTS) {
      normalized = "";
      return false;
    }
    if (normalized.length() > 1) normalized += '/';
    normalized += component;
    if (normalized.length() > MAX_PATH_BYTES) {
      normalized = "";
      return false;
    }
    start = end + 1;
  }
  return !normalized.isEmpty();
}

}  // namespace xtinct::file_transfer
