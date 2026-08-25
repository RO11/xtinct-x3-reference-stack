#pragma once

#include <Arduino.h>

#include "FileTransferSafety.h"

namespace xtinct::file_transfer {

// `path` must already be normalized and absolute. Existing components are
// resolved through SdFat and validated using their actual UTF-8 long names.
PathDecision checkTransferPath(const String& path, PathIntent intent);

bool isProtectedTransferComponent(const String& component);

// Decode and normalize a raw request path only after enforcing byte,
// component and percent-escape bounds. Returns false for traversal, NUL,
// backslash, malformed escapes or allocation failure.
bool normalizeTransferPath(const String& rawPath, String& normalized);

}  // namespace xtinct::file_transfer
