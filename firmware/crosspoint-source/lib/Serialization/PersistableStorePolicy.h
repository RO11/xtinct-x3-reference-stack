#pragma once

#include <cstddef>
#include <cstdint>

namespace persistable_store_policy {

constexpr size_t MAX_PERSISTED_JSON_BYTES = 50U * 1024U;

// The directory-entry size is checked before ArduinoJson or any growing input
// buffer sees the file. Empty and oversized state/settings files fail closed.
inline constexpr bool validPersistedJsonFileSize(const uint64_t bytes) {
  return bytes > 0 && bytes <= MAX_PERSISTED_JSON_BYTES;
}

}  // namespace persistable_store_policy
