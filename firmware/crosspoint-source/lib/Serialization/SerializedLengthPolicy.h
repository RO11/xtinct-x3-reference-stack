#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>

namespace serialization {

// Length-prefixed fields are cache/file input, never allocation instructions.
// Every caller must provide the semantic maximum for its field; this helper also
// proves that the declared bytes still exist in the current input before any
// string is grown.
constexpr bool sizedFieldFits(const uint32_t declaredLength, const size_t typeMaximum,
                              const size_t remainingBytes) {
  return static_cast<size_t>(declaredLength) <= typeMaximum &&
         static_cast<size_t>(declaredLength) <= remainingBytes;
}

constexpr bool checkedAdd(const size_t left, const size_t right, size_t* const result) {
  if (!result || right > std::numeric_limits<size_t>::max() - left) return false;
  *result = left + right;
  return true;
}

}  // namespace serialization
