#pragma once
#include <HalStorage.h>

#include <iostream>
#include <cstdint>
#include <limits>
#include <new>
#include <stdexcept>
#include <string>

#include "SerializedLengthPolicy.h"

#if __has_include(<esp_heap_caps.h>)
#include <esp_heap_caps.h>
#define SERIALIZATION_HAS_ESP_HEAP_CAPS 1
#endif

namespace serialization {
template <typename T>
bool writePod(std::ostream& os, const T& value) {
  os.write(reinterpret_cast<const char*>(&value), sizeof(T));
  return os.good();
}

template <typename T>
bool writePod(HalFile& file, const T& value) {
  return file.write(reinterpret_cast<const uint8_t*>(&value), sizeof(T)) == sizeof(T);
}

template <typename T>
bool readPod(std::istream& is, T& value) {
  is.read(reinterpret_cast<char*>(&value), sizeof(T));
  return is.good();
}

template <typename T>
bool readPod(HalFile& file, T& value) {
  return file.read(reinterpret_cast<uint8_t*>(&value), sizeof(T)) == static_cast<int>(sizeof(T));
}

inline bool writeString(std::ostream& os, const std::string& s) {
  if (s.size() > std::numeric_limits<uint32_t>::max()) return false;
  const auto len = static_cast<uint32_t>(s.size());
  if (!writePod(os, len)) return false;
  os.write(s.data(), len);
  return os.good();
}

inline bool writeString(HalFile& file, const std::string& s) {
  if (s.size() > std::numeric_limits<uint32_t>::max()) return false;
  const auto len = static_cast<uint32_t>(s.size());
  return writePod(file, len) && file.write(reinterpret_cast<const uint8_t*>(s.data()), len) == len;
}

namespace detail {
inline bool resizeStringChecked(std::string& s, const size_t len) {
  if (len > s.capacity()) {
#if defined(SERIALIZATION_HAS_ESP_HEAP_CAPS)
    // std::string has no nothrow growth API. On the ESP target, prove a
    // comfortably larger contiguous 8-bit block exists before calling resize;
    // semantic hard caps keep this request small and deterministic.
    constexpr size_t ALLOCATION_HEADROOM = 1024;
    size_t required = 0;
    if (!checkedAdd(len, ALLOCATION_HEADROOM, &required) ||
        heap_caps_get_largest_free_block(MALLOC_CAP_8BIT) < required) {
      return false;
    }
#endif
  }
#if defined(__cpp_exceptions)
  try {
    s.resize(len);
  } catch (const std::bad_alloc&) {
    return false;
  } catch (const std::length_error&) {
    return false;
  }
#else
  s.resize(len);
#endif
  return true;
}

inline bool streamRemaining(std::istream& is, size_t* const remaining) {
  if (!remaining) return false;
  const std::istream::pos_type start = is.tellg();
  if (start == std::istream::pos_type(-1)) return false;
  is.seekg(0, std::ios::end);
  const std::istream::pos_type end = is.tellg();
  is.seekg(start);
  if (end == std::istream::pos_type(-1) || end < start || !is.good()) return false;
  const std::streamoff delta = end - start;
  if (delta < 0 || static_cast<uintmax_t>(delta) > std::numeric_limits<size_t>::max()) return false;
  *remaining = static_cast<size_t>(delta);
  return true;
}
}  // namespace detail

inline bool readString(std::istream& is, std::string& s, const size_t typeMaximum) {
  uint32_t len = 0;
  if (!readPod(is, len)) return false;
  size_t remaining = 0;
  if (!detail::streamRemaining(is, &remaining) || !sizedFieldFits(len, typeMaximum, remaining) ||
      !detail::resizeStringChecked(s, len)) {
    s.clear();
    return false;
  }
  if (len == 0) return true;
  is.read(s.data(), len);
  if (!is.good()) {
    s.clear();
    return false;
  }
  return true;
}

inline bool readString(HalFile& file, std::string& s, const size_t typeMaximum) {
  uint32_t len = 0;
  if (!readPod(file, len)) return false;
  const size_t pos = file.position();
  const size_t size = file.size();
  const size_t remaining = pos <= size ? size - pos : 0;
  if (!sizedFieldFits(len, typeMaximum, remaining) || !detail::resizeStringChecked(s, len)) {
    s.clear();
    return false;
  }
  if (len == 0) return true;
  if (file.read(s.data(), len) != static_cast<int>(len)) {
    s.clear();
    return false;
  }
  return true;
}
}  // namespace serialization

#if defined(SERIALIZATION_HAS_ESP_HEAP_CAPS)
#undef SERIALIZATION_HAS_ESP_HEAP_CAPS
#endif
