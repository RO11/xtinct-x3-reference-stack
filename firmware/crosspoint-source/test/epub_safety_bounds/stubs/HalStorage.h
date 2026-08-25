#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

// Minimal compile-only HalFile surface for the RISC-V serialization probe.
// Runtime behavior is exercised through the Android gtest binary.
class HalFile {
 public:
  HalFile() = default;
  HalFile(const uint8_t* data, const size_t size) : data_(data), size_(size) {}
  size_t write(const void*, size_t bytes) { return bytes; }
  int read(void* destination, const size_t bytes) {
    if (!destination || bytes > size_ - position_) return 0;
    if (bytes != 0) std::memcpy(destination, data_ + position_, bytes);
    position_ += bytes;
    return static_cast<int>(bytes);
  }
  size_t position() const { return position_; }
  size_t size() const { return size_; }
  uint64_t fileSize64() const { return size_; }
  int available() const { return static_cast<int>(size_ - position_); }
  bool seek(const size_t position) {
    if (position > size_) return false;
    position_ = position;
    return true;
  }
  void close() {}
  explicit operator bool() const { return data_ != nullptr; }

 private:
  const uint8_t* data_ = nullptr;
  size_t size_ = 0;
  size_t position_ = 0;
};
