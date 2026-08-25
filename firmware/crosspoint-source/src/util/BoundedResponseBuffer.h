#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>

namespace xtinct::network {

// A response accumulator for firmware built with -fno-exceptions. Unlike
// throwing dynamic-text growth, an exhausted or fragmented heap is reported to the
// caller instead of entering libstdc++'s throwing allocation/terminate path.
class BoundedResponseBuffer {
 public:
  enum class Failure : uint8_t { None, Limit, Allocation };
  using Reallocate = void* (*)(void*, size_t);
  using Deallocate = void (*)(void*);

  explicit BoundedResponseBuffer(const size_t maximumBytes,
                                 const Reallocate reallocate = &defaultReallocate,
                                 const Deallocate deallocate = &defaultDeallocate)
      : maximumBytes(maximumBytes), reallocate(reallocate), deallocate(deallocate) {
    if (maximumBytes == std::numeric_limits<size_t>::max() || !reallocate || !deallocate) {
      failureState = Failure::Limit;
    }
  }

  ~BoundedResponseBuffer() { release(); }

  BoundedResponseBuffer(const BoundedResponseBuffer&) = delete;
  BoundedResponseBuffer& operator=(const BoundedResponseBuffer&) = delete;
  BoundedResponseBuffer(BoundedResponseBuffer&&) = delete;
  BoundedResponseBuffer& operator=(BoundedResponseBuffer&&) = delete;

  bool reserve(const size_t requestedCapacity) {
    if (failureState != Failure::None) return false;
    if (requestedCapacity > maximumBytes) {
      failureState = Failure::Limit;
      return false;
    }
    return ensureCapacity(requestedCapacity);
  }

  bool append(const uint8_t* bytes, const size_t length) {
    if (failureState != Failure::None) return false;
    if ((!bytes && length != 0) || length > maximumBytes - used) {
      failureState = Failure::Limit;
      return false;
    }
    if (length == 0) return true;
    const size_t required = used + length;
    if (!ensureCapacity(required)) return false;
    std::memcpy(storage + used, bytes, length);
    used = required;
    storage[used] = '\0';
    return true;
  }

  void release() {
    if (storage) deallocate(storage);
    storage = nullptr;
    used = 0;
    allocated = 0;
  }

  char* data() { return storage; }
  const char* data() const { return storage; }
  size_t size() const { return used; }
  size_t capacity() const { return allocated; }
  size_t maximum() const { return maximumBytes; }
  bool empty() const { return used == 0; }
  Failure failure() const { return failureState; }
  bool allocationFailed() const { return failureState == Failure::Allocation; }
  bool limitExceeded() const { return failureState == Failure::Limit; }

 private:
  static void* defaultReallocate(void* pointer, const size_t bytes) { return std::realloc(pointer, bytes); }
  static void defaultDeallocate(void* pointer) { std::free(pointer); }

  bool ensureCapacity(const size_t required) {
    if (required <= allocated) return true;
    size_t candidate = allocated == 0 ? static_cast<size_t>(1024) : allocated;
    if (candidate > maximumBytes) candidate = maximumBytes;
    while (candidate < required) {
      const size_t remaining = maximumBytes - candidate;
      candidate += candidate < remaining ? candidate : remaining;
    }
    void* replacement = reallocate(storage, candidate + 1);
    if (!replacement) {
      failureState = Failure::Allocation;
      return false;
    }
    storage = static_cast<char*>(replacement);
    allocated = candidate;
    storage[used] = '\0';
    return true;
  }

  const size_t maximumBytes;
  const Reallocate reallocate;
  const Deallocate deallocate;
  char* storage = nullptr;
  size_t used = 0;
  size_t allocated = 0;
  Failure failureState = Failure::None;
};

}  // namespace xtinct::network
