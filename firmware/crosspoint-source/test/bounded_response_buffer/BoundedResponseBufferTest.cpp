#include <gtest/gtest.h>

#include <cstdlib>
#include <cstring>

#include "src/util/BoundedResponseBuffer.h"

using xtinct::network::BoundedResponseBuffer;

namespace {
size_t allocationCeiling = 0;
size_t deallocationCount = 0;

void* ceilingReallocate(void* pointer, const size_t bytes) {
  if (bytes > allocationCeiling) return nullptr;
  return std::realloc(pointer, bytes);
}

void countedFree(void* pointer) {
  if (pointer) ++deallocationCount;
  std::free(pointer);
}
}  // namespace

TEST(BoundedResponseBuffer, AcceptsExactMaximumAndRejectsOneMoreByte) {
  BoundedResponseBuffer buffer(8);
  const uint8_t exact[] = {'1', '2', '3', '4', '5', '6', '7', '8'};
  EXPECT_TRUE(buffer.append(exact, sizeof(exact)));
  EXPECT_EQ(buffer.size(), 8U);
  EXPECT_EQ(buffer.maximum(), 8U);
  EXPECT_EQ(buffer.data()[8], '\0');

  const uint8_t extra = '9';
  EXPECT_FALSE(buffer.append(&extra, 1));
  EXPECT_TRUE(buffer.limitExceeded());
  EXPECT_EQ(buffer.size(), 8U);
  EXPECT_EQ(std::memcmp(buffer.data(), exact, sizeof(exact)), 0);
}

TEST(BoundedResponseBuffer, AllocationFailureIsReportedWithoutChangingCommittedBytes) {
  allocationCeiling = 1025;
  deallocationCount = 0;
  BoundedResponseBuffer buffer(4096, ceilingReallocate, countedFree);
  EXPECT_TRUE(buffer.reserve(1024));
  const uint8_t first[] = {'o', 'k'};
  EXPECT_TRUE(buffer.append(first, sizeof(first)));

  const uint8_t growth[2048] = {};
  EXPECT_FALSE(buffer.append(growth, sizeof(growth)));
  EXPECT_TRUE(buffer.allocationFailed());
  EXPECT_EQ(buffer.size(), sizeof(first));
  EXPECT_EQ(std::memcmp(buffer.data(), first, sizeof(first)), 0);

  buffer.release();
  EXPECT_EQ(deallocationCount, 1U);
  EXPECT_EQ(buffer.size(), 0U);
  EXPECT_EQ(buffer.capacity(), 0U);
}

TEST(BoundedResponseBuffer, InvalidInputFailsClosed) {
  BoundedResponseBuffer buffer(32);
  EXPECT_FALSE(buffer.append(nullptr, 1));
  EXPECT_TRUE(buffer.limitExceeded());
  EXPECT_FALSE(buffer.reserve(1));
}
