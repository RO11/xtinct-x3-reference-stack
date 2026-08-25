#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "util/BoundedUtf8Wrap.h"

namespace xtinct::inbox_digest_contract {

inline constexpr char SCHEMA[] = "xtinct.inbox-digest/v1";
// These are deliberately below the wire contract's theoretical text maxima.
// Sixteen deliveries plus sixteen tombstones must still fit in the X3's
// bounded sync-page allocation while leaving useful room for TLS teardown and
// metadata serialization.
inline constexpr size_t MAX_SUMMARY_BYTES = 144;
inline constexpr size_t MAX_POINT_BYTES = 64;
inline constexpr size_t MAX_POINTS = 2;

struct Digest {
  char summary[MAX_SUMMARY_BYTES + 1] = {0};
  char points[MAX_POINTS][MAX_POINT_BYTES + 1] = {{0}};
  uint8_t pointCount = 0;
};

static_assert(sizeof(Digest) == 276, "Inbox digest fixed RAM contract changed");

struct TextSpan {
  const char* data = nullptr;
  size_t bytes = 0;
};

constexpr bool hasExactObjectShape(const size_t memberCount, const bool schemaIsString,
                                   const bool summaryIsString, const bool pointsIsArray) {
  return memberCount == 3 && schemaIsString && summaryIsString && pointsIsArray;
}

inline bool isValidText(const TextSpan text, const size_t maximumBytes) {
  if (!text.data || text.bytes == 0 || text.bytes > maximumBytes) {
    return false;
  }
  size_t offset = 0;
  while (offset < text.bytes) {
    const auto value = static_cast<unsigned char>(text.data[offset]);
    if (value < 0x80) {
      if (value < 0x20 || value == 0x7f) return false;
      ++offset;
      continue;
    }
    const size_t sequence = bounded_utf8_wrap::sequenceLength(text.data + offset, text.bytes - offset);
    if (sequence <= 1) return false;
    offset += sequence;
  }
  return true;
}

inline bool assign(Digest& output, const TextSpan schema, const TextSpan summary,
                   const TextSpan* points, const size_t pointCount) {
  output = {};
  if (!schema.data || schema.bytes != sizeof(SCHEMA) - 1 ||
      std::memcmp(schema.data, SCHEMA, sizeof(SCHEMA) - 1) != 0 ||
      !isValidText(summary, MAX_SUMMARY_BYTES) || pointCount > MAX_POINTS ||
      (pointCount > 0 && !points)) {
    return false;
  }
  std::memcpy(output.summary, summary.data, summary.bytes);
  output.summary[summary.bytes] = '\0';
  for (size_t index = 0; index < pointCount; ++index) {
    if (!isValidText(points[index], MAX_POINT_BYTES)) {
      output = {};
      return false;
    }
    std::memcpy(output.points[index], points[index].data, points[index].bytes);
    output.points[index][points[index].bytes] = '\0';
  }
  output.pointCount = static_cast<uint8_t>(pointCount);
  return true;
}

inline bool isPresent(const Digest& digest) { return digest.summary[0] != '\0'; }

inline size_t boundedLength(const char* text, const size_t capacity) {
  if (!text) return capacity;
  size_t length = 0;
  while (length < capacity && text[length] != '\0') ++length;
  return length;
}

inline bool isWellFormed(const Digest& digest) {
  if (!isPresent(digest)) return digest.pointCount == 0;
  if (digest.pointCount > MAX_POINTS) return false;
  const size_t summaryBytes = boundedLength(digest.summary, sizeof(digest.summary));
  if (summaryBytes == sizeof(digest.summary)) return false;
  if (!isValidText({digest.summary, summaryBytes}, MAX_SUMMARY_BYTES)) return false;
  for (uint8_t index = 0; index < digest.pointCount; ++index) {
    const size_t pointBytes = boundedLength(digest.points[index], sizeof(digest.points[index]));
    if (pointBytes == sizeof(digest.points[index])) return false;
    if (!isValidText({digest.points[index], pointBytes}, MAX_POINT_BYTES)) return false;
  }
  return true;
}

inline bool same(const Digest& first, const Digest& second) {
  if (!isWellFormed(first) || !isWellFormed(second) || first.pointCount != second.pointCount) return false;
  const size_t firstSummaryBytes = boundedLength(first.summary, sizeof(first.summary));
  const size_t secondSummaryBytes = boundedLength(second.summary, sizeof(second.summary));
  if (firstSummaryBytes != secondSummaryBytes ||
      std::memcmp(first.summary, second.summary, firstSummaryBytes) != 0) {
    return false;
  }
  for (uint8_t index = 0; index < first.pointCount; ++index) {
    const size_t firstPointBytes = boundedLength(first.points[index], sizeof(first.points[index]));
    const size_t secondPointBytes = boundedLength(second.points[index], sizeof(second.points[index]));
    if (firstPointBytes != secondPointBytes ||
        std::memcmp(first.points[index], second.points[index], firstPointBytes) != 0) {
      return false;
    }
  }
  return true;
}

}  // namespace xtinct::inbox_digest_contract
