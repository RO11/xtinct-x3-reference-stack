#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "util/InboxDigestContract.h"

namespace xtinct::inbox_digest {

// Digest generation is deliberately a bounded excerpt operation, never a
// whole-article parse. This keeps opening the preview instant on the X3 and
// prevents malformed local text from growing allocations or scan time.
inline constexpr size_t MAX_SOURCE_BYTES = 1024;
inline constexpr size_t MAX_SCAN_BYTES = 64 * 1024;
inline constexpr size_t STREAM_CHUNK_BYTES = 512;
inline constexpr size_t MAX_LINE_BYTES = 512;
inline constexpr size_t MAX_SUMMARY_BYTES = inbox_digest_contract::MAX_SUMMARY_BYTES;
inline constexpr size_t MAX_POINT_BYTES = inbox_digest_contract::MAX_POINT_BYTES;
inline constexpr size_t MAX_POINTS = inbox_digest_contract::MAX_POINTS;

using DigestText = inbox_digest_contract::Digest;

inline bool isBreakPunctuation(const char value) {
  return value == '.' || value == '?' || value == '!' || value == ';';
}

inline bool isLeadingMarkup(const char value) {
  return value == '#' || value == '*' || value == '-' || value == '>' || value == ' ' || value == '\t';
}

inline bool copySegment(const char* source, size_t bytes, char* output, const size_t outputSize) {
  if (!source || !output || outputSize == 0) return false;
  output[0] = '\0';
  while (bytes > 0 && isLeadingMarkup(*source)) {
    ++source;
    --bytes;
  }
  while (bytes > 0 && (source[bytes - 1] == ' ' || source[bytes - 1] == '\t' || source[bytes - 1] == '\n')) --bytes;
  if (bytes == 0) return false;

  size_t written = 0;
  size_t lastSpace = 0;
  bool truncated = false;
  while (written < bytes) {
    const size_t sequence = bounded_utf8_wrap::sequenceLength(source + written, bytes - written);
    if (sequence == 0 || written + sequence >= outputSize) {
      truncated = true;
      break;
    }
    std::memcpy(output + written, source + written, sequence);
    written += sequence;
    if (source[written - 1] == ' ') lastSpace = written - 1;
  }
  if (written < bytes) truncated = true;
  if (truncated && lastSpace > 8) written = lastSpace;
  while (written > 0 && output[written - 1] == ' ') --written;
  output[written] = '\0';
  return written > 0;
}

inline bool extractGeneric(const char* source, const size_t sourceBytes, DigestText& digest) {
  digest = {};
  if (!source || sourceBytes == 0) return false;
  const size_t boundedBytes = sourceBytes < MAX_SOURCE_BYTES ? sourceBytes : MAX_SOURCE_BYTES;
  char normalized[MAX_SOURCE_BYTES + 1] = {0};
  size_t normalizedBytes = 0;
  bool lastWasSpace = false;
  bool lastWasBreak = false;

  size_t input = 0;
  if (boundedBytes >= 3 && static_cast<unsigned char>(source[0]) == 0xef &&
      static_cast<unsigned char>(source[1]) == 0xbb && static_cast<unsigned char>(source[2]) == 0xbf) {
    input = 3;
  }
  while (input < boundedBytes && normalizedBytes < MAX_SOURCE_BYTES) {
    const auto value = static_cast<unsigned char>(source[input]);
    if (value == 0) return false;
    if (value == '\r' || value == '\n') {
      while (normalizedBytes > 0 && normalized[normalizedBytes - 1] == ' ') --normalizedBytes;
      if (normalizedBytes > 0 && !lastWasBreak) normalized[normalizedBytes++] = '\n';
      lastWasSpace = false;
      lastWasBreak = true;
      ++input;
      if (value == '\r' && input < boundedBytes && source[input] == '\n') ++input;
      continue;
    }
    if (value < 0x80) {
      if (value == '\t' || value == ' ' || value < 0x20 || value == 0x7f) {
        if (normalizedBytes > 0 && !lastWasSpace && !lastWasBreak) {
          normalized[normalizedBytes++] = ' ';
          lastWasSpace = true;
        }
      } else {
        normalized[normalizedBytes++] = static_cast<char>(value);
        lastWasSpace = false;
        lastWasBreak = false;
      }
      ++input;
      continue;
    }

    const size_t sequence = bounded_utf8_wrap::sequenceLength(source + input, boundedBytes - input);
    if (sequence <= 1 || input + sequence > boundedBytes || normalizedBytes + sequence > MAX_SOURCE_BYTES) {
      if (normalizedBytes > 0 && !lastWasSpace && !lastWasBreak) {
        normalized[normalizedBytes++] = ' ';
        lastWasSpace = true;
      }
      ++input;
      continue;
    }
    std::memcpy(normalized + normalizedBytes, source + input, sequence);
    normalizedBytes += sequence;
    input += sequence;
    lastWasSpace = false;
    lastWasBreak = false;
  }
  while (normalizedBytes > 0 && (normalized[normalizedBytes - 1] == ' ' || normalized[normalizedBytes - 1] == '\n')) {
    --normalizedBytes;
  }
  normalized[normalizedBytes] = '\0';
  if (normalizedBytes == 0) return false;

  size_t segmentStart = 0;
  uint8_t selected = 0;
  for (size_t index = 0; index <= normalizedBytes && selected < 1 + MAX_POINTS; ++index) {
    const bool atEnd = index == normalizedBytes;
    const bool lineBreak = !atEnd && normalized[index] == '\n';
    const bool sentenceBreak = !atEnd && isBreakPunctuation(normalized[index]) &&
                               (index + 1 == normalizedBytes || normalized[index + 1] == ' ' ||
                                normalized[index + 1] == '\n');
    if (!atEnd && !lineBreak && !sentenceBreak) continue;
    const size_t segmentEnd = sentenceBreak ? index + 1 : index;
    char* destination = selected == 0 ? digest.summary : digest.points[selected - 1];
    const size_t capacity = selected == 0 ? sizeof(digest.summary) : sizeof(digest.points[0]);
    if (copySegment(normalized + segmentStart, segmentEnd - segmentStart, destination, capacity)) ++selected;
    segmentStart = index + 1;
    while (segmentStart < normalizedBytes && normalized[segmentStart] == ' ') ++segmentStart;
    index = segmentStart == 0 ? 0 : segmentStart - 1;
  }
  digest.pointCount = selected > 0 ? static_cast<uint8_t>(selected - 1) : 0;
  return selected > 0;
}

inline bool sameText(const char* first, const char* second) {
  return first && second && std::strcmp(first, second) == 0;
}

inline bool isUrlOnly(const char* value) {
  if (!value) return false;
  return std::strncmp(value, "https://", 8) == 0 || std::strncmp(value, "http://", 7) == 0;
}

inline bool isUpperHeading(const char* value) {
  if (!value || value[0] == '\0' || std::strlen(value) > 64) return false;
  bool hasLetter = false;
  for (const unsigned char* cursor = reinterpret_cast<const unsigned char*>(value); *cursor; ++cursor) {
    if (*cursor >= 0x80 || (*cursor >= 'a' && *cursor <= 'z')) return false;
    if (*cursor >= 'A' && *cursor <= 'Z') hasLetter = true;
  }
  return hasLetter;
}

class StreamExtractor {
 public:
  explicit StreamExtractor(const char* title = nullptr) {
    DigestText normalizedTitle;
    if (title && extractGeneric(title, std::strlen(title), normalizedTitle)) {
      std::memcpy(titleText, normalizedTitle.summary, sizeof(titleText));
    }
  }

  void feed(const char* bytes, size_t length) {
    if (!bytes || length == 0 || scannedBytes >= MAX_SCAN_BYTES || complete()) return;
    const size_t allowed = length < MAX_SCAN_BYTES - scannedBytes ? length : MAX_SCAN_BYTES - scannedBytes;
    for (size_t index = 0; index < allowed && !complete(); ++index) {
      const char value = bytes[index];
      ++scannedBytes;
      if (value == '\r' || value == '\n') {
        processLine();
        if (value == '\r' && index + 1 < allowed && bytes[index + 1] == '\n') {
          ++index;
          ++scannedBytes;
        }
        continue;
      }
      if (lineBytes < MAX_LINE_BYTES) line[lineBytes++] = value;
    }
  }

  bool complete() const { return whyText[0] != '\0' && takeawayText[0] != '\0'; }

  bool finish(DigestText& output) {
    processLine();
    output = {};
    const char* summary = whyText[0] != '\0' ? whyText : generic.summary;
    if (!summary || summary[0] == '\0') return false;
    std::snprintf(output.summary, sizeof(output.summary), "%s", summary);

    auto addPoint = [&](const char* point) {
      if (!point || point[0] == '\0' || output.pointCount >= MAX_POINTS || sameText(point, output.summary)) return;
      for (uint8_t index = 0; index < output.pointCount; ++index) {
        if (sameText(point, output.points[index])) return;
      }
      std::snprintf(output.points[output.pointCount], sizeof(output.points[output.pointCount]), "%s", point);
      ++output.pointCount;
    };
    addPoint(takeawayText);
    for (uint8_t index = 0; index < generic.pointCount; ++index) addPoint(generic.points[index]);
    return true;
  }

 private:
  char line[MAX_LINE_BYTES + 1] = {0};
  size_t lineBytes = 0;
  size_t scannedBytes = 0;
  char titleText[MAX_SUMMARY_BYTES + 1] = {0};
  char whyText[MAX_SUMMARY_BYTES + 1] = {0};
  char takeawayText[MAX_POINT_BYTES + 1] = {0};
  DigestText generic;
  bool awaitingWhy = false;
  bool awaitingTakeaway = false;

  void addGeneric(const char* value) {
    if (!value || value[0] == '\0' || sameText(value, titleText) || sameText(value, generic.summary)) return;
    if (generic.summary[0] == '\0') {
      std::snprintf(generic.summary, sizeof(generic.summary), "%s", value);
      return;
    }
    if (generic.pointCount >= MAX_POINTS) return;
    for (uint8_t index = 0; index < generic.pointCount; ++index) {
      if (sameText(value, generic.points[index])) return;
    }
    std::snprintf(generic.points[generic.pointCount], sizeof(generic.points[generic.pointCount]), "%s", value);
    ++generic.pointCount;
  }

  void processLine() {
    if (lineBytes == 0) return;
    line[lineBytes] = '\0';
    const bool markdownHeading = line[0] == '#';
    DigestText parsed;
    const bool parsedLine = extractGeneric(line, lineBytes, parsed);
    lineBytes = 0;
    line[0] = '\0';
    if (!parsedLine || sameText(parsed.summary, titleText) || isUrlOnly(parsed.summary)) return;
    if (sameText(parsed.summary, "WHY THIS FITS")) {
      awaitingWhy = true;
      awaitingTakeaway = false;
      return;
    }
    if (sameText(parsed.summary, "TAKEAWAY")) {
      awaitingTakeaway = true;
      awaitingWhy = false;
      return;
    }
    if (markdownHeading || isUpperHeading(parsed.summary)) return;

    if (awaitingWhy && whyText[0] == '\0') {
      std::snprintf(whyText, sizeof(whyText), "%s", parsed.summary);
      awaitingWhy = false;
      for (uint8_t index = 0; index < parsed.pointCount; ++index) addGeneric(parsed.points[index]);
      return;
    }
    if (awaitingTakeaway && takeawayText[0] == '\0') {
      std::snprintf(takeawayText, sizeof(takeawayText), "%s", parsed.summary);
      awaitingTakeaway = false;
      return;
    }

    addGeneric(parsed.summary);
    for (uint8_t index = 0; index < parsed.pointCount; ++index) addGeneric(parsed.points[index]);
  }
};

inline bool extract(const char* source, const size_t sourceBytes, DigestText& digest, const char* title = nullptr) {
  StreamExtractor extractor(title);
  extractor.feed(source, sourceBytes);
  return extractor.finish(digest);
}

}  // namespace xtinct::inbox_digest
