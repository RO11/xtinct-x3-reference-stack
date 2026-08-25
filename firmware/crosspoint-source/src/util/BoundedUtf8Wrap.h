#pragma once

#include <cstddef>
#include <cstdint>

namespace bounded_utf8_wrap {

// A visual line never probes or retains more than this many source bytes.
// Real X3 lines are much shorter; the cap protects pathological zero-width or
// unbroken input while leaving normal text layout unchanged.
inline constexpr size_t MAX_PROBE_BYTES = 512;

struct BreakResult {
  size_t displayBytes = 0;
  size_t consumedBytes = 0;
  // The span starts with a valid UTF-8 lead whose continuation bytes are in
  // the next SD chunk. Callers must refill at the same source offset.
  bool needMoreInput = false;
};

inline bool isContinuation(const unsigned char value) { return (value & 0xC0) == 0x80; }

// Return the length of one valid UTF-8 sequence. Invalid bytes consume one
// byte, matching the reader's replacement-glyph progress behavior. A valid
// lead byte truncated at the end of the supplied span returns zero so callers
// can leave it for the next SD chunk instead of splitting the sequence.
inline size_t sequenceLength(const char* text, const size_t available) {
  if (!text || available == 0) return 0;
  const auto lead = static_cast<unsigned char>(text[0]);
  if (lead < 0x80) return 1;

  size_t expected = 0;
  if (lead >= 0xC2 && lead <= 0xDF) {
    expected = 2;
  } else if (lead >= 0xE0 && lead <= 0xEF) {
    expected = 3;
  } else if (lead >= 0xF0 && lead <= 0xF4) {
    expected = 4;
  } else {
    return 1;
  }
  if (available < expected) return 0;
  for (size_t i = 1; i < expected; ++i) {
    if (!isContinuation(static_cast<unsigned char>(text[i]))) return 1;
  }

  const auto second = static_cast<unsigned char>(text[1]);
  if ((lead == 0xE0 && second < 0xA0) || (lead == 0xED && second > 0x9F) ||
      (lead == 0xF0 && second < 0x90) || (lead == 0xF4 && second > 0x8F)) {
    return 1;
  }
  return expected;
}

// Find one display line without allocating substrings. `measurePrefix(bytes)` must return
// the rendered width of text[0..bytes), and is called only at UTF-8 boundaries
// no larger than MAX_PROBE_BYTES. Normal width probes are logarithmically
// bounded; a defensive non-monotone fallback is linearly bounded by the same
// fixed table.
template <typename MeasurePrefix>
BreakResult findBreak(const char* text, const size_t available, const int maxWidth, MeasurePrefix&& measurePrefix,
                      const bool finalInput = true) {
  if (!text || available == 0) return {};

  const size_t probeLimit = available < MAX_PROBE_BYTES ? available : MAX_PROBE_BYTES;
  uint16_t boundaries[MAX_PROBE_BYTES + 1];
  size_t boundaryCount = 1;
  boundaries[0] = 0;
  size_t cursor = 0;
  while (cursor < probeLimit) {
    const size_t bytes = sequenceLength(text + cursor, available - cursor);
    if (bytes == 0 || cursor + bytes > probeLimit) break;
    cursor += bytes;
    boundaries[boundaryCount++] = static_cast<uint16_t>(cursor);
  }

  // A valid lead split across SD reads is not an invalid byte and must not be
  // consumed alone. At true EOF, however, a truncated sequence is malformed;
  // consume one byte so a damaged TXT cannot stall the reader forever.
  if (boundaryCount == 1) {
    if (!finalInput) return {0, 0, true};
    return {1, 1, false};
  }

  const size_t largestCandidate = boundaries[boundaryCount - 1];
  const int largestWidth = measurePrefix(largestCandidate);
  if (largestCandidate == available && largestWidth <= maxWidth) {
    return {available, available};
  }

  size_t fitIndex = 0;
  if (largestWidth <= maxWidth) {
    fitIndex = boundaryCount - 1;
  } else {
    size_t low = 1;
    size_t high = boundaryCount - 1;
    while (low <= high) {
      const size_t middle = low + (high - low) / 2;
      if (measurePrefix(boundaries[middle]) <= maxWidth) {
        fitIndex = middle;
        low = middle + 1;
      } else {
        if (middle == 0) break;
        high = middle - 1;
      }
    }
  }

  // Even one over-wide glyph must advance as one complete UTF-8 sequence.
  bool forcedOverwideCodepoint = fitIndex == 0;
  size_t displayBytes = boundaries[forcedOverwideCodepoint ? 1 : fitIndex];

  // Prefix widths are normally monotone, but shaping and kerning do not
  // promise that mathematically. Re-measure the exact selected prefix. If it
  // is unexpectedly over-wide, walk backward over the already bounded UTF-8
  // boundary table until a measured-safe prefix is found. The exceptional
  // fallback is still capped at MAX_PROBE_BYTES and never splits a codepoint.
  if (!forcedOverwideCodepoint && measurePrefix(displayBytes) > maxWidth) {
    size_t safeIndex = fitIndex;
    while (safeIndex > 1) {
      --safeIndex;
      if (measurePrefix(boundaries[safeIndex]) <= maxWidth) break;
    }
    if (measurePrefix(boundaries[safeIndex]) <= maxWidth) {
      displayBytes = boundaries[safeIndex];
    } else {
      forcedOverwideCodepoint = true;
      displayBytes = boundaries[1];
    }
  }

  // Preserve stock word wrapping: prefer the last ASCII space before the
  // fitting/capped boundary, then consume one delimiter space. Prefix width is
  // normally monotone, but kerning/RTL shaping can make a shorter word prefix
  // unexpectedly wider; one verification keeps the result safe without an
  // unbounded fallback scan.
  if (!forcedOverwideCodepoint) {
    for (size_t i = displayBytes; i > 0; --i) {
      if (text[i - 1] != ' ' || i - 1 == 0) continue;
      const size_t wordBytes = i - 1;
      if (measurePrefix(wordBytes) <= maxWidth) displayBytes = wordBytes;
      break;
    }
  }
  size_t consumedBytes = displayBytes;
  if (consumedBytes < available && text[consumedBytes] == ' ') ++consumedBytes;
  if (displayBytes == 0 || consumedBytes == 0) {
    displayBytes = boundaries[1];
    consumedBytes = displayBytes;
  }
  return {displayBytes, consumedBytes, false};
}

}  // namespace bounded_utf8_wrap
