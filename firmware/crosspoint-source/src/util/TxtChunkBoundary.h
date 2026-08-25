#pragma once

#include <cstddef>

namespace txt_chunk_boundary {

// The TXT renderer uses NUL-terminated font APIs, so embedded NUL bytes are
// not representable. Daily-report producers reject them; ordinary malformed
// TXT files are rejected here rather than silently measuring different text
// from what is stored.
inline bool containsEmbeddedNul(const char* text, const size_t bytes) {
  if (!text) return false;
  for (size_t i = 0; i < bytes; ++i) {
    if (text[i] == '\0') return true;
  }
  return false;
}

// A single-byte lookahead is enough to keep a CRLF terminator atomic when the
// fixed SD read happens to end on its CR byte.
inline bool shouldAppendCrLfLookahead(const char* chunk, const size_t chunkBytes, const bool hasMoreInput,
                                      const char lookahead) {
  return chunk && chunkBytes > 0 && hasMoreInput && chunk[chunkBytes - 1] == '\r' && lookahead == '\n';
}

struct LineSpan {
  size_t displayBytes = 0;  // excludes a complete CR/LF terminator
  size_t sourceBytes = 0;   // includes the terminator when complete
  bool complete = false;
};

// Classify the first logical line in a loaded chunk. A trailing CR is hidden
// only when the logical line is known complete (CRLF or EOF); an incomplete
// boundary never invents or consumes a terminator.
inline LineSpan firstLine(const char* text, const size_t available, const bool inputEndsAtEof) {
  if (!text) return {};
  size_t newline = 0;
  while (newline < available && text[newline] != '\n') ++newline;

  const bool hasNewline = newline < available;
  const bool complete = hasNewline || inputEndsAtEof;
  size_t displayBytes = newline;
  if (complete && displayBytes > 0 && text[displayBytes - 1] == '\r') --displayBytes;
  return {displayBytes, newline + (hasNewline ? 1 : 0), complete};
}

}  // namespace txt_chunk_boundary
