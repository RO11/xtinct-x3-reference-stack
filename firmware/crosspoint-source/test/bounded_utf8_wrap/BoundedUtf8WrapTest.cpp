#include <gtest/gtest.h>

#include <algorithm>
#include <string>

#include "src/util/BoundedUtf8Wrap.h"
#include "src/util/TxtChunkBoundary.h"

TEST(BoundedUtf8Wrap, UnbrokenAsciiUsesBoundedLogarithmicProbes) {
  const std::string text(8192, 'x');
  size_t calls = 0;
  size_t largestProbe = 0;
  const auto result = bounded_utf8_wrap::findBreak(text.data(), text.size(), 40, [&](const size_t bytes) {
    ++calls;
    largestProbe = std::max(largestProbe, bytes);
    return static_cast<int>(bytes);
  });
  EXPECT_EQ(result.displayBytes, 40U);
  EXPECT_EQ(result.consumedBytes, 40U);
  EXPECT_LE(calls, 12U);
  EXPECT_LE(largestProbe, bounded_utf8_wrap::MAX_PROBE_BYTES);
}

TEST(BoundedUtf8Wrap, FullWorkerMaximumCompletesWithBoundedWork) {
  const std::string text(24 * 1024, 'x');
  size_t offset = 0;
  size_t calls = 0;
  while (offset < text.size()) {
    const auto result = bounded_utf8_wrap::findBreak(text.data() + offset, text.size() - offset, 48,
                                                      [&](const size_t bytes) {
                                                        ++calls;
                                                        EXPECT_LE(bytes, bounded_utf8_wrap::MAX_PROBE_BYTES);
                                                        return static_cast<int>(bytes);
                                                      });
    ASSERT_GT(result.consumedBytes, 0U);
    offset += result.consumedBytes;
  }
  EXPECT_EQ(offset, text.size());
  EXPECT_LE(calls, (text.size() / 48 + 1) * 12);
}

TEST(BoundedUtf8Wrap, PrefersTheLastFittingWordBoundary) {
  const std::string text = "alpha beta gamma";
  const auto result = bounded_utf8_wrap::findBreak(text.data(), text.size(), 10,
                                                    [](const size_t bytes) { return static_cast<int>(bytes); });
  EXPECT_EQ(text.substr(0, result.displayBytes), "alpha");
  EXPECT_EQ(result.consumedBytes, 6U);
}

TEST(BoundedUtf8Wrap, KeepsAMeasuredFitWhenShorterWordPrefixIsNonMonotone) {
  const std::string text = "ab cd ef";
  const auto result = bounded_utf8_wrap::findBreak(text.data(), text.size(), 5, [](const size_t bytes) {
    return bytes == 2 ? 100 : static_cast<int>(bytes);
  });
  EXPECT_EQ(result.displayBytes, 5U);
  EXPECT_EQ(result.consumedBytes, 6U);
}

TEST(BoundedUtf8Wrap, NeverSplitsValidUtf8Sequences) {
  const std::string euro = "\xE2\x82\xAC";
  std::string text;
  for (int i = 0; i < 1000; ++i) text += euro;
  const auto result = bounded_utf8_wrap::findBreak(text.data(), text.size(), 5, [](const size_t bytes) {
    EXPECT_EQ(bytes % 3, 0U);
    return static_cast<int>(bytes / 3);
  });
  EXPECT_EQ(result.displayBytes, 15U);
  EXPECT_EQ(result.consumedBytes, 15U);
}

TEST(BoundedUtf8Wrap, OverwideGlyphStillConsumesTheWholeCodepoint) {
  const std::string text = "\xF0\x9F\x90\xB7tail";  // pig emoji + ASCII
  const auto result = bounded_utf8_wrap::findBreak(text.data(), text.size(), 1,
                                                    [](const size_t) { return 100; });
  EXPECT_EQ(result.displayBytes, 4U);
  EXPECT_EQ(result.consumedBytes, 4U);
}

TEST(BoundedUtf8Wrap, ZeroWidthInputIsStillCapped) {
  const std::string text(2048, 'x');
  const auto result = bounded_utf8_wrap::findBreak(text.data(), text.size(), 100,
                                                    [](const size_t) { return 0; });
  EXPECT_EQ(result.displayBytes, bounded_utf8_wrap::MAX_PROBE_BYTES);
  EXPECT_EQ(result.consumedBytes, bounded_utf8_wrap::MAX_PROBE_BYTES);
}

TEST(BoundedUtf8Wrap, SplitUtf8LeadRequestsMoreInputWithoutConsumingIt) {
  std::string chunk(8191, 'x');
  chunk.push_back('\xF0');
  const auto result = bounded_utf8_wrap::findBreak(
      chunk.data() + 8191, 1, 100, [](const size_t bytes) { return static_cast<int>(bytes); }, false);
  EXPECT_TRUE(result.needMoreInput);
  EXPECT_EQ(result.displayBytes, 0U);
  EXPECT_EQ(result.consumedBytes, 0U);
}

TEST(BoundedUtf8Wrap, TruncatedUtf8AtTrueEofMakesReplacementProgress) {
  const std::string truncated = "\xF0";
  const auto result = bounded_utf8_wrap::findBreak(
      truncated.data(), truncated.size(), 100, [](const size_t bytes) { return static_cast<int>(bytes); }, true);
  EXPECT_FALSE(result.needMoreInput);
  EXPECT_EQ(result.displayBytes, 1U);
  EXPECT_EQ(result.consumedBytes, 1U);
}

TEST(BoundedUtf8Wrap, FinalWidthVerificationFallsBackToAMeasuredSafeBoundary) {
  const std::string text = "abcdef";
  size_t fiveByteMeasurements = 0;
  const auto result = bounded_utf8_wrap::findBreak(text.data(), text.size(), 5, [&](const size_t bytes) {
    if (bytes == 5 && ++fiveByteMeasurements > 1) return 100;
    return static_cast<int>(bytes);
  });
  EXPECT_LE(result.displayBytes, 4U);
  EXPECT_GT(result.displayBytes, 0U);
}

TEST(TxtChunkBoundary, CrLfSplitAtEightKiBIsAppendedAndConsumedTogether) {
  std::string chunk(8191, 'x');
  chunk.push_back('\r');
  ASSERT_TRUE(txt_chunk_boundary::shouldAppendCrLfLookahead(chunk.data(), chunk.size(), true, '\n'));
  chunk.push_back('\n');
  const auto line = txt_chunk_boundary::firstLine(chunk.data(), chunk.size(), false);
  EXPECT_TRUE(line.complete);
  EXPECT_EQ(line.displayBytes, 8191U);
  EXPECT_EQ(line.sourceBytes, 8193U);
}

TEST(TxtChunkBoundary, IncompleteTrailingCrIsNotHiddenOrConsumedAsATerminator) {
  const std::string chunk = "abc\r";
  const auto line = txt_chunk_boundary::firstLine(chunk.data(), chunk.size(), false);
  EXPECT_FALSE(line.complete);
  EXPECT_EQ(line.displayBytes, 4U);
  EXPECT_EQ(line.sourceBytes, 4U);
}

TEST(TxtChunkBoundary, ExactDisplayLineFollowedByCrLfConsumesBothTerminatorBytes) {
  const std::string chunk = "page\r\nnext";
  const auto line = txt_chunk_boundary::firstLine(chunk.data(), chunk.size(), false);
  EXPECT_TRUE(line.complete);
  EXPECT_EQ(line.displayBytes, 4U);
  EXPECT_EQ(line.sourceBytes, 6U);
  EXPECT_EQ(chunk.substr(line.sourceBytes), "next");
}

TEST(TxtChunkBoundary, GenuineBlankLinesRemainOneConsumedSourceByte) {
  const std::string chunk = "\nnext";
  const auto line = txt_chunk_boundary::firstLine(chunk.data(), chunk.size(), false);
  EXPECT_TRUE(line.complete);
  EXPECT_EQ(line.displayBytes, 0U);
  EXPECT_EQ(line.sourceBytes, 1U);
}

TEST(TxtChunkBoundary, EofWithoutNewlineConsumesTheFinalLogicalLine) {
  const std::string chunk = "final line";
  const auto line = txt_chunk_boundary::firstLine(chunk.data(), chunk.size(), true);
  EXPECT_TRUE(line.complete);
  EXPECT_EQ(line.displayBytes, chunk.size());
  EXPECT_EQ(line.sourceBytes, chunk.size());
}

TEST(TxtChunkBoundary, EmbeddedNulIsExplicitlyRejected) {
  const std::string text("ab\0cd", 5);
  EXPECT_TRUE(txt_chunk_boundary::containsEmbeddedNul(text.data(), text.size()));
  EXPECT_FALSE(txt_chunk_boundary::containsEmbeddedNul("abcd", 4));
}
