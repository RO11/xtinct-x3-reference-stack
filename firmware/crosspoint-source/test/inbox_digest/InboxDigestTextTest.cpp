#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <string>

#include "src/network/XtinctSyncClient.h"
#include "src/util/InboxDigestText.h"

namespace {

xtinct::inbox_digest::DigestText extractInChunks(const std::string& source, const char* title,
                                                  const size_t chunkBytes) {
  xtinct::inbox_digest::StreamExtractor extractor(title);
  for (size_t offset = 0; offset < source.size() && !extractor.complete(); offset += chunkBytes) {
    const size_t bytes = std::min(chunkBytes, source.size() - offset);
    extractor.feed(source.data() + offset, bytes);
  }
  xtinct::inbox_digest::DigestText digest;
  EXPECT_TRUE(extractor.finish(digest));
  return digest;
}

}  // namespace

TEST(InboxDigestText, ReaderGenomeUsesWhyThisFitsAndTakeawayProse) {
  const std::string source =
      "On-device neural quantization\r\n"
      "\r\n"
      "WHY THIS FITS\r\n"
      "It makes small local models practical. Extra context stays secondary.\r\n"
      "IMPLEMENTATION NOTES\r\n"
      "A generic paragraph must not replace the fit.\r\n"
      "TAKEAWAY\r\n"
      "Prefer the measured smaller model first. Another sentence is optional.\r\n";

  const auto digest = extractInChunks(source, "On-device neural quantization", 7);
  EXPECT_STREQ(digest.summary, "It makes small local models practical.");
  ASSERT_GE(digest.pointCount, 1);
  EXPECT_STREQ(digest.points[0], "Prefer the measured smaller model first.");
  EXPECT_EQ(std::string(digest.summary).find("WHY THIS FITS"), std::string::npos);
  EXPECT_EQ(std::string(digest.points[0]).find("TAKEAWAY"), std::string::npos);
}

TEST(InboxDigestText, FindsTakeawayWellBeyondTheOldOneKilobyteExcerpt) {
  std::string source =
      "Long local article\n"
      "WHY THIS FITS\n"
      "The selected topic matches the reader genome.\n";
  while (source.size() < 4096) {
    source += "Supporting detail remains local and bounded during preview extraction.\n";
  }
  source += "TAKEAWAY\nAct on the locally cached evidence.\n";

  ASSERT_GT(source.find("TAKEAWAY"), xtinct::inbox_digest::MAX_SOURCE_BYTES);
  const auto digest = extractInChunks(source, "Long local article", 31);
  EXPECT_STREQ(digest.summary, "The selected topic matches the reader genome.");
  ASSERT_GE(digest.pointCount, 1);
  EXPECT_STREQ(digest.points[0], "Act on the locally cached evidence.");
}

TEST(InboxDigestText, GenericFallbackSkipsTitleAndHeadingLines) {
  const std::string source =
      "A useful article\n"
      "# CONTEXT\n"
      "UPPERCASE SECTION\n"
      "First useful paragraph.\n"
      "Second useful paragraph.\n";

  const auto digest = extractInChunks(source, "A useful article", 5);
  EXPECT_STREQ(digest.summary, "First useful paragraph.");
  ASSERT_GE(digest.pointCount, 1);
  EXPECT_STREQ(digest.points[0], "Second useful paragraph.");
}

TEST(InboxDigestText, ReadingQueueFallbackSkipsCanonicalUrlLine) {
  const std::string source =
      "Saved article\n"
      "https://example.com/research/reader?utm_source=xtinct\n"
      "The useful article summary starts here.\n"
      "A second practical point follows.\n";

  const auto digest = extractInChunks(source, "Saved article", 9);
  EXPECT_STREQ(digest.summary, "The useful article summary starts here.");
  ASSERT_GE(digest.pointCount, 1);
  EXPECT_STREQ(digest.points[0], "A second practical point follows.");
}

TEST(InboxDigestText, MalformedLineDoesNotBlockLaterSafeProse) {
  std::string source("Broken\0line\n", 12);
  source += "Safe cached paragraph.\n";

  const auto digest = extractInChunks(source, "Different title", 3);
  EXPECT_STREQ(digest.summary, "Safe cached paragraph.");
}

TEST(InboxDigestContract, AcceptsExactFirmwareCapsWithoutDynamicStorage) {
  using namespace xtinct::inbox_digest_contract;
  const std::string summary(MAX_SUMMARY_BYTES, 's');
  const std::string point(MAX_POINT_BYTES, 'p');
  const TextSpan points[] = {{point.c_str(), point.size()}, {point.c_str(), point.size()}};
  Digest digest;

  ASSERT_TRUE(assign(digest, {SCHEMA, sizeof(SCHEMA) - 1}, {summary.c_str(), summary.size()}, points, 2));
  EXPECT_TRUE(isPresent(digest));
  EXPECT_TRUE(isWellFormed(digest));
  EXPECT_EQ(digest.pointCount, 2);
  EXPECT_EQ(sizeof(Digest), 276U);
  EXPECT_EQ(sizeof(XtinctInboxItem), 796U);
}

TEST(InboxDigestContract, RejectsWrongSchemaAndTextBeyondFirmwareCaps) {
  using namespace xtinct::inbox_digest_contract;
  const std::string summary(MAX_SUMMARY_BYTES, 's');
  const std::string longSummary(MAX_SUMMARY_BYTES + 1, 's');
  const std::string point(MAX_POINT_BYTES, 'p');
  const std::string longPoint(MAX_POINT_BYTES + 1, 'p');
  Digest digest;
  TextSpan points[] = {{point.c_str(), point.size()}};

  EXPECT_FALSE(assign(digest, {"wrong", 5}, {summary.c_str(), summary.size()}, points, 1));
  EXPECT_FALSE(assign(digest, {SCHEMA, sizeof(SCHEMA) - 1},
                      {longSummary.c_str(), longSummary.size()}, points, 1));
  points[0] = {longPoint.c_str(), longPoint.size()};
  EXPECT_FALSE(assign(digest, {SCHEMA, sizeof(SCHEMA) - 1},
                      {summary.c_str(), summary.size()}, points, 1));
}

TEST(InboxDigestContract, RejectsExtraVersionMemberAndMalformedText) {
  using namespace xtinct::inbox_digest_contract;
  EXPECT_TRUE(hasExactObjectShape(3, true, true, true));
  EXPECT_FALSE(hasExactObjectShape(4, true, true, true));  // extra `version` member

  const std::string embeddedNul("safe\0hidden", 11);
  const std::string invalidUtf8("\xF0", 1);
  EXPECT_FALSE(isValidText({embeddedNul.data(), embeddedNul.size()}, MAX_SUMMARY_BYTES));
  EXPECT_FALSE(isValidText({invalidUtf8.data(), invalidUtf8.size()}, MAX_SUMMARY_BYTES));

  Digest oldMetadata;
  EXPECT_FALSE(isPresent(oldMetadata));
  EXPECT_TRUE(isWellFormed(oldMetadata));
}
