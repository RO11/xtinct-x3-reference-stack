#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <string>

#include "src/util/XtinctSyncContract.h"
#include "src/util/InboxSyncPagingPolicy.h"

using namespace xtinct::sync_v2;

TEST(InboxSyncPagingPolicy, DirectX3PagesStayHeapBoundedAndRecoverCursorZeroHistory) {
  using namespace xtinct::inbox_sync_paging;
  EXPECT_EQ(DIRECT_PAGE_CHANGES, 8U);
  EXPECT_EQ(MAX_PAGES_PER_WAKE, 10U);
  EXPECT_EQ(MAX_CHANGES_PER_WAKE, 80U);
  EXPECT_EQ(MAX_DIRECT_RESPONSE_BYTES, 28U * 1024U);
  EXPECT_EQ(pagesRequired(0), 0U);
  EXPECT_EQ(pagesRequired(1), 1U);
  EXPECT_EQ(pagesRequired(77), 10U);
  EXPECT_TRUE(completesWithinOneWake(77));
  EXPECT_FALSE(completesWithinOneWake(81));

  // This is a device admission policy, not a wire-protocol reduction.
  EXPECT_EQ(MAX_DELIVERIES, 16U);
  EXPECT_EQ(MAX_TOMBSTONES, 16U);
}

TEST(XtinctSyncContract, ValidatesIdentifiersAndDigests) {
  EXPECT_TRUE(isSafeId("x3-main"));
  EXPECT_TRUE(isSafeId("a"));
  EXPECT_FALSE(isSafeId("X3-main"));
  EXPECT_FALSE(isSafeId("-bad"));
  EXPECT_FALSE(isSafeId("a/b"));
  EXPECT_FALSE(isSafeId(std::string(33, 'a').c_str()));
  EXPECT_TRUE(isSha256(std::string(64, 'a').c_str()));
  EXPECT_FALSE(isSha256(std::string(63, 'a').c_str()));
  EXPECT_FALSE(isSha256(std::string(64, 'A').c_str()));
}

TEST(XtinctSyncContract, RecognizesOnlyExactManagedMetadataNames) {
  char itemId[33] = {};
  EXPECT_TRUE(managedMetadataItemId("morning-brief.json", itemId));
  EXPECT_STREQ(itemId, "morning-brief");
  EXPECT_FALSE(managedMetadataItemId("morning-brief.jsonfoo", itemId));
  EXPECT_FALSE(managedMetadataItemId("../brief.json", itemId));
  EXPECT_FALSE(managedMetadataItemId("Brief.json", itemId));

  char finalName[38] = {};
  EXPECT_TRUE(managedMetadataSidecarFinalName("morning-brief.json.bak", finalName));
  EXPECT_STREQ(finalName, "morning-brief.json");
  EXPECT_TRUE(managedMetadataSidecarFinalName("morning-brief.json.tmp", finalName));
  EXPECT_FALSE(managedMetadataSidecarFinalName("morning-brief.json.old", finalName));
  EXPECT_FALSE(managedMetadataSidecarFinalName("../brief.json.bak", finalName));
  EXPECT_EQ(MAX_INBOX_METADATA_SCAN_FILES, 193U);
}

TEST(XtinctSyncContract, RestrictsKindsMimesAndExtensions) {
  EXPECT_EQ(parseKind("epub"), Kind::Epub);
  EXPECT_STREQ(extensionForKind(Kind::Epub), ".epub");
  EXPECT_TRUE(mimeAllowed(Kind::Text, "text/plain; charset=utf-8"));
  EXPECT_FALSE(mimeAllowed(Kind::Text, "text/html"));
  EXPECT_FALSE(mimeAllowed(Kind::Invalid, "application/octet-stream"));
}

TEST(XtinctSyncContract, RecognizesOnlyManagedArtifactNames) {
  const std::string digest(64, 'a');
  char parsed[65] = {};
  EXPECT_TRUE(managedArtifactDigest((digest + ".epub").c_str(), parsed));
  EXPECT_STREQ(parsed, digest.c_str());
  EXPECT_TRUE(managedArtifactDigest((digest + ".bmp.bak").c_str(), parsed));
  EXPECT_TRUE(managedArtifactDigest((digest + ".txt.tmp").c_str(), parsed));
  EXPECT_FALSE(managedArtifactDigest((digest + ".jpg").c_str(), parsed));
  EXPECT_FALSE(managedArtifactDigest((digest + ".epub.exe").c_str(), parsed));
  EXPECT_FALSE(managedArtifactDigest((std::string(64, 'A') + ".epub").c_str(), parsed));
}

TEST(XtinctSyncContract, ValidatesExactX3BitmapHeader) {
  std::array<uint8_t, 54> bmp{};
  bmp[0] = 'B';
  bmp[1] = 'M';
  bmp[2] = 0xbe;  // 48062 LE
  bmp[3] = 0xbb;
  bmp[10] = 62;
  bmp[14] = 40;
  bmp[18] = 0xe0;  // 480 LE
  bmp[19] = 0x01;
  bmp[22] = 0x20;  // 800 LE
  bmp[23] = 0x03;
  bmp[26] = 1;
  bmp[28] = 1;
  EXPECT_TRUE(isX3OneBitBmpHeader(bmp.data(), bmp.size(), X3_ONE_BIT_BMP_BYTES));
  bmp[28] = 8;
  EXPECT_FALSE(isX3OneBitBmpHeader(bmp.data(), bmp.size(), X3_ONE_BIT_BMP_BYTES));
  bmp[28] = 1;
  EXPECT_FALSE(isX3OneBitBmpHeader(bmp.data(), bmp.size(), X3_ONE_BIT_BMP_BYTES + 1));
}

TEST(XtinctSyncContract, ValidatesNativeX3SleepBitmapHeader) {
  std::array<uint8_t, X3_SLEEP_BMP_PIXEL_OFFSET> bmp{};
  bmp[0] = 'B';
  bmp[1] = 'M';
  const auto put16 = [&](const size_t offset, const uint16_t value) {
    bmp[offset] = static_cast<uint8_t>(value);
    bmp[offset + 1] = static_cast<uint8_t>(value >> 8);
  };
  const auto put32 = [&](const size_t offset, const uint32_t value) {
    bmp[offset] = static_cast<uint8_t>(value);
    bmp[offset + 1] = static_cast<uint8_t>(value >> 8);
    bmp[offset + 2] = static_cast<uint8_t>(value >> 16);
    bmp[offset + 3] = static_cast<uint8_t>(value >> 24);
  };
  put32(2, X3_NATIVE_SLEEP_BMP_BYTES);
  put32(10, X3_SLEEP_BMP_PIXEL_OFFSET);
  put32(14, 40);
  put32(18, X3_SLEEP_BMP_WIDTH);
  put32(22, X3_SLEEP_BMP_HEIGHT);
  put16(26, 1);
  put16(28, X3_SLEEP_BMP_BITS_PER_PIXEL);
  put32(34, X3_SLEEP_BMP_ROW_BYTES * X3_SLEEP_BMP_HEIGHT);
  put32(46, 4);
  const std::array<uint8_t, 16> nativePalette = {
      0, 0, 0, 0, 85, 85, 85, 0, 170, 170, 170, 0, 255, 255, 255, 0,
  };
  std::copy(nativePalette.begin(), nativePalette.end(), bmp.begin() + 54);

  EXPECT_TRUE(isX3NativeSleepBmpHeader(bmp.data(), bmp.size(), X3_NATIVE_SLEEP_BMP_BYTES));
  bmp[58] = 84;
  EXPECT_FALSE(isX3NativeSleepBmpHeader(bmp.data(), bmp.size(), X3_NATIVE_SLEEP_BMP_BYTES));
  bmp[58] = 85;
  put32(18, 480);
  EXPECT_FALSE(isX3NativeSleepBmpHeader(bmp.data(), bmp.size(), X3_NATIVE_SLEEP_BMP_BYTES));
}

TEST(XtinctSyncContract, SelectsThreeDailyWakeWindows) {
  EXPECT_EQ(secondsUntilNextWindow(4 * 3600), 15 * 60U);
  EXPECT_EQ(secondsUntilNextWindow(4 * 3600 + 15 * 60), 4 * 3600U);
  EXPECT_EQ(secondsUntilNextWindow(17 * 3600), 3600U);
  EXPECT_EQ(secondsUntilNextWindow(18 * 3600), 10 * 3600U + 15 * 60U);
}

TEST(XtinctSyncContract, ReservesBoundedDeviceStatusIdentity) {
  EXPECT_TRUE(isSafeId(DEVICE_STATUS_ITEM_ID));
  EXPECT_TRUE(isSha256(DEVICE_STATUS_REVISION));
}

TEST(XtinctSyncContract, AcceptsPinnedDeleteReceiptSpellingOnly) {
  EXPECT_TRUE(isAckEventType("deleted"));
  EXPECT_FALSE(isAckEventType("delete"));
  EXPECT_FALSE(isAckEventType("removed"));
}

TEST(XtinctSyncContract, AcceptsGenomeFeedbackReceipts) {
  EXPECT_TRUE(isAckEventType("like"));
  EXPECT_TRUE(isAckEventType("dislike"));
  EXPECT_FALSE(isAckEventType("liked"));
  EXPECT_FALSE(isAckEventType("feedback"));
}

TEST(XtinctSyncContract, NeverEvictsPersistedOutboxReceipts) {
  EXPECT_TRUE(outboxCanAppend(MAX_OUTBOX_EVENTS - 1, 0, MAX_OUTBOX_EVENT_LINE_BYTES));
  EXPECT_FALSE(outboxCanAppend(MAX_OUTBOX_EVENTS, 0, 1));
  EXPECT_TRUE(outboxCanAppend(0, MAX_OUTBOX_BYTES - MAX_OUTBOX_EVENT_LINE_BYTES - 1,
                              MAX_OUTBOX_EVENT_LINE_BYTES));
  EXPECT_FALSE(outboxCanAppend(0, MAX_OUTBOX_BYTES - MAX_OUTBOX_EVENT_LINE_BYTES,
                               MAX_OUTBOX_EVENT_LINE_BYTES));
  EXPECT_FALSE(outboxCanAppend(0, 0, MAX_OUTBOX_EVENT_LINE_BYTES + 1));
}

TEST(XtinctSyncContract, RecoversTheLastCommittedAtomicVersion) {
  EXPECT_EQ(atomicRecoveryAction(true, true, true), AtomicRecoveryAction::UseFinal);
  EXPECT_EQ(atomicRecoveryAction(false, true, true), AtomicRecoveryAction::RestoreBackup);
  EXPECT_EQ(atomicRecoveryAction(false, true, false), AtomicRecoveryAction::RestoreBackup);
  EXPECT_EQ(atomicRecoveryAction(false, false, true), AtomicRecoveryAction::DiscardTemporary);
  EXPECT_EQ(atomicRecoveryAction(false, false, false), AtomicRecoveryAction::Missing);
}

TEST(XtinctSyncContract, ValidatesUtf8AcrossChunkBoundaries) {
  Utf8Validator valid;
  const uint8_t first[] = {'h', 'i', ' ', 0xe2};
  const uint8_t second[] = {0x82, 0xac};
  valid.feed(first, sizeof(first));
  EXPECT_FALSE(valid.complete());
  valid.feed(second, sizeof(second));
  EXPECT_TRUE(valid.complete());

  Utf8Validator overlong;
  const uint8_t invalid[] = {0xc0, 0x80};
  overlong.feed(invalid, sizeof(invalid));
  EXPECT_FALSE(overlong.complete());

  Utf8Validator surrogate;
  const uint8_t invalidSurrogate[] = {0xed, 0xa0, 0x80};
  surrogate.feed(invalidSurrogate, sizeof(invalidSurrogate));
  EXPECT_FALSE(surrogate.complete());

  Utf8Validator embeddedNul;
  const uint8_t nul[] = {'a', 0, 'b'};
  embeddedNul.feed(nul, sizeof(nul));
  EXPECT_FALSE(embeddedNul.complete());
}
