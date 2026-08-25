#include <gtest/gtest.h>

#include <array>
#include <cstdio>
#include <initializer_list>
#include <string>

#include "src/util/InboxNewestSelection.h"
#include "src/util/InboxDailyCachePolicy.h"

namespace {

struct Item {
  const char* createdAt = "";
  const char* itemId = "";
};

constexpr bool newestSelectionWorksAtCompileTime() {
  Item retained[2] = {};
  size_t count = 0;
  count = xtinct::inbox_selection::retainNewest(retained, count, 2, Item{"2026-08-07T04:00:00Z", "older"});
  count = xtinct::inbox_selection::retainNewest(retained, count, 2, Item{"2026-08-07T04:15:00Z", "newest-b"});
  count = xtinct::inbox_selection::retainNewest(retained, count, 2, Item{"2026-08-07T04:15:00Z", "newest-a"});
  return count == 2 && xtinct::inbox_selection::compareText(retained[0].itemId, "newest-a") == 0 &&
         xtinct::inbox_selection::compareText(retained[1].itemId, "newest-b") == 0;
}

static_assert(newestSelectionWorksAtCompileTime());

struct OwnedItem {
  char createdAt[40] = {};
  char itemId[33] = {};
};

OwnedItem makeItem(const int minute, const int id) {
  OwnedItem item;
  std::snprintf(item.createdAt, sizeof(item.createdAt), "2026-08-07T%02d:%02d:00Z",
                4 + minute / 60, minute % 60);
  std::snprintf(item.itemId, sizeof(item.itemId), "item-%02d", id);
  return item;
}

OwnedItem makeTiedItem(const int id) {
  OwnedItem item;
  std::snprintf(item.createdAt, sizeof(item.createdAt), "2026-08-07T04:15:00Z");
  std::snprintf(item.itemId, sizeof(item.itemId), "item-%02d", id);
  return item;
}

struct PageCursor {
  char createdAt[40] = {};
  char itemId[33] = {};
};

}  // namespace

TEST(InboxNewestSelection, RetainsNewestSixteenAcrossAllSixtyFourMetadataFiles) {
  std::array<OwnedItem, 16> retained{};
  size_t count = 0;

  // Model an unfavourable directory order: the oldest 48 entries arrive
  // before the newest 16. The former loadInbox implementation stopped early.
  for (int index = 0; index < 64; ++index) {
    const OwnedItem candidate = makeItem(index, index);
    count = xtinct::inbox_selection::retainNewest(retained.data(), count, retained.size(), candidate);
  }

  ASSERT_EQ(count, retained.size());
  for (size_t index = 0; index < retained.size(); ++index) {
    const int expected = 63 - static_cast<int>(index);
    char expectedId[33];
    std::snprintf(expectedId, sizeof(expectedId), "item-%02d", expected);
    EXPECT_STREQ(retained[index].itemId, expectedId);
  }
}

TEST(InboxNewestSelection, UsesItemIdAsDeterministicTimestampTieBreaker) {
  std::array<OwnedItem, 3> retained{};
  size_t count = 0;
  const char* timestamp = "2026-08-07T04:15:00Z";
  for (const char* id : {"item-c", "item-a", "item-b", "item-z"}) {
    OwnedItem candidate;
    std::snprintf(candidate.createdAt, sizeof(candidate.createdAt), "%s", timestamp);
    std::snprintf(candidate.itemId, sizeof(candidate.itemId), "%s", id);
    count = xtinct::inbox_selection::retainNewest(retained.data(), count, retained.size(), candidate);
  }

  ASSERT_EQ(count, retained.size());
  EXPECT_STREQ(retained[0].itemId, "item-a");
  EXPECT_STREQ(retained[1].itemId, "item-b");
  EXPECT_STREQ(retained[2].itemId, "item-c");
}

TEST(InboxNewestSelection, NeverWritesPastTheVisibleCapacity) {
  struct Guarded {
    std::array<OwnedItem, 2> retained{};
    unsigned guard = 0x51a7cafeU;
  } guarded;
  size_t count = 0;
  for (int index = 0; index < 64; ++index) {
    const OwnedItem candidate = makeItem(index, index);
    count = xtinct::inbox_selection::retainNewest(guarded.retained.data(), count, guarded.retained.size(), candidate);
  }
  EXPECT_EQ(count, guarded.retained.size());
  EXPECT_EQ(guarded.guard, 0x51a7cafeU);
}

TEST(InboxNewestSelection, PaginatesAllSixtyFourTiedItemsInAdversarialDirectoryOrder) {
  std::array<OwnedItem, 64> source{};
  for (int index = 0; index < 64; ++index) source[index] = makeTiedItem(index);

  xtinct::inbox_selection::BoundedPageHistory<PageCursor, 8> history;
  history.reset();
  for (int page = 0; page < 8; ++page) {
    std::array<OwnedItem, 8> retained{};
    size_t retainedCount = 0;
    size_t eligibleCount = 0;
    const PageCursor& before = history.current();

    // 17 is coprime with 64, so this visits every item once in a stable but
    // deliberately unhelpful SD-directory order.
    for (int offset = 0; offset < 64; ++offset) {
      const OwnedItem& candidate = source[(offset * 17 + 5) % 64];
      if (xtinct::inbox_selection::isStrictlyOlderThanCursor(
              candidate.createdAt, candidate.itemId, before.createdAt, before.itemId)) {
        ++eligibleCount;
      }
      retainedCount = xtinct::inbox_selection::retainNewestBefore(
          retained.data(), retainedCount, retained.size(), candidate, before.createdAt, before.itemId);
    }

    ASSERT_EQ(retainedCount, retained.size());
    for (int row = 0; row < 8; ++row) {
      char expected[33];
      std::snprintf(expected, sizeof(expected), "item-%02d", page * 8 + row);
      EXPECT_STREQ(retained[row].itemId, expected);
    }
    const bool hasOlder = eligibleCount > retainedCount;
    EXPECT_EQ(hasOlder, page < 7);
    if (hasOlder) {
      PageCursor cursor;
      std::snprintf(cursor.createdAt, sizeof(cursor.createdAt), "%s", retained.back().createdAt);
      std::snprintf(cursor.itemId, sizeof(cursor.itemId), "%s", retained.back().itemId);
      ASSERT_TRUE(history.push(cursor));
    }
  }

  EXPECT_EQ(history.pageIndex(), 7U);
  EXPECT_FALSE(history.canPush());
  for (size_t page = 7; page > 0; --page) {
    EXPECT_TRUE(history.previous());
    EXPECT_EQ(history.pageIndex(), page - 1);
  }
  EXPECT_FALSE(history.previous());
}

TEST(InboxDailyCachePolicy, UsesCompleteSameDayCursorMatchedFirstPageOnly) {
  constexpr uint32_t today = 20676;
  EXPECT_TRUE(xtinct::inbox_cache::canUseFastFirstPage(true, true, true, true, today, today));
  EXPECT_FALSE(xtinct::inbox_cache::canUseFastFirstPage(false, true, true, true, today, today));
  EXPECT_FALSE(xtinct::inbox_cache::canUseFastFirstPage(true, false, true, true, today, today));
  EXPECT_FALSE(xtinct::inbox_cache::canUseFastFirstPage(true, true, false, true, today, today));
  EXPECT_FALSE(xtinct::inbox_cache::canUseFastFirstPage(true, true, true, false, today, today));
  EXPECT_FALSE(xtinct::inbox_cache::canUseFastFirstPage(true, true, true, true, today, today - 1));
}

TEST(InboxDailyCachePolicy, BrisbaneMidnightChangesTheLocalDay) {
  // UTC day 2 at 13:59:59 is 23:59:59 in Brisbane. One second later is the
  // next local calendar day even though the UTC date has not changed.
  constexpr int64_t beforeMidnight = 2 * 86400 + 13 * 3600 + 59 * 60 + 59;
  uint32_t beforeDay = 0;
  uint32_t afterDay = 0;
  ASSERT_TRUE(xtinct::inbox_cache::localDayFromUtcEpoch(beforeMidnight, 88, beforeDay));
  ASSERT_TRUE(xtinct::inbox_cache::localDayFromUtcEpoch(beforeMidnight + 1, 88, afterDay));
  EXPECT_EQ(beforeDay, 2U);
  EXPECT_EQ(afterDay, 3U);
  EXPECT_FALSE(xtinct::inbox_cache::localDayFromUtcEpoch(-1, 88, afterDay));
  EXPECT_FALSE(xtinct::inbox_cache::localDayFromUtcEpoch(0, 105, afterDay));
}
