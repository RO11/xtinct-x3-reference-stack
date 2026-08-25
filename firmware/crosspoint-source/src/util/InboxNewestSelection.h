#pragma once

#include <cstddef>

namespace xtinct::inbox_selection {

// CrossPoint's v2 service emits canonical UTC timestamps. Their byte order is
// therefore their chronological order, which lets the X3 rank metadata without
// parsing dates or allocating temporary strings. item_id is the deterministic
// tie-breaker for items created in the same instant.
constexpr int compareText(const char* left, const char* right) {
  if (!left) left = "";
  if (!right) right = "";
  while (*left != '\0' && *left == *right) {
    ++left;
    ++right;
  }
  return static_cast<unsigned char>(*left) - static_cast<unsigned char>(*right);
}

constexpr bool isNewer(const char* leftCreatedAt, const char* leftItemId,
                       const char* rightCreatedAt, const char* rightItemId) {
  const int createdOrder = compareText(leftCreatedAt, rightCreatedAt);
  if (createdOrder != 0) return createdOrder > 0;
  return compareText(leftItemId, rightItemId) < 0;
}

// A page cursor is the last (oldest) item on the previous page. Candidates
// must sort strictly after it. Null/empty pairs select the first page; a
// half-populated cursor fails closed.
constexpr bool isStrictlyOlderThanCursor(const char* candidateCreatedAt, const char* candidateItemId,
                                         const char* cursorCreatedAt, const char* cursorItemId) {
  const bool noCreatedAt = !cursorCreatedAt || cursorCreatedAt[0] == '\0';
  const bool noItemId = !cursorItemId || cursorItemId[0] == '\0';
  if (noCreatedAt || noItemId) return noCreatedAt && noItemId;
  return isNewer(cursorCreatedAt, cursorItemId, candidateCreatedAt, candidateItemId);
}

// Retain at most `capacity` complete items while a caller streams metadata one
// file at a time. The retained prefix is always newest-first; no second array
// proportional to the Inbox's 64-file protocol bound is needed.
template <typename Item>
constexpr size_t retainNewest(Item* retained, size_t retainedCount, const size_t capacity,
                              const Item& candidate) {
  if (!retained || capacity == 0) return 0;
  if (retainedCount > capacity) retainedCount = capacity;

  size_t insertion = 0;
  while (insertion < retainedCount &&
         !isNewer(candidate.createdAt, candidate.itemId,
                  retained[insertion].createdAt, retained[insertion].itemId)) {
    ++insertion;
  }
  if (insertion >= capacity) return retainedCount;

  const size_t nextCount = retainedCount < capacity ? retainedCount + 1 : retainedCount;
  for (size_t index = nextCount - 1; index > insertion; --index) {
    retained[index] = retained[index - 1];
  }
  retained[insertion] = candidate;
  return nextCount;
}

template <typename Item>
constexpr size_t retainNewestBefore(Item* retained, const size_t retainedCount, const size_t capacity,
                                    const Item& candidate, const char* cursorCreatedAt,
                                    const char* cursorItemId) {
  if (!isStrictlyOlderThanCursor(candidate.createdAt, candidate.itemId, cursorCreatedAt, cursorItemId)) {
    return retainedCount;
  }
  return retainNewest(retained, retainedCount, capacity, candidate);
}

// Eight 8-item pages cover the protocol's complete 64-item Inbox. The history
// owns only one stable (createdAt,itemId) boundary per page and never grows.
template <typename Cursor, size_t MaximumPages>
class BoundedPageHistory {
 public:
  static_assert(MaximumPages > 0);

  constexpr void reset() {
    for (size_t index = 0; index < MaximumPages; ++index) cursors[index] = Cursor{};
    currentIndex = 0;
  }

  constexpr const Cursor& current() const { return cursors[currentIndex]; }
  constexpr size_t pageIndex() const { return currentIndex; }
  constexpr bool canPush() const { return currentIndex + 1 < MaximumPages; }

  constexpr bool push(const Cursor& cursor) {
    if (!canPush()) return false;
    cursors[++currentIndex] = cursor;
    return true;
  }

  constexpr bool previous() {
    if (currentIndex == 0) return false;
    --currentIndex;
    return true;
  }

 private:
  Cursor cursors[MaximumPages] = {};
  size_t currentIndex = 0;
};

namespace detail {
struct CompileTimeItem {
  const char* createdAt;
  const char* itemId;
};

constexpr bool compileTimeSelectionProbe() {
  CompileTimeItem retained[2] = {};
  size_t count = 0;
  count = retainNewest(retained, count, 2, CompileTimeItem{"2026-08-07T04:00:00Z", "older"});
  count = retainNewest(retained, count, 2, CompileTimeItem{"2026-08-07T04:15:00Z", "newest-b"});
  count = retainNewest(retained, count, 2, CompileTimeItem{"2026-08-07T04:15:00Z", "newest-a"});
  return count == 2 && compareText(retained[0].itemId, "newest-a") == 0 &&
         compareText(retained[1].itemId, "newest-b") == 0;
}

struct CompileTimeCursor {
  const char* createdAt;
  const char* itemId;
};

constexpr bool compileTimePagingProbe() {
  CompileTimeItem retained[2] = {};
  size_t count = 0;
  count = retainNewestBefore(retained, count, 2, CompileTimeItem{"2026-08-07T04:00:00Z", "item-c"},
                             "2026-08-07T04:00:00Z", "item-b");
  count = retainNewestBefore(retained, count, 2, CompileTimeItem{"2026-08-07T04:00:00Z", "item-a"},
                             "2026-08-07T04:00:00Z", "item-b");
  BoundedPageHistory<CompileTimeCursor, 2> history;
  history.reset();
  return count == 1 && compareText(retained[0].itemId, "item-c") == 0 &&
         history.push(CompileTimeCursor{"2026-08-07T04:00:00Z", "item-b"}) &&
         history.pageIndex() == 1 && !history.canPush() && history.previous() && history.pageIndex() == 0;
}

}  // namespace detail

static_assert(detail::compileTimeSelectionProbe());
static_assert(detail::compileTimePagingProbe());

}  // namespace xtinct::inbox_selection
