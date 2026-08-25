#include <cstddef>
#include <cstdint>

#include "src/util/DailyCardsFreshnessPolicy.h"
#include "src/util/InboxDailyCachePolicy.h"
#include "src/util/InboxSyncPagingPolicy.h"
#include "src/util/XtinctSyncContract.h"

using namespace xtinct;

static_assert(inbox_sync_paging::DIRECT_PAGE_CHANGES == 8);
static_assert(inbox_sync_paging::MAX_PAGES_PER_WAKE == 10);
static_assert(inbox_sync_paging::pagesRequired(18) == 3);
static_assert(inbox_sync_paging::pagesRequired(77) == 10);
static_assert(inbox_sync_paging::completesWithinOneWake(80));
static_assert(!inbox_sync_paging::completesWithinOneWake(81));

static_assert(daily_cards::shouldClaimAutomaticSync(
    true, daily_cards::StoredStateStatus::Missing, 20677, 0, 0));
static_assert(!daily_cards::shouldClaimAutomaticSync(
    true, daily_cards::StoredStateStatus::Valid, 20677, 20677, 0));
static_assert(daily_cards::canStampFresh(true, true));
static_assert(!daily_cards::canStampFresh(true, false));
static_assert(daily_cards::freshDayAfterAttempt(false, 20677) == 0);

constexpr bool brisbane_day_boundary() {
  uint32_t before = 0;
  uint32_t after = 0;
  constexpr int64_t before_midnight = 2 * 86400 + 13 * 3600 + 59 * 60 + 59;
  return inbox_cache::localDayFromUtcEpoch(
             before_midnight, daily_cards::BRISBANE_UTC_OFFSET_QUARTER_HOURS_BIASED, before) &&
         inbox_cache::localDayFromUtcEpoch(
             before_midnight + 1, daily_cards::BRISBANE_UTC_OFFSET_QUARTER_HOURS_BIASED, after) &&
         before == 2 && after == 3;
}
static_assert(brisbane_day_boundary());
static_assert(inbox_cache::canUseFastFirstPage(true, true, true, true, 20677, 20677));
static_assert(!inbox_cache::canUseFastFirstPage(true, false, true, true, 20677, 20677));

static_assert(sync_v2::outboxCanAppend(sync_v2::MAX_OUTBOX_EVENTS - 1, 0,
                                      sync_v2::MAX_OUTBOX_EVENT_LINE_BYTES));
static_assert(!sync_v2::outboxCanAppend(sync_v2::MAX_OUTBOX_EVENTS, 0, 1));
static_assert(sync_v2::atomicRecoveryAction(false, true, true) ==
              sync_v2::AtomicRecoveryAction::RestoreBackup);
static_assert(sync_v2::atomicRecoveryAction(false, false, true) ==
              sync_v2::AtomicRecoveryAction::DiscardTemporary);

int firmware_network_contract_compile_gate() { return 0; }

