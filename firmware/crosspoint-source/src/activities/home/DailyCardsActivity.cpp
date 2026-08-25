#include "DailyCardsActivity.h"

#include <Arduino.h>
#include <ArduinoJson.h>
#include <GfxRenderer.h>
#include <HalClock.h>
#include <HalStorage.h>
#include <I18n.h>
#include <Logging.h>
#include <Memory.h>
#include <Txt.h>

#include <algorithm>
#include <cstdio>
#include <ctime>
#include <new>
#include <stdexcept>

#include "CrossPointSettings.h"
#include "DeepSleep.h"
#include "MappedInputManager.h"
#include "SdCardFontSystem.h"
#include "SilentRestart.h"
#include "XtinctFeedConfigStore.h"
#include "activities/reader/TxtReaderActivity.h"
#include "components/UITheme.h"
#include "fontIds.h"
#include "network/FileTransferSafety.h"
#include "util/DailyCardsFreshnessPolicy.h"
#include "util/InboxDailyCachePolicy.h"
#include "util/XtinctAtomicFile.h"
#include "util/XtinctDateFormat.h"
#include "util/XtinctWakeRuntimePolicy.h"

namespace {
constexpr uint32_t RETRY_DELAY_SECONDS = 15 * 60;
constexpr uint8_t MAX_SCHEDULED_RETRIES = 3;
RTC_DATA_ATTR uint8_t scheduledRetryCount = 0;
RTC_DATA_ATTR bool diagnosticTestWakePending = false;
constexpr char DAILY_SYNC_DIR[] = "/.crosspoint/xtinct";
constexpr char DAILY_SYNC_STATE_PATH[] = "/.crosspoint/xtinct/daily-sync-state.json";
constexpr char DAILY_SYNC_STATE_TEMP_PATH[] = "/.crosspoint/xtinct/daily-sync-state.json.tmp";
constexpr char DAILY_SYNC_STATE_BACKUP_PATH[] = "/.crosspoint/xtinct/daily-sync-state.json.bak";
constexpr size_t MAX_DAILY_SYNC_STATE_BYTES = 128;

struct DailySyncState {
  uint32_t attemptDay = 0;
  uint32_t freshDay = 0;
};

struct AtomicStorageOps {
  bool exists(const char* path) const { return Storage.exists(path); }
  bool remove(const char* path) const { return Storage.remove(path); }
  bool rename(const char* source, const char* destination) const {
    return Storage.rename(source, destination);
  }
};

bool recoverDailySyncState() {
  AtomicStorageOps ops;
  return xtinct::atomic_file::succeeded(xtinct::atomic_file::recover(
      ops, DAILY_SYNC_STATE_PATH, DAILY_SYNC_STATE_TEMP_PATH,
      DAILY_SYNC_STATE_BACKUP_PATH));
}

xtinct::daily_cards::StoredStateStatus readDailySyncState(DailySyncState& state) {
  state = {};
  if (!recoverDailySyncState()) return xtinct::daily_cards::StoredStateStatus::Invalid;
  if (!Storage.exists(DAILY_SYNC_STATE_PATH)) {
    return xtinct::daily_cards::StoredStateStatus::Missing;
  }
  char body[MAX_DAILY_SYNC_STATE_BYTES + 1] = {0};
  HalFile file;
  if (!Storage.openFileForRead("XFEED", DAILY_SYNC_STATE_PATH, file)) {
    return xtinct::daily_cards::StoredStateStatus::Invalid;
  }
  const uint64_t fileBytes = file.fileSize64();
  if (fileBytes == 0 || fileBytes > MAX_DAILY_SYNC_STATE_BYTES) {
    file.close();
    return xtinct::daily_cards::StoredStateStatus::Invalid;
  }
  const size_t bytes = static_cast<size_t>(fileBytes);
  const bool readExactly = file.read(body, bytes) == static_cast<int>(bytes);
  const bool closeOk = file.close();
  if (!readExactly || !closeOk) return xtinct::daily_cards::StoredStateStatus::Invalid;
  JsonDocument document;
  if (deserializeJson(document, body, bytes) || !document.is<JsonObjectConst>()) {
    return xtinct::daily_cards::StoredStateStatus::Invalid;
  }
  const JsonObjectConst root = document.as<JsonObjectConst>();
  if (root.size() != 3 || (root["schema"] | 0) != 1 ||
      !root["attempt_day"].is<uint32_t>() || !root["fresh_day"].is<uint32_t>()) {
    return xtinct::daily_cards::StoredStateStatus::Invalid;
  }
  state.attemptDay = root["attempt_day"].as<uint32_t>();
  state.freshDay = root["fresh_day"].as<uint32_t>();
  return xtinct::daily_cards::StoredStateStatus::Valid;
}

bool writeDailySyncState(const DailySyncState& state) {
  if ((!Storage.exists(DAILY_SYNC_DIR) && !Storage.mkdir(DAILY_SYNC_DIR)) ||
      !recoverDailySyncState()) {
    return false;
  }
  JsonDocument document;
  document["schema"] = 1;
  document["attempt_day"] = state.attemptDay;
  document["fresh_day"] = state.freshDay;
  const size_t bytes = measureJson(document);
  char body[MAX_DAILY_SYNC_STATE_BYTES + 1] = {0};
  if (document.overflowed() || bytes == 0 || bytes > MAX_DAILY_SYNC_STATE_BYTES ||
      serializeJson(document, body, sizeof(body)) != bytes) {
    return false;
  }

  HalFile temporary;
  if (!Storage.openFileForWrite("XFEED", DAILY_SYNC_STATE_TEMP_PATH, temporary)) return false;
  const bool durable = xtinct::file_transfer::finishDurableWrite(
      temporary, temporary.write(body, bytes) == bytes);
  if (!durable) {
    if (Storage.exists(DAILY_SYNC_STATE_TEMP_PATH)) Storage.remove(DAILY_SYNC_STATE_TEMP_PATH);
    return false;
  }

  AtomicStorageOps ops;
  bool previousExisted = false;
  const auto promoted = xtinct::atomic_file::promoteRetainingBackup(
      ops, DAILY_SYNC_STATE_TEMP_PATH, DAILY_SYNC_STATE_PATH,
      DAILY_SYNC_STATE_BACKUP_PATH, previousExisted);
  if (!xtinct::atomic_file::succeeded(promoted)) {
    recoverDailySyncState();
    return false;
  }
  return xtinct::atomic_file::succeeded(xtinct::atomic_file::commit(
      ops, DAILY_SYNC_STATE_PATH, DAILY_SYNC_STATE_TEMP_PATH,
      DAILY_SYNC_STATE_BACKUP_PATH));
}

bool currentLocalDay(uint32_t& localDay) {
  if (!halClock.hasValidTime()) return false;
  const time_t now = time(nullptr);
  return now >= 1609459200 && xtinct::inbox_cache::localDayFromUtcEpoch(
                                    static_cast<int64_t>(now),
                                    xtinct::daily_cards::BRISBANE_UTC_OFFSET_QUARTER_HOURS_BIASED,
                                    localDay);
}

bool claimAutomaticSyncForToday() {
  uint32_t localDay = 0;
  const bool dayKnown = currentLocalDay(localDay);
  DailySyncState state;
  const auto status = readDailySyncState(state);
  if (!xtinct::daily_cards::shouldClaimAutomaticSync(
          dayKnown, status, localDay, state.attemptDay, state.freshDay)) {
    return false;
  }
  state.attemptDay = localDay;
  if (!writeDailySyncState(state)) {
    LOG_ERR("XFEED", "Daily Cards automatic sync claim could not be stored");
    return false;
  }
  return true;
}

bool stampFreshToday() {
  uint32_t localDay = 0;
  if (!currentLocalDay(localDay)) return false;
  DailySyncState state;
  const auto status = readDailySyncState(state);
  if (status == xtinct::daily_cards::StoredStateStatus::Invalid) return false;
  state.freshDay = xtinct::daily_cards::freshDayAfterAttempt(true, localDay);
  return writeDailySyncState(state);
}

bool clearFreshBeforeNetworkAttempt() {
  DailySyncState state;
  const auto status = readDailySyncState(state);
  if (status == xtinct::daily_cards::StoredStateStatus::Invalid) return false;
  state.freshDay = xtinct::daily_cards::freshDayAfterAttempt(false, 0);
  return writeDailySyncState(state);
}

bool v1SyncComplete(const XtinctFeedClient::SyncResult result) {
  return result == XtinctFeedClient::SyncResult::UPDATED ||
         result == XtinctFeedClient::SyncResult::NOT_MODIFIED;
}

bool v2SyncComplete(const XtinctSyncClient::SyncResult result) {
  return (result == XtinctSyncClient::SyncResult::UPDATED ||
          result == XtinctSyncClient::SyncResult::CURRENT) &&
         XtinctSyncClient::isInboxSyncCompleteToday();
}

bool isTransientFailure(const XtinctFeedClient::SyncResult result) {
  return result == XtinctFeedClient::SyncResult::NO_WIFI || result == XtinctFeedClient::SyncResult::CLOCK_ERROR ||
         result == XtinctFeedClient::SyncResult::NETWORK_ERROR;
}

bool isTransientFailure(const XtinctSyncClient::SyncResult result) {
  return result == XtinctSyncClient::SyncResult::NO_WIFI || result == XtinctSyncClient::SyncResult::NETWORK_ERROR;
}

void logHeapStage(const char* stage) {
  LOG_INF("XHEAP", "stage=%s free=%u max=%u min=%u", stage, static_cast<unsigned>(ESP.getFreeHeap()),
          static_cast<unsigned>(ESP.getMaxAllocHeap()), static_cast<unsigned>(ESP.getMinFreeHeap()));
}
}  // namespace

void DailyCardsActivity::prepareDiagnosticTestWake() {
  scheduledRetryCount = 0;
  diagnosticTestWakePending = true;
}

bool DailyCardsActivity::consumeDiagnosticTestWake() {
  const bool pending = diagnosticTestWakePending;
  diagnosticTestWakePending = false;
  if (pending) scheduledRetryCount = 0;
  return pending;
}

void DailyCardsActivity::resetScheduledRetryState() {
  scheduledRetryCount = 0;
  diagnosticTestWakePending = false;
}

void DailyCardsActivity::onEnter() {
  Activity::onEnter();
  state = State::SYNCING;
  syncStarted = false;
  automaticSyncPending = false;
  forcedSyncPending = scheduledWake;
  syncScreenPainted = false;
  networkSessionRan = false;
  syncResult = XtinctFeedClient::SyncResult::NO_CONFIG;
  inboxSyncResult = XtinctSyncClient::SyncResult::CURRENT;
  if (!scheduledWake) {
    // Validate and paint retained cards before deciding whether today's one
    // automatic delta attempt is due. A missing cache still recovers by using
    // the existing forced foreground sync path.
    loadBestCard();
    if (state == State::CARD_READY) {
      syncResult = XtinctFeedClient::SyncResult::NOT_MODIFIED;
      automaticSyncPending = true;
    } else {
      automaticSyncPending = true;
    }
  } else {
    requestUpdate();
  }
}

void DailyCardsActivity::onExit() {
  XtinctFeedClient::disconnectWifi();
  Activity::onExit();
  // TLS and Wi-Fi leave meaningful heap fragmentation on the ~380 KB X3.
  // The deep-sleep latch makes this a no-op during sleep preparation; a manual
  // Back action gets a clean, silent reboot to Home like stock Wi-Fi flows.
  if (!scheduledWake && networkSessionRan) silentRestart();
}

void DailyCardsActivity::runSync() {
#if defined(__cpp_exceptions)
  try {
#endif
  logHeapStage("daily-sync-start");
  if (!XTINCT_FEED_CONFIG.hasReadToken()) {
    syncResult = XtinctFeedClient::SyncResult::NO_CONFIG;
  } else if (!XtinctFeedClient::connectSavedWifi()) {
    syncResult = XtinctFeedClient::SyncResult::NO_WIFI;
  } else {
    logHeapStage("wifi-connected");
    // Refresh UTC on every Daily Cards network session. The historical sync
    // flag cannot detect a stopped-but-plausible RTC, while this request already
    // has Wi-Fi awake and therefore adds no extra wake cycle.
    const bool clockAvailable = halClock.isAvailable();
    const bool ntpSynced = clockAvailable && halClock.syncFromNTP();
    if (ntpSynced) {
      SETTINGS.clockHasBeenSynced = 1;
      SETTINGS.saveToFile();
    }
    const bool clockValid = halClock.hasValidTime();
    LOG_INF("XFEED", "Clock gate (rtc=%u ntp=%u valid=%u heap=%u max=%u)", clockAvailable ? 1U : 0U,
            ntpSynced ? 1U : 0U, clockValid ? 1U : 0U, static_cast<unsigned>(ESP.getFreeHeap()),
            static_cast<unsigned>(ESP.getMaxAllocHeap()));
    if (!clockValid) {
      LOG_ERR("XFEED", "Daily Cards sync refused: RTC time is invalid");
      syncResult = XtinctFeedClient::SyncResult::CLOCK_ERROR;
      XtinctFeedClient::disconnectWifi();
      logHeapStage("wifi-off");
      loadBestCard();
      return;
    }
    logHeapStage("clock-ready");
    logHeapStage("before-v1");
    auto client = makeUniqueNoThrow<XtinctFeedClient>();
    if (!client) {
      LOG_ERR("XFEED", "OOM: Daily Cards sync client");
      syncResult = XtinctFeedClient::SyncResult::NETWORK_ERROR;
    } else {
      syncResult = client->sync();
    }
    logHeapStage("after-v1");
    client.reset();
    logHeapStage("before-v2");
    auto inboxClient = makeUniqueNoThrow<XtinctSyncClient>();
    if (!inboxClient) {
      inboxSyncResult = XtinctSyncClient::SyncResult::NETWORK_ERROR;
    } else {
      inboxSyncResult = inboxClient->sync();
    }
    logHeapStage("after-v2");
  }
  if (xtinct::daily_cards::canStampFresh(v1SyncComplete(syncResult),
                                          v2SyncComplete(inboxSyncResult)) &&
      !stampFreshToday()) {
    LOG_ERR("XFEED", "Complete Daily Cards sync could not record freshness");
  }
  LOG_INF("XFEED", "Sync finished (cards=%u inbox=%u heap=%u max=%u)", static_cast<unsigned>(syncResult),
          static_cast<unsigned>(inboxSyncResult),
          static_cast<unsigned>(ESP.getFreeHeap()), static_cast<unsigned>(ESP.getMaxAllocHeap()));
  XtinctFeedClient::disconnectWifi();
  logHeapStage("wifi-off");
  loadBestCard();
#if defined(__cpp_exceptions)
  } catch (const std::bad_alloc&) {
    LOG_ERR("XFEED", "Daily Cards stopped safely after allocation failure");
    syncResult = XtinctFeedClient::SyncResult::NETWORK_ERROR;
    inboxSyncResult = XtinctSyncClient::SyncResult::NETWORK_ERROR;
    XtinctFeedClient::disconnectWifi();
    state = cardCount > 0 ? State::CARD_READY : State::NO_CARD;
    requestUpdate();
  } catch (const std::length_error&) {
    LOG_ERR("XFEED", "Daily Cards stopped safely after bounded-length failure");
    syncResult = XtinctFeedClient::SyncResult::NETWORK_ERROR;
    inboxSyncResult = XtinctSyncClient::SyncResult::NETWORK_ERROR;
    XtinctFeedClient::disconnectWifi();
    state = cardCount > 0 ? State::CARD_READY : State::NO_CARD;
    requestUpdate();
  } catch (...) {
    // An exception escaping ActivityManager::loop() reaches std::terminate()
    // and ESP-IDF abort(), which reboots the X3. Keep the already validated
    // cached card visible and report a retryable network failure instead.
    LOG_ERR("XFEED", "Daily Cards stopped safely after unexpected exception");
    syncResult = XtinctFeedClient::SyncResult::NETWORK_ERROR;
    inboxSyncResult = XtinctSyncClient::SyncResult::NETWORK_ERROR;
    XtinctFeedClient::disconnectWifi();
    state = cardCount > 0 ? State::CARD_READY : State::NO_CARD;
    requestUpdate();
  }
#endif
}

void DailyCardsActivity::loadBestCard() {
  cardCount = XtinctFeedClient::cachedCardCount();
  if (cardCount > 0 && XtinctFeedClient::loadBestCachedCard(card, cardIndex)) {
    state = State::CARD_READY;
  } else {
    cardIndex = 0;
    state = State::NO_CARD;
  }
  logHeapStage("card-loaded");
  requestUpdate();
}

void DailyCardsActivity::moveCard(const int direction) {
  if (cardCount < 2) return;
  if (direction > 0) {
    cardIndex = (cardIndex + 1) % cardCount;
  } else {
    cardIndex = cardIndex == 0 ? cardCount - 1 : cardIndex - 1;
  }
  if (XtinctFeedClient::loadCachedCard(cardIndex, card)) requestUpdate();
}

void DailyCardsActivity::openFullReport() {
  char path[160];
  if (!XtinctFeedClient::cachedReportPath(card, path, sizeof(path)) || !Storage.exists(path)) {
    card.hasReport = false;
    requestUpdate();
    return;
  }
  sdFontSystem.ensureLoaded(renderer);
  auto report = makeUniqueNoThrow<Txt>(path, "/.crosspoint");
  if (!report || !report->load()) {
    LOG_ERR("XFEED", "Could not open cached report for %s", card.taskId);
    card.hasReport = false;
    requestUpdate();
    return;
  }
  auto reader = makeUniqueNoThrow<TxtReaderActivity>(renderer, mappedInput, std::move(report), 0,
                                                     /*transientDocument=*/true, std::string(card.title));
  if (!reader) {
    LOG_ERR("XFEED", "OOM: full report reader");
    return;
  }
  startActivityForResult(std::move(reader), [](const ActivityResult&) {});
}

void DailyCardsActivity::loop() {
  if ((automaticSyncPending || forcedSyncPending) && !syncStarted) {
    syncStarted = true;
    // For ordinary opens this flushes the cached card to the panel before any
    // Wi-Fi/TLS work. Manual Refresh and scheduled wakes retain their syncing
    // screen and existing timing/retry behavior. With no cache, NO_CARD stays
    // visible if today's automatic attempt has already been consumed.
    if (!syncScreenPainted && !requestUpdateAndWait()) {
      // Never begin Wi-Fi/TLS while an unconfirmed render may still own the
      // framebuffer, font cache or SD card. Keep validated cached cards and
      // turn the failed paint into a retryable foreground error.
      LOG_ERR("XFEED", "Daily Cards sync cancelled: busy screen was not confirmed");
      syncStarted = false;
      automaticSyncPending = false;
      forcedSyncPending = false;
      syncResult = XtinctFeedClient::SyncResult::NETWORK_ERROR;
      loadBestCard();
      if (scheduledWake) enterDeepSleep(false, true, RETRY_DELAY_SECONDS);
      return;
    }
    syncScreenPainted = false;
    const bool shouldRun = forcedSyncPending || claimAutomaticSyncForToday();
    automaticSyncPending = false;
    forcedSyncPending = false;
    if (!shouldRun) {
      syncStarted = false;
      return;
    }
    if (!clearFreshBeforeNetworkAttempt()) {
      // Forced/manual/scheduled operations may still repair the feeds. The
      // unreadable or old state remains fail-closed for later automatic opens,
      // and full success is the only path that can stamp freshness again.
      LOG_ERR("XFEED", "Daily Cards freshness could not be cleared before sync");
    }
    networkSessionRan = true;
    runSync();
    if (scheduledWake) {
      // Make the fetched (or cached fallback) card physically visible before
      // sleeping. No provisioning activity is entered on any failure path.
      if (!requestUpdateAndWait()) {
        LOG_ERR("XFEED", "Daily Cards final scheduled paint was not confirmed");
      }
      uint32_t retryDelay = 0;
      const bool transientFailure = isTransientFailure(syncResult) || isTransientFailure(inboxSyncResult);
      if (!allowScheduledRetries) {
        // A diagnostic wake is exactly one sync attempt. Its RTC latch was
        // consumed before this activity started; regardless of success or
        // failure, clear ordinary retry state and return to the daily plan.
        scheduledRetryCount = 0;
        LOG_INF("XFEED", "Diagnostic wake complete; ordinary retry suppressed");
      } else if (xtinct::wake_runtime::shouldScheduleRetry(allowScheduledRetries, transientFailure,
                                                           scheduledRetryCount, MAX_SCHEDULED_RETRIES)) {
        ++scheduledRetryCount;
        retryDelay = RETRY_DELAY_SECONDS;
        LOG_INF("XFEED", "Scheduled sync retry %u/%u armed", scheduledRetryCount, MAX_SCHEDULED_RETRIES);
      } else if (transientFailure) {
        LOG_ERR("XFEED", "Scheduled sync retries exhausted; waiting until next daily wake");
        scheduledRetryCount = 0;
      } else {
        scheduledRetryCount = 0;
      }
      enterDeepSleep(false, true, retryDelay);
    }
    return;
  }

  if (mappedInput.wasPressed(MappedInputManager::Button::Back)) {
    onGoHome();
    return;
  }
  if (mappedInput.wasPressed(MappedInputManager::Button::Confirm)) {
    state = State::SYNCING;
    syncStarted = false;
    automaticSyncPending = false;
    forcedSyncPending = true;
    // E-Ink has no animation, so make the busy state physically visible before
    // Wi-Fi/TLS can block the main loop. The next loop consumes this latch and
    // does not redraw the same page a second time.
    if (!requestUpdateAndWait()) {
      LOG_ERR("XFEED", "Daily Cards refresh cancelled: busy screen was not confirmed");
      forcedSyncPending = false;
      syncResult = XtinctFeedClient::SyncResult::NETWORK_ERROR;
      state = cardCount > 0 ? State::CARD_READY : State::NO_CARD;
      requestUpdate();
      return;
    }
    syncScreenPainted = true;
    return;
  }
  if (mappedInput.wasPressed(MappedInputManager::Button::Left) ||
      mappedInput.wasPressed(MappedInputManager::Button::Up)) {
    if (card.hasReport) openFullReport();
  } else if (mappedInput.wasPressed(MappedInputManager::Button::Right) ||
             mappedInput.wasPressed(MappedInputManager::Button::Down)) {
    moveCard(1);
  }
}

const char* DailyCardsActivity::syncStatusText() const {
  switch (syncResult) {
    case XtinctFeedClient::SyncResult::UPDATED:
      return tr(STR_DAILY_CARDS_UPDATED);
    case XtinctFeedClient::SyncResult::NOT_MODIFIED:
      return tr(STR_DAILY_CARDS_CURRENT);
    case XtinctFeedClient::SyncResult::NO_CONFIG:
      return tr(STR_DAILY_CARDS_NOT_CONFIGURED);
    case XtinctFeedClient::SyncResult::NO_WIFI:
      return tr(STR_DAILY_CARDS_NO_WIFI);
    case XtinctFeedClient::SyncResult::CLOCK_ERROR:
      return tr(STR_DAILY_CARDS_CLOCK_ERROR);
    case XtinctFeedClient::SyncResult::UNAUTHORIZED:
      return tr(STR_DAILY_CARDS_UNAUTHORIZED);
    case XtinctFeedClient::SyncResult::INVALID_DATA:
      return tr(STR_DAILY_CARDS_INVALID);
    case XtinctFeedClient::SyncResult::STORAGE_ERROR:
      return tr(STR_DAILY_CARDS_STORAGE_ERROR);
    case XtinctFeedClient::SyncResult::NETWORK_ERROR:
    default:
      return tr(STR_DAILY_CARDS_NETWORK_ERROR);
  }
}

void DailyCardsActivity::renderCard() const {
  const auto& metrics = UITheme::getInstance().getMetrics();
  const int width = renderer.getScreenWidth();
  const int height = renderer.getScreenHeight();
  const int margin = metrics.contentSidePadding;
  const int headerTop = metrics.topPadding;
  GUI.drawHeader(renderer, Rect{0, headerTop, width, metrics.headerHeight}, card.title);

  char position[32];
  if (cardCount > 1) {
    snprintf(position, sizeof(position), "%u/%u  %s", static_cast<unsigned>(cardIndex + 1),
             static_cast<unsigned>(cardCount), syncStatusText());
  } else {
    snprintf(position, sizeof(position), "%s", syncStatusText());
  }
  GUI.drawSubHeader(renderer, Rect{0, headerTop + metrics.headerHeight, width, metrics.tabBarHeight}, position);

  int y = headerTop + metrics.headerHeight + metrics.tabBarHeight + metrics.verticalSpacing;
  const int bottom = height - (scheduledWake ? metrics.verticalSpacing : metrics.buttonHintsHeight + metrics.verticalSpacing);
  const int contentWidth = width - margin * 2;
  char formattedDate[32];
  char updatedLine[64];
  if (xtinct::formatGeneratedDate(card.generatedAt, formattedDate, sizeof(formattedDate))) {
    snprintf(updatedLine, sizeof(updatedLine), tr(STR_UPDATED_FMT), formattedDate);
  } else {
    // Old/physically edited caches remain readable even if their timestamp is
    // not one of the Worker contract's ISO-8601 values.
    snprintf(updatedLine, sizeof(updatedLine), tr(STR_UPDATED_FMT), card.generatedAt);
  }
  const std::string updated = renderer.truncatedText(SMALL_FONT_ID, updatedLine, contentWidth);
  renderer.drawText(SMALL_FONT_ID, margin, y, updated.c_str());
  y += renderer.getLineHeight(SMALL_FONT_ID) + metrics.verticalSpacing;
  const int summaryHeight = renderer.getLineHeight(UI_10_FONT_ID) * 3;
  UITheme::drawCenteredWrappedText(renderer, Rect{margin, y, contentWidth, summaryHeight}, UI_10_FONT_ID, card.summary, 3,
                                   true, EpdFontFamily::BOLD, UITheme::TextVerticalAlignment::TOP);
  y += summaryHeight + metrics.verticalSpacing;

  if (card.metricCount > 0) {
    const int gap = metrics.verticalSpacing;
    const int cellWidth = (contentWidth - gap * (card.metricCount - 1)) / card.metricCount;
    const int metricHeight = renderer.getLineHeight(UI_10_FONT_ID) + renderer.getLineHeight(SMALL_FONT_ID) + 14;
    for (uint8_t i = 0; i < card.metricCount; ++i) {
      const int x = margin + i * (cellWidth + gap);
      renderer.drawRect(x, y, cellWidth, metricHeight, true);
      const std::string value = renderer.truncatedText(UI_10_FONT_ID, card.metrics[i].value, cellWidth - 8);
      const std::string label = renderer.truncatedText(SMALL_FONT_ID, card.metrics[i].label, cellWidth - 8);
      UITheme::drawCenteredText(renderer, Rect{x + 4, y, cellWidth - 8, metricHeight}, UI_10_FONT_ID, y + 5,
                                value.c_str(), true, EpdFontFamily::BOLD);
      UITheme::drawCenteredText(renderer, Rect{x + 4, y, cellWidth - 8, metricHeight}, SMALL_FONT_ID,
                                y + 8 + renderer.getLineHeight(UI_10_FONT_ID), label.c_str());
    }
    y += metricHeight + metrics.verticalSpacing;
  }

  for (uint8_t sectionIndex = 0; sectionIndex < card.sectionCount && y < bottom; ++sectionIndex) {
    const auto& section = card.sections[sectionIndex];
    const std::string heading = renderer.truncatedText(UI_10_FONT_ID, section.heading, contentWidth);
    renderer.drawText(UI_10_FONT_ID, margin, y, heading.c_str(), true, EpdFontFamily::BOLD);
    y += renderer.getLineHeight(UI_10_FONT_ID) + 2;
    for (uint8_t lineIndex = 0; lineIndex < section.lineCount && y < bottom; ++lineIndex) {
      char bullet[sizeof(section.lines[0]) + 2];
      snprintf(bullet, sizeof(bullet), "- %s", section.lines[lineIndex]);
      const std::string line = renderer.truncatedText(SMALL_FONT_ID, bullet, contentWidth);
      renderer.drawText(SMALL_FONT_ID, margin, y, line.c_str());
      y += renderer.getLineHeight(SMALL_FONT_ID) + 2;
    }
    y += metrics.verticalSpacing;
  }

  if (!scheduledWake) {
    const auto labels =
        mappedInput.mapLabels(tr(STR_BACK), tr(STR_REFRESH), card.hasReport ? "Open" : "", cardCount > 1 ? "Next" : "");
    GUI.drawButtonHints(renderer, labels.btn1, labels.btn2, labels.btn3, labels.btn4);
  }
}

void DailyCardsActivity::render(RenderLock&&) {
  renderer.clearScreen();
  const auto& metrics = UITheme::getInstance().getMetrics();
  const int width = renderer.getScreenWidth();
  const int height = renderer.getScreenHeight();

  if (state == State::SYNCING) {
    GUI.drawHeader(renderer, Rect{0, metrics.topPadding, width, metrics.headerHeight}, tr(STR_DAILY_CARDS));
    UITheme::drawCenteredWrappedText(renderer, Rect{metrics.contentSidePadding, metrics.headerHeight,
                                                    width - metrics.contentSidePadding * 2, height - metrics.headerHeight},
                                     UI_12_FONT_ID, tr(STR_DAILY_CARDS_SYNCING), 2, true, EpdFontFamily::BOLD);
  } else if (state == State::CARD_READY) {
    renderCard();
  } else {
    GUI.drawHeader(renderer, Rect{0, metrics.topPadding, width, metrics.headerHeight}, tr(STR_DAILY_CARDS));
    UITheme::drawCenteredWrappedText(renderer, Rect{metrics.contentSidePadding, metrics.headerHeight,
                                                    width - metrics.contentSidePadding * 2, height - metrics.headerHeight},
                                     UI_12_FONT_ID, syncStatusText(), 4, true, EpdFontFamily::BOLD);
    if (!scheduledWake) {
      const auto labels = mappedInput.mapLabels(tr(STR_BACK), tr(STR_REFRESH), "", "");
      GUI.drawButtonHints(renderer, labels.btn1, labels.btn2, labels.btn3, labels.btn4);
    }
  }
  renderer.displayBuffer();
}
