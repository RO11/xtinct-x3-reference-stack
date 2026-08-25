#pragma once

#include "activities/Activity.h"
#include "network/XtinctFeedClient.h"
#include "network/XtinctSyncClient.h"

class DailyCardsActivity final : public Activity {
 public:
  explicit DailyCardsActivity(GfxRenderer& renderer, MappedInputManager& mappedInput, bool scheduledWake = false,
                              bool allowScheduledRetries = true)
      : Activity("DailyCards", renderer, mappedInput),
        scheduledWake(scheduledWake),
        allowScheduledRetries(allowScheduledRetries) {}
  static void prepareDiagnosticTestWake();
  static bool consumeDiagnosticTestWake();
  static void resetScheduledRetryState();

  void onEnter() override;
  void onExit() override;
  void loop() override;
  void render(RenderLock&&) override;
  bool preventAutoSleep() override {
    return state == State::SYNCING || automaticSyncPending || forcedSyncPending;
  }
  bool skipLoopDelay() override {
    return state == State::SYNCING || automaticSyncPending || forcedSyncPending;
  }

 private:
  enum class State : uint8_t { SYNCING, CARD_READY, NO_CARD };

  const bool scheduledWake;
  const bool allowScheduledRetries;
  State state = State::SYNCING;
  XtinctFeedClient::SyncResult syncResult = XtinctFeedClient::SyncResult::NO_CONFIG;
  XtinctSyncClient::SyncResult inboxSyncResult = XtinctSyncClient::SyncResult::NO_CONFIG;
  XtinctDailyCard card;
  size_t cardIndex = 0;
  size_t cardCount = 0;
  bool syncStarted = false;
  bool automaticSyncPending = false;
  bool forcedSyncPending = false;
  bool syncScreenPainted = false;
  bool networkSessionRan = false;

  void runSync();
  void loadBestCard();
  void moveCard(int direction);
  void openFullReport();
  const char* syncStatusText() const;
  void renderCard() const;
};
