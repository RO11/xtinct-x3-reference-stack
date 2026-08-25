#pragma once

#include <memory>

#include "activities/Activity.h"
#include "network/PocketSyncBleServer.h"

class PhoneSyncActivity final : public Activity {
 public:
  PhoneSyncActivity(GfxRenderer& renderer, MappedInputManager& mappedInput)
      : Activity("PhoneSync", renderer, mappedInput) {}

  void onEnter() override;
  void onExit() override;
  void loop() override;
  void render(RenderLock&&) override;
  bool preventAutoSleep() override { return true; }
  bool skipLoopDelay() override { return true; }

 private:
  static constexpr unsigned long SESSION_TIMEOUT_MS = 30UL * 60UL * 1000UL;
  static constexpr unsigned long RESET_HOLD_MS = 3000UL;

  std::unique_ptr<PocketSyncBleServer> pocketServer;
  PocketSyncBleServer::Snapshot state{};
  unsigned long sessionStartedAt = 0;
  uint32_t renderedGeneration = 0;
  bool started = false;
  bool resetHoldFired = false;
  bool resetSucceeded = false;
};

