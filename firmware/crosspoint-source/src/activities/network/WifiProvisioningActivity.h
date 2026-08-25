#pragma once

#include <DNSServer.h>

#include <memory>

#include "activities/Activity.h"
#include "network/WifiProvisioningServer.h"

class WifiProvisioningActivity final : public Activity {
 public:
  explicit WifiProvisioningActivity(GfxRenderer& renderer, MappedInputManager& mappedInput, bool recoveryMode = false)
      : Activity("WifiProvisioning", renderer, mappedInput), recoveryMode(recoveryMode) {}

  void onEnter() override;
  void onExit() override;
  void loop() override;
  void render(RenderLock&&) override;
  bool preventAutoSleep() override { return true; }
  bool skipLoopDelay() override { return true; }

 private:
  static constexpr unsigned long SESSION_TIMEOUT_MS = 10UL * 60UL * 1000UL;

  const bool recoveryMode;
  std::unique_ptr<DNSServer> dnsServer;
  std::unique_ptr<WifiProvisioningServer> provisioningServer;
  unsigned long sessionStartedAt = 0;
  bool started = false;
  bool startFailed = false;
  bool lastProvisionedState = false;
  char apSsid[25] = {0};
  char apPassword[13] = {0};
  char sessionToken[25] = {0};

  bool startProvisioning();
  void stopProvisioning();
  void generateCredentials();
};
