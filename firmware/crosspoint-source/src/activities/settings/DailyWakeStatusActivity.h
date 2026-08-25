#pragma once

#include "activities/Activity.h"

class DailyWakeStatusActivity final : public Activity {
 public:
  explicit DailyWakeStatusActivity(GfxRenderer& renderer, MappedInputManager& mappedInput)
      : Activity("DailyWakeStatus", renderer, mappedInput) {}

  void onEnter() override;
  void loop() override;
  void render(RenderLock&&) override;

 private:
  bool testBlocked = false;
};
