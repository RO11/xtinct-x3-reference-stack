#pragma once

#include <cstdint>

enum class XtinctTimerOverridePurpose : uint8_t {
  ScheduledRetry = 0,
  DiagnosticTest,
};

// preserveCurrentFrame keeps the currently rendered e-ink frame visible while
// the MCU sleeps. It is used only by unattended Daily Cards refreshes.
// timerOverrideSeconds schedules a bounded retry instead of the next daily
// wall-clock wake when non-zero. overridePurpose distinguishes an ordinary
// retry from the explicit one-shot diagnostic wake.
void enterDeepSleep(bool fromTimeout = false, bool preserveCurrentFrame = false, uint32_t timerOverrideSeconds = 0,
                    XtinctTimerOverridePurpose overridePurpose = XtinctTimerOverridePurpose::ScheduledRetry);
