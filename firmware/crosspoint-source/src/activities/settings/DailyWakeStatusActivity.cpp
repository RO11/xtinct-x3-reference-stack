#include "DailyWakeStatusActivity.h"

#include <GfxRenderer.h>
#include <I18n.h>

#include <cstdio>
#include <string>

#include "CrossPointSettings.h"
#include "DeepSleep.h"
#include "MappedInputManager.h"
#include "XtinctBuildInfo.h"
#include "XtinctFeedConfigStore.h"
#include "XtinctWakePlan.h"
#include "XtinctWakeStatusStore.h"
#include "activities/home/DailyCardsActivity.h"
#include "components/UITheme.h"
#include "fontIds.h"

void DailyWakeStatusActivity::onEnter() {
  Activity::onEnter();
  testBlocked = false;
  requestUpdate();
}

void DailyWakeStatusActivity::loop() {
  if (mappedInput.wasPressed(MappedInputManager::Button::Back)) {
    finish();
    return;
  }
  if (mappedInput.wasPressed(MappedInputManager::Button::Confirm)) {
    const XtinctWakePlan plan = calculateXtinctWakePlan();
    if (!plan.ready) {
      testBlocked = true;
      requestUpdate();
      return;
    }
    // This is an explicit physical test action. It sleeps immediately, wakes
    // once in two minutes, performs the normal scheduled sync, and then returns
    // to the configured daily schedule.
    DailyCardsActivity::prepareDiagnosticTestWake();
    enterDeepSleep(false, false, 2U * 60U, XtinctTimerOverridePurpose::DiagnosticTest);
  }
}

void DailyWakeStatusActivity::render(RenderLock&&) {
  renderer.clearScreen();
  const auto& metrics = UITheme::getInstance().getMetrics();
  const int width = renderer.getScreenWidth();
  const int height = renderer.getScreenHeight();
  const int margin = metrics.contentSidePadding;
  const int contentWidth = width - margin * 2;
  GUI.drawHeader(renderer, Rect{0, metrics.topPadding, width, metrics.headerHeight}, tr(STR_DAILY_WAKE_STATUS),
                 XTINCT_RELEASE_LABEL);

  const XtinctWakePlan plan = calculateXtinctWakePlan();
  char windows[40] = "Unavailable";
  formatXtinctWakeWindows(windows, sizeof(windows));
  char timezone[16] = "Invalid";
  formatXtinctUtcOffset(SETTINGS.clockUtcOffsetQ, timezone, sizeof(timezone));
  char nextTime[8] = "--:--";
  if (plan.nextLocalKnown) formatXtinctLocalTime(plan.nextHour, plan.nextMinute, nextTime, sizeof(nextTime));
  char lastTimerTime[8] = "--:--";
  if (XTINCT_WAKE_STATUS.isLastTimerNextLocalKnown()) {
    formatXtinctLocalTime(XTINCT_WAKE_STATUS.getLastTimerNextHour(), XTINCT_WAKE_STATUS.getLastTimerNextMinute(),
                          lastTimerTime, sizeof(lastTimerTime));
  }

  int y = metrics.topPadding + metrics.headerHeight + metrics.verticalSpacing * 2;
  const int lineHeight = renderer.getLineHeight(UI_10_FONT_ID) + metrics.verticalSpacing;
  auto drawLine = [&](const char* label, const char* value, const bool boldValue = false) {
    char line[160];
    std::snprintf(line, sizeof(line), "%s: %s", label, value);
    const std::string clipped = renderer.truncatedText(UI_10_FONT_ID, line, contentWidth);
    renderer.drawText(UI_10_FONT_ID, margin, y, clipped.c_str(), true,
                      boldValue ? EpdFontFamily::BOLD : EpdFontFamily::REGULAR);
    y += lineHeight;
  };

  drawLine("Build", XTINCT_BUILD_ID);
  drawLine("Auto sync", XTINCT_FEED_CONFIG.isAutoSyncRequested() ? "ON" : "OFF",
           XTINCT_FEED_CONFIG.isAutoSyncRequested());
  drawLine("Credential", XTINCT_FEED_CONFIG.hasReadToken() ? "Installed" : "MISSING",
           !XTINCT_FEED_CONFIG.hasReadToken());
  drawLine("Clock", SETTINGS.clockHasBeenSynced ? "Synchronized" : "NOT SYNCHRONIZED",
           !SETTINGS.clockHasBeenSynced);
  drawLine("Timezone", timezone, SETTINGS.clockUtcOffsetQ != 88);
  if (SETTINGS.clockUtcOffsetQ != 88) drawLine("Warning", "Brisbane requires UTC+10:00", true);
  drawLine("Windows", windows);
  drawLine("Next sleep", plan.ready ? nextTime : xtinctWakeReasonLabel(plan.reason), !plan.ready);

  char lastTimer[160];
  if (XTINCT_WAKE_STATUS.getLastTimerState() == XtinctTimerArmState::Armed &&
      XTINCT_WAKE_STATUS.isLastTimerNextLocalKnown()) {
    std::snprintf(lastTimer, sizeof(lastTimer), "%s for %s",
                  xtinctTimerArmStateLabel(XTINCT_WAKE_STATUS.getLastTimerState()), lastTimerTime);
  } else if (XTINCT_WAKE_STATUS.getLastTimerState() == XtinctTimerArmState::NotArmed) {
    std::snprintf(lastTimer, sizeof(lastTimer), "%s - %s",
                  xtinctTimerArmStateLabel(XTINCT_WAKE_STATUS.getLastTimerState()),
                  xtinctWakeReasonLabel(XTINCT_WAKE_STATUS.getLastTimerReason()));
  } else if (XTINCT_WAKE_STATUS.getLastTimerState() == XtinctTimerArmState::Error) {
    std::snprintf(lastTimer, sizeof(lastTimer), "%s (%ld)",
                  xtinctTimerArmStateLabel(XTINCT_WAKE_STATUS.getLastTimerState()),
                  static_cast<long>(XTINCT_WAKE_STATUS.getLastTimerError()));
  } else {
    std::snprintf(lastTimer, sizeof(lastTimer), "%s",
                  xtinctTimerArmStateLabel(XTINCT_WAKE_STATUS.getLastTimerState()));
  }
  drawLine("Last sleep", lastTimer, XTINCT_WAKE_STATUS.getLastTimerState() != XtinctTimerArmState::Armed);
  drawLine("Last wake", xtinctWakeCauseLabel(XTINCT_WAKE_STATUS.getLastWakeCause()),
           XTINCT_WAKE_STATUS.getLastWakeCause() == XtinctObservedWakeCause::Timer);

  if (testBlocked) {
    const int messageHeight = renderer.getLineHeight(SMALL_FONT_ID) * 2;
    UITheme::drawCenteredWrappedText(renderer, Rect{margin, y + metrics.verticalSpacing, contentWidth, messageHeight},
                                     SMALL_FONT_ID, xtinctWakeReasonLabel(plan.reason), 2, true,
                                     EpdFontFamily::BOLD);
  }

  const auto labels = mappedInput.mapLabels(tr(STR_BACK), "Test 2 min", "", "");
  GUI.drawButtonHints(renderer, labels.btn1, labels.btn2, labels.btn3, labels.btn4);
  renderer.displayBuffer();
}
