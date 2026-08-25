#include <Arduino.h>
#include <BoardConfig.h>
#include <Epub.h>
#include <FontCacheManager.h>
#include <FontDecompressor.h>
#include <GfxRenderer.h>
#include <HalClock.h>
#include <HalDisplay.h>
#include <HalGPIO.h>
#include <HalPowerManager.h>
#include <HalStorage.h>
#include <HalSystem.h>
#include <HalTiltSensor.h>
#include <I18n.h>
#include <Logging.h>
#include <SPI.h>
#include <WiFi.h>
#include <builtinFonts/all.h>

#include <algorithm>
#include <cstring>

#include "CrossPointSettings.h"
#include "CrossPointState.h"
#include "DeepSleep.h"
#include "MappedInputManager.h"
#include "RecentBooksStore.h"
#include "SdCardFontSystem.h"
#include "XtinctFeedConfigStore.h"
#include "XtinctBuildInfo.h"
#include "XtinctWakePlan.h"
#include "XtinctWakeStatusStore.h"
#include "activities/Activity.h"
#include "activities/ActivityManager.h"
#include "activities/home/DailyCardsActivity.h"
#include "activities/settings/SdFirmwareUpdateActivity.h"
#include "components/UITheme.h"
#include "fontIds.h"
#include "images/LoadingIcon.h"
#include "network/OtaBootSwitch.h"
#include "network/PocketSyncStore.h"
#include "util/ButtonNavigator.h"
#include "util/ScreenshotUtil.h"
#include "util/XtinctBootRecovery.h"
#include "util/XtinctFeedCredentialPolicy.h"

static_assert(BoardConfig::XTEINK_X3.inputStyle == BoardConfig::InputStyle::XteinkAdcLadder,
              "X3 recovery sequence requires the ADC ladder contract");
static_assert(BoardConfig::XTEINK_X3_UC8279.inputStyle == BoardConfig::InputStyle::XteinkAdcLadder,
              "X3-UC8279 recovery sequence requires the ADC ladder contract");
static_assert(BoardConfig::XTEINK_X3.input.up == BoardConfig::XTEINK_X3_UC8279.input.up &&
                  BoardConfig::XTEINK_X3.input.down == BoardConfig::XTEINK_X3_UC8279.input.down &&
                  BoardConfig::XTEINK_X3.input.power == BoardConfig::XTEINK_X3_UC8279.input.power,
              "Both X3 panel variants must expose the same Up/Down/Power input contract");

GfxRenderer renderer(display);
MappedInputManager mappedInputManager(gpio, renderer);
ActivityManager activityManager(renderer, mappedInputManager);
FontDecompressor fontDecompressor;
SdCardFontSystem sdFontSystem;
FontCacheManager fontCacheManager(renderer.getFontMap(), renderer.getSdCardFonts());
static unsigned long allowSleepAt = 0;

// Fonts
EpdFont notoserif14RegularFont(&notoserif_14_regular);
EpdFont notoserif14BoldFont(&notoserif_14_bold);
EpdFont notoserif14ItalicFont(&notoserif_14_italic);
EpdFont notoserif14BoldItalicFont(&notoserif_14_bolditalic);
EpdFontFamily notoserif14FontFamily(&notoserif14RegularFont, &notoserif14BoldFont, &notoserif14ItalicFont,
                                    &notoserif14BoldItalicFont);
#ifndef OMIT_FONTS
EpdFont notoserif12RegularFont(&notoserif_12_regular);
EpdFont notoserif12BoldFont(&notoserif_12_bold);
EpdFont notoserif12ItalicFont(&notoserif_12_italic);
EpdFont notoserif12BoldItalicFont(&notoserif_12_bolditalic);
EpdFontFamily notoserif12FontFamily(&notoserif12RegularFont, &notoserif12BoldFont, &notoserif12ItalicFont,
                                    &notoserif12BoldItalicFont);
EpdFont notoserif16RegularFont(&notoserif_16_regular);
EpdFont notoserif16BoldFont(&notoserif_16_bold);
EpdFont notoserif16ItalicFont(&notoserif_16_italic);
EpdFont notoserif16BoldItalicFont(&notoserif_16_bolditalic);
EpdFontFamily notoserif16FontFamily(&notoserif16RegularFont, &notoserif16BoldFont, &notoserif16ItalicFont,
                                    &notoserif16BoldItalicFont);
EpdFont notoserif18RegularFont(&notoserif_18_regular);
EpdFont notoserif18BoldFont(&notoserif_18_bold);
EpdFont notoserif18ItalicFont(&notoserif_18_italic);
EpdFont notoserif18BoldItalicFont(&notoserif_18_bolditalic);
EpdFontFamily notoserif18FontFamily(&notoserif18RegularFont, &notoserif18BoldFont, &notoserif18ItalicFont,
                                    &notoserif18BoldItalicFont);

EpdFont notosans12RegularFont(&notosans_12_regular);
EpdFont notosans12BoldFont(&notosans_12_bold);
EpdFont notosans12ItalicFont(&notosans_12_italic);
EpdFont notosans12BoldItalicFont(&notosans_12_bolditalic);
EpdFontFamily notosans12FontFamily(&notosans12RegularFont, &notosans12BoldFont, &notosans12ItalicFont,
                                   &notosans12BoldItalicFont);
EpdFont notosans14RegularFont(&notosans_14_regular);
EpdFont notosans14BoldFont(&notosans_14_bold);
EpdFont notosans14ItalicFont(&notosans_14_italic);
EpdFont notosans14BoldItalicFont(&notosans_14_bolditalic);
EpdFontFamily notosans14FontFamily(&notosans14RegularFont, &notosans14BoldFont, &notosans14ItalicFont,
                                   &notosans14BoldItalicFont);
EpdFont notosans16RegularFont(&notosans_16_regular);
EpdFont notosans16BoldFont(&notosans_16_bold);
EpdFont notosans16ItalicFont(&notosans_16_italic);
EpdFont notosans16BoldItalicFont(&notosans_16_bolditalic);
EpdFontFamily notosans16FontFamily(&notosans16RegularFont, &notosans16BoldFont, &notosans16ItalicFont,
                                   &notosans16BoldItalicFont);
EpdFont notosans18RegularFont(&notosans_18_regular);
EpdFont notosans18BoldFont(&notosans_18_bold);
EpdFont notosans18ItalicFont(&notosans_18_italic);
EpdFont notosans18BoldItalicFont(&notosans_18_bolditalic);
EpdFontFamily notosans18FontFamily(&notosans18RegularFont, &notosans18BoldFont, &notosans18ItalicFont,
                                   &notosans18BoldItalicFont);

#endif  // OMIT_FONTS

EpdFont smallFont(&notosans_8_regular);
EpdFontFamily smallFontFamily(&smallFont);

EpdFont ui10RegularFont(&ubuntu_10_regular);
EpdFont ui10BoldFont(&ubuntu_10_bold);
EpdFontFamily ui10FontFamily(&ui10RegularFont, &ui10BoldFont);

EpdFont ui12RegularFont(&ubuntu_12_regular);
EpdFont ui12BoldFont(&ubuntu_12_bold);
EpdFontFamily ui12FontFamily(&ui12RegularFont, &ui12BoldFont);

// measurement of power button press duration calibration value
unsigned long t1 = 0;
unsigned long t2 = 0;

// Definitions for SilentRestart.h. RTC_NOINIT survives ESP.restart() but not power loss.
RTC_NOINIT_ATTR uint32_t silentRebootMagic;
RTC_NOINIT_ATTR uint32_t silentRebootTarget;
constexpr uint32_t SILENT_REBOOT_MAGIC = 0xC1EAB007;
constexpr uint32_t SILENT_REBOOT_TARGET_HOME = 0;
constexpr uint32_t SILENT_REBOOT_TARGET_READER = 1;

// How the device is coming back to life, resolved once at boot. Both resume
// flows suppress the splash and leave the panel holding its pre-boot frame; a
// plain boot shows the splash. See setup() for the resolution.
enum class BootResume : uint8_t {
  Splash,       // cold boot, flash, panic, or plain reboot
  Silent,       // heap-defrag ESP.restart() (RTC flag; lost on power loss)
  QuickResume,  // wake from a quick-resume deep sleep (SD flag; survives power loss)
  Scheduled,    // unattended timer wake for Daily Cards
};

// Latched true once enterDeepSleep() commits to sleeping, before it tears down
// the current activity. WiFi activities call silentRestart() in onExit() to
// clear heap fragmentation on the way out, but deep sleep is a full chip reset
// on wake and already clears the heap, so rebooting here would just power the
// device back up against the user's sleep gesture. Never cleared:
// startDeepSleep() does not return, so a set latch only ends at the wakeup reset.
static bool deepSleepInProgress = false;

void silentRestart() {
  if (deepSleepInProgress) return;  // sleeping supersedes the heap-defrag reboot
  silentRebootTarget = SILENT_REBOOT_TARGET_HOME;
  silentRebootMagic = SILENT_REBOOT_MAGIC;
  LOG_DBG("MAIN", "Silent restart (target=home)");
  // E-ink retains the previous frame until Home's first paint lands (~2-3s).
  // Without an overlay, users don't see the reboot and fire input through to
  // Home. Select on the default selectorIndex=0 then opens the most-recent
  // book, looking like a trampoline back to the reader they just exited.
  GUI.drawPopup(renderer, tr(STR_LOADING_POPUP));
  delay(50);
  ESP.restart();
}

void silentRestartToReader() {
  if (deepSleepInProgress) return;  // sleeping supersedes the heap-defrag reboot
  silentRebootTarget = SILENT_REBOOT_TARGET_READER;
  silentRebootMagic = SILENT_REBOOT_MAGIC;
  LOG_DBG("MAIN", "Silent restart (target=reader)");
  GUI.drawPopup(renderer, tr(STR_LOADING_POPUP));
  delay(50);
  ESP.restart();
}

void waitForPowerRelease() {
  gpio.update();
  while (gpio.isPressed(HalGPIO::BTN_POWER)) {
    delay(50);
    gpio.update();
  }
}

constexpr char SLEEP_FRAME_FILE[] = "/.crosspoint/sleep_frame.bin";

static void saveSleepFrameBuffer() {
  HalFile file;
  if (!Storage.openFileForWrite("SLP", SLEEP_FRAME_FILE, file)) return;
  file.write(renderer.getFrameBuffer(), renderer.getBufferSize());
  file.close();
}

static bool loadSleepFrameBuffer() {
  HalFile file;
  if (!Storage.openFileForRead("SLP", SLEEP_FRAME_FILE, file)) return false;
  const size_t bufferSize = display.getBufferSize();
  const size_t bytesRead = file.read(display.getFrameBuffer(), bufferSize);
  file.close();
  if (bytesRead != bufferSize) {
    Storage.remove(SLEEP_FRAME_FILE);
    return false;
  }
  Storage.remove(SLEEP_FRAME_FILE);
  return true;
}

static XtinctTimerArmState toPersistedTimerState(const HalPowerManager::TimerWakeArmState state) {
  switch (state) {
    case HalPowerManager::TimerWakeArmState::Armed:
      return XtinctTimerArmState::Armed;
    case HalPowerManager::TimerWakeArmState::Error:
      return XtinctTimerArmState::Error;
    case HalPowerManager::TimerWakeArmState::NotRequested:
    default:
      return XtinctTimerArmState::NotArmed;
  }
}

static void armAndRecordWakePlan(const XtinctWakePlan& plan) {
  const auto armResult = powerManager.armTimerWakeup(plan.ready ? plan.seconds : 0);
  XTINCT_WAKE_STATUS.recordTimerResult(plan, toPersistedTimerState(armResult.state), armResult.error);
  if (!XTINCT_WAKE_STATUS.saveToFile()) {
    LOG_ERR("MAIN", "Could not persist XTINCT timer-arm result");
  }
  if (!plan.ready) {
    LOG_ERR("MAIN", "XTINCT wake not armed: %s", xtinctWakeReasonCode(plan.reason));
  }
}

[[noreturn]] static void startHeadlessDeepSleepWithConfiguredWake() {
  armAndRecordWakePlan(calculateXtinctWakePlan());
  powerManager.startDeepSleep(gpio);
  while (true) {
  }
}

// Enter deep sleep mode
void enterDeepSleep(const bool fromTimeout, const bool preserveCurrentFrame, const uint32_t timerOverrideSeconds,
                    const XtinctTimerOverridePurpose overridePurpose) {
  HalPowerManager::Lock powerLock;  // Ensure we are at normal CPU frequency for sleep preparation

  const bool isQuickResumeSleep =
      !preserveCurrentFrame &&
      (SETTINGS.sleepScreen == CrossPointSettings::SLEEP_SCREEN_MODE::QUICK_RESUME ||
       (fromTimeout &&
        SETTINGS.quickResumeSleepScreen == CrossPointSettings::QUICK_RESUME_SLEEP_SCREEN::QUICK_RESUME_AFTER_TIMEOUT));
  if (!preserveCurrentFrame) {
    APP_STATE.lastSleepFromReader = activityManager.isReaderActivity();
    APP_STATE.showBootScreen = !isQuickResumeSleep;
    APP_STATE.saveToFile();
  }

  // Commit to sleeping before goToSleep() runs the outgoing activity's onExit():
  // a WiFi activity would otherwise silentRestart() here and reboot instead.
  deepSleepInProgress = true;

  // Capture and arm before rendering a potentially slow cover/custom sleep
  // screen. Sleeping at 04:14:58 must produce a short 04:15 timer rather than
  // letting rendering cross the wall-clock target and defer until 08:15.
  const XtinctWakePlan wakePlan =
      timerOverrideSeconds == 0
          ? calculateXtinctWakePlan()
          : (overridePurpose == XtinctTimerOverridePurpose::DiagnosticTest
                 ? calculateXtinctDiagnosticTestWakePlan(timerOverrideSeconds)
                 : calculateXtinctRetryWakePlan(timerOverrideSeconds));
  armAndRecordWakePlan(wakePlan);

  if (!preserveCurrentFrame) activityManager.goToSleep(fromTimeout);

  if (isQuickResumeSleep) {
    saveSleepFrameBuffer();
  }

  // Tear down WiFi so the modem power domain isn't held alive across deep sleep.
  // Wake from deep sleep is effectively a chip reset, so no state needs to survive.
  if (WiFi.getMode() != WIFI_MODE_NULL) {
    WiFi.disconnect(true);
    WiFi.mode(WIFI_OFF);
  }

  halTiltSensor.deepSleep();
  display.deepSleep();
  LOG_DBG("MAIN", "Entering deep sleep");

  powerManager.startDeepSleep(gpio);
}

void setupDisplayAndFonts(bool seamless = false) {
  display.begin(seamless);
  renderer.begin();
  activityManager.begin();
  LOG_DBG("MAIN", "Display initialized");

  // Initialize font decompressor for compressed reader fonts
  if (!fontDecompressor.init()) {
    LOG_ERR("MAIN", "Font decompressor init failed");
  }
  fontCacheManager.setFontDecompressor(&fontDecompressor);
  renderer.setFontCacheManager(&fontCacheManager);
  renderer.insertFont(NOTOSERIF_14_FONT_ID, notoserif14FontFamily);
#ifndef OMIT_FONTS
  renderer.insertFont(NOTOSERIF_12_FONT_ID, notoserif12FontFamily);
  renderer.insertFont(NOTOSERIF_16_FONT_ID, notoserif16FontFamily);
  renderer.insertFont(NOTOSERIF_18_FONT_ID, notoserif18FontFamily);

  renderer.insertFont(NOTOSANS_12_FONT_ID, notosans12FontFamily);
  renderer.insertFont(NOTOSANS_14_FONT_ID, notosans14FontFamily);
  renderer.insertFont(NOTOSANS_16_FONT_ID, notosans16FontFamily);
  renderer.insertFont(NOTOSANS_18_FONT_ID, notosans18FontFamily);
#endif  // OMIT_FONTS
  renderer.insertFont(UI_10_FONT_ID, ui10FontFamily);
  renderer.insertFont(UI_12_FONT_ID, ui12FontFamily);
  renderer.insertFont(SMALL_FONT_ID, smallFontFamily);

  // Discover and load SD card fonts
  sdFontSystem.begin(renderer);

  LOG_DBG("MAIN", "Fonts setup");
}

// Sample the X3-representable recovery sequence after the SD card is mounted
// but before any Pocket Sync transaction is recovered. A confirmed Power+Up
// first stage latches SD firmware recovery immediately; the optional neutral +
// Power+Down second stage requests a partition rollback. Up and Down share one
// ADC ladder, so they are intentionally never treated as a simultaneous chord.
static bool detectAndHandleBootRecovery() {
  const unsigned long settleStart = millis();
  while (!xtinct::boot_recovery::elapsed(millis(), settleStart, 500)) {
    gpio.update();
    delay(10);
  }

  uint32_t now = millis();
  xtinct::boot_recovery::Detector detector(now);
  xtinct::boot_recovery::Result result;
  const uint32_t deadlineStart = now;
  do {
    gpio.update();
    now = millis();
    result = detector.step(now, {gpio.isPressed(HalGPIO::BTN_POWER), gpio.isPressed(HalGPIO::BTN_UP),
                                 gpio.isPressed(HalGPIO::BTN_DOWN)});
    if (!result.finished) delay(10);
  } while (!result.finished &&
           !xtinct::boot_recovery::elapsed(
               now, deadlineStart,
               xtinct::boot_recovery::POWER_UP_HOLD_MS + xtinct::boot_recovery::SECOND_STAGE_TIMEOUT_MS + 500));

  if (!result.finished) {
    // Force a deterministic timeout transition; if Power+Up was confirmed the
    // detector deliberately preserves the SD-recovery latch.
    result = detector.step(millis(), {false, false, false});
  }

  if (!result.sdRecoveryLatched) return false;
  LOG_INF("MAIN", "SD firmware recovery latched (POWER + UP boot stage)");
  if (!result.partitionRollback) return true;

  const esp_partition_t* alternate = ota_boot::findAlternateAppPartition();
  if (!alternate || !ota_boot::hasValidAppImageHeader(alternate)) {
    LOG_ERR("MAIN", "Sequential rollback rejected: alternate app image is unavailable or invalid; using SD recovery");
    return true;
  }
  LOG_INF("MAIN", "Sequential rollback requested: switching to %s", alternate->label);
  if (!ota_boot::switchTo(alternate)) {
    LOG_ERR("MAIN", "Sequential rollback switch failed; using SD recovery");
    return true;
  }
  delay(50);
  ESP.restart();
  return true;
}

void setup() {
  BoardConfig::holdPowerRails();

  t1 = millis();

#ifdef ENABLE_SERIAL_LOG
  // Earliest possible Serial setup. The 250 ms stall before begin() lets the
  // USB Serial/JTAG peripheral finish power-on and lets the host complete USB
  // enumeration before we touch the CDC state — otherwise cold boot races
  // and the host has to be physically replugged for logs to flow. Warm reboot
  // worked without the delay because USB was already enumerated.
  delay(250);
  Serial.begin(115200);
#if LOG_SERIAL_HAS_TX_TIMEOUT
  logSerial.setTxTimeoutMs(1);  // This is a load-bearing 1. Do not modify.
#endif
#endif

  HalSystem::begin();

  // Read-and-clear so a panic later in setup() doesn't loop into silent reboot.
  // Bound the target range too — RTC_NOINIT memory is uninitialized on cold boot.
  const bool isSilentReboot = (silentRebootMagic == SILENT_REBOOT_MAGIC);
  const uint32_t snapshotTarget =
      (isSilentReboot && silentRebootTarget <= SILENT_REBOOT_TARGET_READER) ? silentRebootTarget : 0;
  silentRebootMagic = 0;
  silentRebootTarget = 0;

  gpio.begin();
  powerManager.begin();
  halTiltSensor.begin();
  halClock.begin();

  LOG_INF("MAIN", "Hardware detect: %s", gpio.deviceIsX3() ? "X3" : "X4");

  const auto wakeupReason = gpio.getWakeupReason();

  // SD Card Initialization
  // We need 6 open files concurrently when parsing a new chapter
  if (!Storage.begin()) {
    LOG_ERR("MAIN", "SD card initialization failed");
    setupDisplayAndFonts(isSilentReboot);
    activityManager.goToFullScreenMessage("SD card error", EpdFontFamily::BOLD);
    return;
  }

  // This must stay immediately after Storage.begin(): explicit Power+Up is the
  // escape hatch when a damaged Pocket Sync marker would otherwise fail closed
  // before the SD firmware picker can be shown. Gate the slower detector with
  // a direct physical sample, not the recorded wake cause: panic/software-reset
  // boot loops must remain recoverable, while an ordinary timer wake pays no
  // 500 ms settle delay.
  const bool recoveryFirmwareMode =
      gpio.isBootRecoveryPowerUpHeldNow() && detectAndHandleBootRecovery();

  // A power loss can occur between the V1/V2 backup and promote phases. Finish
  // or roll back that single SD transaction before any screen reads either
  // data set; never expose a half-committed Pocket Sync pack. Only the explicit
  // SD recovery latch bypasses this fail-closed guard.
  if (xtinct::boot_recovery::mustRecoverPendingCommit(recoveryFirmwareMode) &&
      !PocketSyncStore::recoverPendingCommit()) {
    LOG_ERR("MAIN", "Pocket Sync transaction recovery failed closed");
    setupDisplayAndFonts(isSilentReboot);
    activityManager.goToFullScreenMessage("Pocket Sync recovery failed", EpdFontFamily::BOLD);
    return;
  }

  HalSystem::checkPanic();

  SETTINGS.loadFromFile();
  if (SETTINGS.clockHasBeenSynced && !halClock.hasValidTime()) {
    // The historical flag can outlive a reset/flat battery-backed RTC. Clear it
    // so the next Wi-Fi session must recover UTC from NTP before TLS or a daily
    // wake can be armed.
    SETTINGS.clockHasBeenSynced = 0;
    if (!SETTINGS.saveToFile()) LOG_ERR("MAIN", "Could not clear invalid clock sync state");
  }
  APP_STATE.loadFromFile();
  RECENT_BOOKS.loadFromFile();
  I18N.setLanguage(static_cast<Language>(SETTINGS.language));
  XTINCT_FEED_CONFIG.load();
  XTINCT_WAKE_STATUS.loadFromFile();
  UITheme::getInstance().reload();
  ButtonNavigator::setMappedInputManager(mappedInputManager);

  XtinctObservedWakeCause observedWakeCause = XtinctObservedWakeCause::Other;
  switch (wakeupReason) {
    case HalGPIO::WakeupReason::Timer:
      observedWakeCause = XtinctObservedWakeCause::Timer;
      break;
    case HalGPIO::WakeupReason::PowerButton:
      observedWakeCause = XtinctObservedWakeCause::PowerButton;
      break;
    case HalGPIO::WakeupReason::AfterUSBPower:
      observedWakeCause = XtinctObservedWakeCause::UsbPower;
      break;
    case HalGPIO::WakeupReason::AfterFlash:
      observedWakeCause = XtinctObservedWakeCause::AfterFlash;
      break;
    case HalGPIO::WakeupReason::Other:
    default:
      observedWakeCause = XtinctObservedWakeCause::Other;
      break;
  }
  XTINCT_WAKE_STATUS.recordWakeCause(observedWakeCause);
  if (!XTINCT_WAKE_STATUS.saveToFile()) LOG_ERR("MAIN", "Could not persist XTINCT wake cause");
  if (wakeupReason != HalGPIO::WakeupReason::Timer) DailyCardsActivity::resetScheduledRetryState();
  switch (wakeupReason) {
    case HalGPIO::WakeupReason::PowerButton:
      if (recoveryFirmwareMode) {
        LOG_INF("MAIN", "Power hold verification bypassed for latched SD recovery");
        break;
      }
      LOG_DBG("MAIN", "Verifying power button press duration");
      if (!gpio.verifyPowerButtonWakeup(SETTINGS.getPowerButtonDuration(),
                                        SETTINGS.shortPwrBtn == CrossPointSettings::SHORT_PWRBTN::SLEEP)) {
        startHeadlessDeepSleepWithConfiguredWake();
      }
      break;
    case HalGPIO::WakeupReason::AfterUSBPower:
      // If USB power caused a cold boot, go back to sleep
      LOG_DBG("MAIN", "Wakeup reason: After USB Power");
      if (xtinct::boot_recovery::mayEnterPreRoutingSleep(recoveryFirmwareMode)) {
        startHeadlessDeepSleepWithConfiguredWake();
      } else {
        LOG_INF("MAIN", "USB-power sleep bypassed for latched SD recovery");
      }
      break;
    case HalGPIO::WakeupReason::AfterFlash:
      // After flashing, just proceed to boot
    case HalGPIO::WakeupReason::Other:
    default:
      break;
  }

  // A separate Power+Down shortcut opens the physically local Phone Wi-Fi
  // Setup portal. Do not run it after the Power+Up SD-recovery latch.
  bool wifiProvisioningRecoveryMode = false;
  if (wakeupReason == HalGPIO::WakeupReason::PowerButton && !recoveryFirmwareMode) {
    // Refresh the cached button state a few times — isPressed() needs ~half a second to settle
    // after boot per the HalGPIO contract. Use a millis-based deadline so we always wait the full
    // settle window even if the loop body takes longer than expected on slow boots.
    const unsigned long settleStart = millis();
    while (millis() - settleStart < 500) {
      gpio.update();
      delay(10);
    }
    if (gpio.isPressed(HalGPIO::BTN_DOWN)) {
      wifiProvisioningRecoveryMode = true;
      LOG_INF("MAIN", "Phone Wi-Fi recovery mode (DOWN + POWER held at boot)");
    }
  }

  // First serial output only here to avoid timing inconsistencies for power button press duration verification
  LOG_DBG("MAIN", "Starting CrossPoint version " CROSSPOINT_VERSION);

  // Resolve the single boot-presentation decision. Skipping the splash also
  // skips the panel-clearing pass and the X3 initial-full-sync arming (see
  // HalDisplay::begin), so the first paint is FAST_REFRESH (~500ms) over the
  // retained frame and input dispatches against a visible UI.
  const bool isScheduledWake = wakeupReason == HalGPIO::WakeupReason::Timer;
  // Consume the RTC one-shot purpose before any activity starts. A diagnostic
  // timer wake therefore cannot inherit or create the ordinary retry loop,
  // even when its single network attempt fails.
  const bool isDiagnosticTestWake = isScheduledWake && DailyCardsActivity::consumeDiagnosticTestWake();
  const BootResume resume = isScheduledWake             ? BootResume::Scheduled
                            : isSilentReboot              ? BootResume::Silent
                            : !APP_STATE.showBootScreen ? BootResume::QuickResume
                                                        : BootResume::Splash;
  bool allowFastInitialReaderRefresh = false;

  setupDisplayAndFonts(resume == BootResume::Silent || resume == BootResume::QuickResume);

  switch (resume) {
    case BootResume::Silent:
      // Splash skipped: the routing block below picks the target activity; the
      // panel keeps showing the pre-reboot popup until that first paint lands.
      break;
    case BootResume::QuickResume:
      // One-shot flag: re-arm the splash for the next non-quick-resume boot. Save
      // before any painting so a hang in the blocking paint path can't strand
      // us in a quick-resume-with-no-frame loop on the next boot.
      APP_STATE.showBootScreen = true;
      APP_STATE.saveToFile();
      if (loadSleepFrameBuffer()) {
        const bool useDifferentialRefresh = gpio.deviceIsX3();
        if (useDifferentialRefresh) {
          // begin() clears the X3 controller RAM, so restore the saved frame as
          // the baseline before replacing the moon with the loading icon.
          renderer.cleanupGrayscaleWithFrameBuffer();
        }

        const auto pageHeight = renderer.getScreenHeight();
        renderer.drawImage(LoadingIcon, 0, pageHeight - LOADINGICON_HEIGHT, LOADINGICON_WIDTH, LOADINGICON_HEIGHT);
        if (useDifferentialRefresh) {
          renderer.displayGrayscaleBase(HalDisplay::FAST_REFRESH);
          allowFastInitialReaderRefresh = true;
        } else {
          renderer.displayBuffer(HalDisplay::HALF_REFRESH);
        }
      } else {
        activityManager.goToBoot();  // frame file missing, fall back to the splash
      }
      break;
    case BootResume::Splash:
      activityManager.goToBoot();
      break;
    case BootResume::Scheduled:
      // Full display/controller initialization above, but no splash. The Daily
      // Cards activity is the first frame and will return to sleep after it lands.
      break;
  }

  if (recoveryFirmwareMode) {
    // Skip normal home/reader routing: jump straight into the SD firmware picker.
    activityManager.replaceActivity(
        std::make_unique<SdFirmwareUpdateActivity>(renderer, mappedInputManager, /*recoveryMode=*/true));
  } else if (wifiProvisioningRecoveryMode) {
    activityManager.goToWifiProvisioning(/*recoveryMode=*/true);
  } else if (HalSystem::isRebootFromPanic()) {
    // If we rebooted from a panic, go to crash report screen to show the panic info
    activityManager.goToCrashReport();
  } else if (isScheduledWake) {
    activityManager.goToDailyCards(/*scheduledWake=*/true,
                                   /*allowScheduledRetries=*/!isDiagnosticTestWake);
  } else if (resume == BootResume::Silent && snapshotTarget == SILENT_REBOOT_TARGET_READER &&
             !APP_STATE.openEpubPath.empty()) {
    activityManager.goToReader(APP_STATE.openEpubPath);
  } else if (resume == BootResume::Silent) {
    // target == home (or reader with no open book): land on home — don't fall
    // through to the sleep-wake "resume reader" logic, which fires on stale
    // openEpubPath + lastSleepFromReader from a prior session.
    activityManager.goHome();
  } else if (APP_STATE.openEpubPath.empty() || !APP_STATE.lastSleepFromReader ||
             mappedInputManager.isPressed(MappedInputManager::Button::Back) || APP_STATE.readerActivityLoadCount > 0) {
    // Boot to home screen if no book is open, last sleep was not from reader, back button is held, or reader activity
    // crashed (indicated by readerActivityLoadCount > 0)
    activityManager.goHome();
  } else {
    // Clear app state to avoid getting into a boot loop if the epub doesn't load
    const auto path = APP_STATE.openEpubPath;
    APP_STATE.openEpubPath = "";
    APP_STATE.readerActivityLoadCount++;
    APP_STATE.saveToFile();
    activityManager.goToReader(path, allowFastInitialReaderRefresh);
  }

  if (resume == BootResume::Silent) {
    // Block until the first paint physically completes. refreshDisplay()
    // waits on the panel BUSY pin so when this returns the user can see the
    // new activity. Without the wait, an edge captured by gpio.update()
    // during boot dispatches against an invisible Home and the default
    // selectorIndex=0 opens the most-recent book.
    activityManager.requestUpdateAndWait();
    // Absorb any button held at this point into currentState as a non-edge:
    // two gpio.update() calls separated by > InputManager's 5ms debounce
    // transition the held bit through lastDebounceTime into currentState
    // without setting pressedEvents, so the first loop()'s own gpio.update()
    // sees state == currentState and emits nothing.
    gpio.update();
    delay(10);
    gpio.update();
  }

  // Ensure we're not still holding the power button before leaving setup
  waitForPowerRelease();
  allowSleepAt = millis() + 2000;
}

void loop() {
  static unsigned long maxLoopDuration = 0;
  const unsigned long loopStartTime = millis();
  static unsigned long lastMemPrint = 0;

  gpio.setSharedConfirmPowerShortPressEmitsPower(SETTINGS.shortPwrBtn == CrossPointSettings::SHORT_PWRBTN::SLEEP);
  gpio.update();
  halTiltSensor.update(SETTINGS.tiltPageTurn, SETTINGS.orientation, activityManager.isReaderActivity());

  renderer.setFadingFix(SETTINGS.fadingFix);

  if (Serial && millis() - lastMemPrint >= 10000) {
    LOG_INF("MEM", "Free: %d bytes, Total: %d bytes, Min Free: %d bytes, MaxAlloc: %d bytes", ESP.getFreeHeap(),
            ESP.getHeapSize(), ESP.getMinFreeHeap(), ESP.getMaxAllocHeap());
    lastMemPrint = millis();
  }

  // Assemble USB commands without the blocking Stream line reader: a malformed host
  // must not grow an unbounded secret-bearing String or block the main loop.
  // We use logSerial from logging to avoid deprecation warnings.
  constexpr char XTINCT_FEED_COMMAND[] = "CMD:XTINCT_FEED:";
  constexpr size_t MAX_SERIAL_COMMAND_BYTES =
      sizeof(XTINCT_FEED_COMMAND) - 1 + xtinct::feed_credential::MAX_ORIGIN_LENGTH + 1 +
      xtinct::feed_credential::MAX_TOKEN_LENGTH;
  static char serialCommand[MAX_SERIAL_COMMAND_BYTES + 1] = {};
  static size_t serialCommandLength = 0;
  static bool discardOversizedSerialCommand = false;
  while (logSerial.available() > 0) {
    const int next = logSerial.read();
    if (next < 0) break;
    const char value = static_cast<char>(next);
    if (value == '\r') continue;
    if (value != '\n') {
      if (discardOversizedSerialCommand) continue;
      if (serialCommandLength >= MAX_SERIAL_COMMAND_BYTES) {
        std::fill(serialCommand, serialCommand + serialCommandLength, '\0');
        serialCommandLength = 0;
        discardOversizedSerialCommand = true;
        continue;
      }
      serialCommand[serialCommandLength++] = value;
      continue;
    }
    if (discardOversizedSerialCommand) {
      discardOversizedSerialCommand = false;
      logSerial.println("ERR:SERIAL:SIZE");
      continue;
    }
    serialCommand[serialCommandLength] = '\0';
    String line(serialCommand);
    if (line.startsWith(XTINCT_FEED_COMMAND)) {
      const size_t prefixLength = sizeof(XTINCT_FEED_COMMAND) - 1;
      const int separator = line.indexOf(' ', prefixLength);
      const bool mayReplace = !XTINCT_FEED_CONFIG.hasReadToken() || activityManager.isWifiProvisioningActivity();
      if (!mayReplace) {
        logSerial.println("ERR:XTINCT_FEED:LOCKED");
      } else if (separator <= static_cast<int>(prefixLength) ||
                 static_cast<size_t>(separator + 1) >= line.length()) {
        logSerial.println("ERR:XTINCT_FEED:FORMAT");
      } else {
        std::string origin(line.c_str() + prefixLength, static_cast<size_t>(separator) - prefixLength);
        std::string token(line.c_str() + separator + 1, line.length() - static_cast<size_t>(separator + 1));
        if (!XtinctFeedConfigStore::isValidBaseUrl(origin)) {
          logSerial.println("ERR:XTINCT_FEED:ORIGIN");
        } else if (!XtinctFeedConfigStore::isValidReadToken(token)) {
          logSerial.println("ERR:XTINCT_FEED:TOKEN");
        } else {
          const bool saved = XTINCT_FEED_CONFIG.replaceCredential(origin, token);
          logSerial.println(saved ? "OK:XTINCT_FEED" : "ERR:XTINCT_FEED:SAVE");
        }
        std::fill(origin.begin(), origin.end(), '\0');
        std::fill(token.begin(), token.end(), '\0');
      }
      // Best-effort erase of the transient serial receive buffer. The durable
      // credential lives only in one bound NVS record and private RAM fields.
      for (size_t i = prefixLength; i < line.length(); ++i) line.setCharAt(i, '\0');
    } else if (line.startsWith("CMD:")) {
      String cmd = line.substring(4);
      cmd.trim();
      if (cmd == "XTINCT_IDENTITY") {
        logSerial.printf("OK:XTINCT_IDENTITY:X3:%s\n", XTINCT_BUILD_ID);
      } else if (cmd == "SCREENSHOT") {
        const uint32_t bufferSize = display.getBufferSize();
        logSerial.printf("SCREENSHOT_START:%d\n", bufferSize);
        uint8_t* buf = display.getFrameBuffer();
        logSerial.write(buf, bufferSize);
        logSerial.printf("SCREENSHOT_END\n");
      }
    }
    std::fill(serialCommand, serialCommand + serialCommandLength, '\0');
    serialCommandLength = 0;
  }

  // Check for any user activity (button press or release) or active background work
  static unsigned long lastActivityTime = millis();
  if (gpio.wasAnyPressed() || gpio.wasAnyReleased() || gpio.wasTouchActivity() || halTiltSensor.hadActivity() ||
      activityManager.preventAutoSleep()) {
    lastActivityTime = millis();         // Reset inactivity timer
    powerManager.setPowerSaving(false);  // Restore normal CPU frequency on user activity
  }

  static bool screenshotButtonsReleased = true;
  static bool screenshotComboActive = false;
  if (gpio.isPressed(HalGPIO::BTN_POWER) && gpio.isPressed(HalGPIO::BTN_DOWN)) {
    screenshotComboActive = true;
    if (screenshotButtonsReleased) {
      screenshotButtonsReleased = false;
      {
        RenderLock lock;
        ScreenshotUtil::takeScreenshot(renderer);
      }
    }
    return;
  }
  if (screenshotComboActive) {
    if (gpio.isPressed(HalGPIO::BTN_POWER)) return;
    if (gpio.wasReleased(HalGPIO::BTN_POWER)) {
      screenshotButtonsReleased = true;
      screenshotComboActive = false;
      return;
    }
    screenshotButtonsReleased = true;
    screenshotComboActive = false;
  }

  const unsigned long sleepTimeoutMs = SETTINGS.getSleepTimeoutMs();
  if (sleepTimeoutMs > 0 && millis() - lastActivityTime >= sleepTimeoutMs) {
    LOG_DBG("SLP", "Auto-sleep triggered after %lu ms of inactivity", sleepTimeoutMs);
    enterDeepSleep(true);
    // This should never be hit as `enterDeepSleep` calls esp_deep_sleep_start
    return;
  }

  if (millis() >= allowSleepAt && gpio.isPressed(HalGPIO::BTN_POWER) &&
      gpio.getPowerButtonHeldTime() > SETTINGS.getPowerButtonDuration()) {
    // If the screenshot combination is potentially being pressed, don't sleep
    if (gpio.isPressed(HalGPIO::BTN_DOWN)) {
      return;
    }
    enterDeepSleep();
    // This should never be hit as `enterDeepSleep` calls esp_deep_sleep_start
    return;
  }

  // Refresh screen when power button is short-pressed with FORCE_REFRESH setting.
  if (SETTINGS.shortPwrBtn == CrossPointSettings::SHORT_PWRBTN::FORCE_REFRESH &&
      mappedInputManager.wasReleased(MappedInputManager::Button::Power)) {
    LOG_DBG("MAIN", "Manual screen refresh triggered");
    if (!activityManager.handleForcedRefresh()) {
      RenderLock lock;
      renderer.displayBuffer(HalDisplay::HALF_REFRESH);
    }
  }

  // Refresh the battery icon when USB is plugged or unplugged.
  // Placed after sleep guards so we never queue a render that won't be processed.
  if (gpio.wasUsbStateChanged()) {
    activityManager.requestUpdate();
  }

  const unsigned long activityStartTime = millis();
  activityManager.loop();
  const unsigned long activityDuration = millis() - activityStartTime;

  const unsigned long loopDuration = millis() - loopStartTime;
  if (loopDuration > maxLoopDuration) {
    maxLoopDuration = loopDuration;
    if (maxLoopDuration > 50) {
      LOG_DBG("LOOP", "New max loop duration: %lu ms (activity: %lu ms)", maxLoopDuration, activityDuration);
    }
  }

  // Add delay at the end of the loop to prevent tight spinning
  // When an activity requests skip loop delay (e.g., webserver running), use yield() for faster response
  // Otherwise, use longer delay to save power
  if (activityManager.skipLoopDelay()) {
    powerManager.setPowerSaving(false);  // Make sure we're at full performance when skipLoopDelay is requested
    yield();                             // Give FreeRTOS a chance to run tasks, but return immediately
  } else {
    if (millis() - lastActivityTime >= HalPowerManager::IDLE_POWER_SAVING_MS) {
      // If we've been inactive for a while, increase the delay to save power
      powerManager.setPowerSaving(true);  // Lower CPU frequency after extended inactivity
      delay(50);
    } else {
      // Short delay to prevent tight loop while still being responsive
      delay(10);
    }
  }
}
