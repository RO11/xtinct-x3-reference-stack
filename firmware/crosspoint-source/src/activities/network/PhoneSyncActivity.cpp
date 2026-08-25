#include "PhoneSyncActivity.h"

#include <GfxRenderer.h>
#include <I18n.h>
#include <Memory.h>

#include <cstdio>

#include "MappedInputManager.h"
#include "components/UITheme.h"
#include "fontIds.h"

namespace {
const char* stageText(const PocketSyncBleServer::Snapshot& state) {
  using Stage = PocketSyncBleServer::UiStage;
  switch (state.stage) {
    case Stage::Advertising:
      return state.configured ? tr(STR_PHONE_SYNC_READY) : tr(STR_PHONE_SYNC_FIND);
    case Stage::Pairing:
      return tr(STR_PHONE_SYNC_PAIRING);
    case Stage::Secured:
      return tr(STR_PHONE_SYNC_SECURED);
    case Stage::Gathering:
      return tr(STR_PHONE_SYNC_GATHERING);
    case Stage::Receiving:
      return state.stream == xtinct::pocket_sync::MANIFEST_STREAM ? tr(STR_PHONE_SYNC_MANIFEST)
                                                                  : tr(STR_PHONE_SYNC_OBJECTS);
    case Stage::Validating:
      return tr(STR_PHONE_SYNC_VALIDATING);
    case Stage::Committing:
      return tr(STR_PHONE_SYNC_COMMITTING);
    case Stage::Complete:
      return tr(STR_PHONE_SYNC_COMPLETE);
    case Stage::Failed:
      return tr(STR_PHONE_SYNC_FAILED);
    case Stage::Stopped:
    default:
      return tr(STR_PHONE_SYNC_START_FAILED);
  }
}
}  // namespace

void PhoneSyncActivity::onEnter() {
  Activity::onEnter();
  sessionStartedAt = millis();
  pocketServer = makeUniqueNoThrow<PocketSyncBleServer>();
  started = pocketServer && pocketServer->begin();
  if (pocketServer) {
    state = pocketServer->snapshot();
    renderedGeneration = pocketServer->uiGeneration();
  }
  requestUpdate();
}

void PhoneSyncActivity::onExit() {
  if (pocketServer) {
    pocketServer->end();
    pocketServer.reset();
  }
  Activity::onExit();
}

void PhoneSyncActivity::loop() {
  if (mappedInput.wasPressed(MappedInputManager::Button::Back) ||
      millis() - sessionStartedAt >= SESSION_TIMEOUT_MS) {
    onGoHome();
    return;
  }
  if (!started || !pocketServer) return;

  if (resetHoldFired) {
    if (!mappedInput.isPressed(MappedInputManager::Button::Confirm)) resetHoldFired = false;
  } else if (mappedInput.isPressed(MappedInputManager::Button::Confirm) &&
             mappedInput.getHeldTime() >= RESET_HOLD_MS) {
    resetHoldFired = true;
    resetSucceeded = pocketServer->resetPairing();
    requestUpdate();
  }

  pocketServer->loop();
  const uint32_t generation = pocketServer->uiGeneration();
  if (generation != renderedGeneration) {
    renderedGeneration = generation;
    state = pocketServer->snapshot();
    requestUpdate();
  }
}

void PhoneSyncActivity::render(RenderLock&&) {
  renderer.clearScreen();
  const auto& metrics = UITheme::getInstance().getMetrics();
  const int width = renderer.getScreenWidth();
  const int height = renderer.getScreenHeight();
  GUI.drawHeader(renderer, Rect{0, metrics.topPadding, width, metrics.headerHeight}, tr(STR_PHONE_SYNC));

  const int contentTop = metrics.topPadding + metrics.headerHeight + metrics.verticalSpacing * 2;
  const int contentWidth = width - 2 * metrics.contentSidePadding;
  UITheme::drawCenteredWrappedText(
      renderer, Rect{metrics.contentSidePadding, contentTop, contentWidth, 90}, UI_12_FONT_ID,
      started ? stageText(state) : tr(STR_PHONE_SYNC_START_FAILED), 4, true, EpdFontFamily::BOLD);

  int y = contentTop + 112;
  if (started && !state.configured && state.enrollmentOpen) {
    char passkey[32];
    std::snprintf(passkey, sizeof(passkey), "%06lu", static_cast<unsigned long>(pocketServer->passkey()));
    renderer.drawCenteredText(UI_12_FONT_ID, y, tr(STR_PHONE_SYNC_PASSKEY), true, EpdFontFamily::BOLD);
    renderer.drawCenteredText(UI_12_FONT_ID, y + 42, passkey, true, EpdFontFamily::BOLD);
    y += 104;
    UITheme::drawCenteredWrappedText(
        renderer, Rect{metrics.contentSidePadding, y, contentWidth, 76}, UI_10_FONT_ID,
        tr(STR_PHONE_SYNC_PAIRING_OPEN), 3);
  } else if (state.stage == PocketSyncBleServer::UiStage::Receiving) {
    char progress[96];
    if (state.stream == xtinct::pocket_sync::MANIFEST_STREAM) {
      std::snprintf(progress, sizeof(progress), tr(STR_PHONE_SYNC_MANIFEST_PROGRESS),
                    static_cast<unsigned long>(state.durableOffset));
    } else {
      std::snprintf(progress, sizeof(progress), tr(STR_PHONE_SYNC_OBJECT_PROGRESS),
                    static_cast<unsigned>(state.stream + 1),
                    static_cast<unsigned long>(state.durableOffset));
    }
    renderer.drawCenteredText(UI_10_FONT_ID, y, progress);
    y += 52;
  }

  if (resetSucceeded) {
    UITheme::drawCenteredWrappedText(renderer, Rect{metrics.contentSidePadding, y, contentWidth, 72},
                                     UI_10_FONT_ID, tr(STR_PHONE_SYNC_RESET_DONE), 3, true,
                                     EpdFontFamily::BOLD);
  } else if (started && state.configured &&
             state.stage != PocketSyncBleServer::UiStage::Complete) {
    UITheme::drawCenteredWrappedText(renderer, Rect{metrics.contentSidePadding, y, contentWidth, 88},
                                     UI_10_FONT_ID, tr(STR_PHONE_SYNC_ATOMIC_HINT), 4);
  }

  const auto labels = mappedInput.mapLabels(tr(STR_BACK), tr(STR_PHONE_SYNC_RESET_HINT), "", "");
  GUI.drawButtonHints(renderer, labels.btn1, labels.btn2, labels.btn3, labels.btn4);
  renderer.displayBuffer();
}

