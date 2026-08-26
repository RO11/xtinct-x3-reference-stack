#include "InboxActivity.h"

#include <GfxRenderer.h>
#include <HalClock.h>
#include <HalStorage.h>
#include <Logging.h>
#include <Memory.h>
#include <Txt.h>

#include <algorithm>
#include <cstdio>
#include <memory>

#include "CrossPointSettings.h"
#include "MappedInputManager.h"
#include "SdCardFontSystem.h"
#include "activities/reader/TxtReaderActivity.h"
#include "activities/util/BmpViewerActivity.h"
#include "components/UITheme.h"
#include "fontIds.h"
#include "network/XtinctFeedClient.h"
#include "util/XtinctDateFormat.h"

void InboxActivity::onEnter() {
  Activity::onEnter();
  resetPaging();
  loadItems();
  view = itemCount > 0 ? View::PREVIEW : View::LIST;
  if (itemCount > 0) loadSelectedPreview();
  requestUpdate();
}

void InboxActivity::onExit() {
  XtinctFeedClient::disconnectWifi();
  Activity::onExit();
}

void InboxActivity::loadItems() {
  do {
    const PageCursor& cursor = pageHistory.current();
    const char* beforeCreatedAt = cursor.createdAt[0] == '\0' ? nullptr : cursor.createdAt;
    const char* beforeItemId = cursor.itemId[0] == '\0' ? nullptr : cursor.itemId;
    itemCount = XtinctSyncClient::loadInboxPage(items, VISIBLE_ITEM_LIMIT, beforeCreatedAt, beforeItemId,
                                                hasOlderItems);
    if (itemCount > 0 || pageHistory.pageIndex() == 0) break;
  } while (pageHistory.previous());
  if (itemCount == 0) selectorIndex = 0;
  else if (selectorIndex >= static_cast<int>(itemCount)) selectorIndex = static_cast<int>(itemCount) - 1;
}

void InboxActivity::resetPaging() {
  pageHistory.reset();
  selectorIndex = 0;
  hasOlderItems = false;
}

void InboxActivity::showPreviousPage() {
  if (!pageHistory.previous()) return;
  selectorIndex = 0;
  statusMessage.clear();
  loadItems();
  if (view == View::PREVIEW && itemCount > 0) loadSelectedPreview();
  requestUpdate();
}

void InboxActivity::showNextPage() {
  if (!hasOlderItems || itemCount == 0 || !pageHistory.canPush()) return;
  PageCursor cursor;
  const XtinctInboxItem& boundary = items[itemCount - 1];
  std::snprintf(cursor.createdAt, sizeof(cursor.createdAt), "%s", boundary.createdAt);
  std::snprintf(cursor.itemId, sizeof(cursor.itemId), "%s", boundary.itemId);
  if (!pageHistory.push(cursor)) return;
  selectorIndex = 0;
  statusMessage.clear();
  loadItems();
  if (view == View::PREVIEW && itemCount > 0) loadSelectedPreview();
  requestUpdate();
}

void InboxActivity::listBounds(int& contentTop, int& contentHeight) const {
  const auto& metrics = UITheme::getInstance().getMetrics();
  contentTop = metrics.topPadding + metrics.headerHeight + metrics.verticalSpacing;
  const int statusHeight = statusMessage.empty() ? 0 : renderer.getLineHeight(SMALL_FONT_ID) + metrics.verticalSpacing;
  const int paginationHeight = (pageHistory.pageIndex() > 0 || hasOlderItems) ? metrics.buttonHintsHeight + metrics.verticalSpacing : 0;
  contentHeight = renderer.getScreenHeight() - contentTop - metrics.buttonHintsHeight - metrics.verticalSpacing -
                  statusHeight - paginationHeight;
}

void InboxActivity::startSync() {
  state = State::SYNCING;
  syncStarted = false;
  statusMessage = "Connecting...";
  requestUpdate();
}

void InboxActivity::runSync() {
  if (!XtinctFeedClient::connectSavedWifi()) {
    syncResult = XtinctSyncClient::SyncResult::NO_WIFI;
  } else {
    if (halClock.isAvailable() && halClock.syncFromNTP()) {
      SETTINGS.clockHasBeenSynced = 1;
      SETTINGS.saveToFile();
    }
    auto client = makeUniqueNoThrow<XtinctSyncClient>();
    syncResult = client ? client->sync() : XtinctSyncClient::SyncResult::NETWORK_ERROR;
  }
  XtinctFeedClient::disconnectWifi();
  statusMessage = XtinctSyncClient::resultMessage(syncResult);
  resetPaging();
  loadItems();
  state = State::READY;
  view = itemCount > 0 ? View::PREVIEW : View::LIST;
  if (itemCount > 0) loadSelectedPreview();
  requestUpdate();
}

void InboxActivity::openSelected() {
  if (itemCount == 0 || selectorIndex < 0 || selectorIndex >= static_cast<int>(itemCount)) return;
  view = View::PREVIEW;
  statusMessage.clear();
  loadSelectedPreview();
  requestUpdate();
}

const char* InboxActivity::selectedKindLabel() const {
  if (itemCount == 0 || selectorIndex < 0 || selectorIndex >= static_cast<int>(itemCount)) return "item";
  using xtinct::sync_v2::Kind;
  switch (items[selectorIndex].kind) {
    case Kind::Card:
      return "card";
    case Kind::Text:
      return "article";
    case Kind::Image1Bit:
      return "image";
    case Kind::Epub:
      return "EPUB";
    case Kind::Action:
      return "action";
    case Kind::SleepScreen:
      return "sleep screen";
    default:
      return "item";
  }
}

void InboxActivity::loadSelectedPreview() {
  previewDigest = {};
  previewDate[0] = '\0';
  if (itemCount == 0 || selectorIndex < 0 || selectorIndex >= static_cast<int>(itemCount)) return;

  const XtinctInboxItem& selected = items[selectorIndex];
  if (!xtinct::formatGeneratedDate(selected.createdAt, previewDate, sizeof(previewDate))) {
    std::snprintf(previewDate, sizeof(previewDate), "%.10s", selected.createdAt);
  }
  char artifactPath[160];
  if (!XtinctSyncClient::artifactPath(selected, artifactPath, sizeof(artifactPath)) ||
      !Storage.exists(artifactPath)) {
    statusMessage = "File missing - sync again";
    std::snprintf(previewDigest.summary, sizeof(previewDigest.summary),
                  "This item is not available locally. Open Actions and choose Sync now.");
    return;
  }

  using xtinct::sync_v2::Kind;
  const bool textual = selected.kind == Kind::Card || selected.kind == Kind::Text || selected.kind == Kind::Action;
  bool extracted = xtinct::inbox_digest_contract::isPresent(selected.digest);
  if (extracted) previewDigest = selected.digest;
  if (!extracted && textual) {
    HalFile file;
    if (Storage.openFileForRead("XDIGEST", artifactPath, file)) {
      xtinct::inbox_digest::StreamExtractor extractor(selected.title);
      uint64_t remaining = std::min<uint64_t>(file.fileSize64(), xtinct::inbox_digest::MAX_SCAN_BYTES);
      char source[xtinct::inbox_digest::STREAM_CHUNK_BYTES];
      bool readOk = remaining > 0;
      while (remaining > 0 && !extractor.complete()) {
        const size_t wanted = static_cast<size_t>(
            std::min<uint64_t>(remaining, xtinct::inbox_digest::STREAM_CHUNK_BYTES));
        const int amount = file.read(source, wanted);
        if (amount != static_cast<int>(wanted)) {
          readOk = false;
          break;
        }
        extractor.feed(source, wanted);
        remaining -= wanted;
      }
      file.close();
      if (readOk) extracted = extractor.finish(previewDigest);
    }
  }

  if (!extracted) {
    const char* fallback = "This verified item is ready to open offline.";
    if (selected.kind == Kind::Epub) fallback = "This edition is ready to read offline.";
    else if (selected.kind == Kind::Image1Bit || selected.kind == Kind::SleepScreen) {
      fallback = "This image is ready to view offline.";
    } else if (textual) {
      fallback = "No short preview is available. Open the item for the complete content.";
    }
    std::snprintf(previewDigest.summary, sizeof(previewDigest.summary), "%s", fallback);
  }
}

void InboxActivity::showNextPreview() {
  if (itemCount == 0) return;
  statusMessage.clear();
  if (selectorIndex + 1 < static_cast<int>(itemCount)) {
    ++selectorIndex;
  } else if (hasOlderItems) {
    showNextPage();
    return;
  } else {
    resetPaging();
    loadItems();
  }
  if (itemCount > 0) {
    view = View::PREVIEW;
    loadSelectedPreview();
  }
  requestUpdate();
}

void InboxActivity::openFullSelected() {
  if (itemCount == 0 || selectorIndex < 0 || selectorIndex >= static_cast<int>(itemCount)) return;
  const XtinctInboxItem selected = items[selectorIndex];
  char path[160];
  if (!XtinctSyncClient::artifactPath(selected, path, sizeof(path)) || !Storage.exists(path)) {
    statusMessage = "File missing - sync again";
    requestUpdate();
    return;
  }
  // "opened" is telemetry, not permission to read an already verified local
  // artifact. A successfully queued receipt is retried by the ordinary outbox;
  // an unavailable/full outbox is logged without blocking EPUB, text or image.
  XtinctSyncClient::recordOpenedBestEffort(selected);
  if (selected.kind == xtinct::sync_v2::Kind::Epub) {
    activityManager.goToReader(path);
    return;
  }
  if (selected.kind == xtinct::sync_v2::Kind::Image1Bit ||
      selected.kind == xtinct::sync_v2::Kind::SleepScreen) {
    startActivityForResult(std::make_unique<BmpViewerActivity>(renderer, mappedInput, path, /*returnToCaller=*/true),
                           [this](const ActivityResult&) { requestUpdate(); });
    return;
  }
  sdFontSystem.ensureLoaded(renderer);
  auto document = makeUniqueNoThrow<Txt>(path, "/.crosspoint");
  if (!document || !document->load()) {
    statusMessage = "Could not open item";
    requestUpdate();
    return;
  }
  auto reader = makeUniqueNoThrow<TxtReaderActivity>(renderer, mappedInput, std::move(document), 0,
                                                      /*transientDocument=*/true, std::string(selected.title));
  if (!reader) {
    statusMessage = "Out of memory";
    requestUpdate();
    return;
  }
  startActivityForResult(std::move(reader), [this](const ActivityResult&) { requestUpdate(); });
}

void InboxActivity::showActions() {
  actionNames.clear();
  actionCodes.clear();
  actionNames.emplace_back(tr(STR_SYNC_NOW));
  actionCodes.emplace_back("sync");
  if (view == View::PREVIEW && itemCount > 0) {
    actionNames.emplace_back("Browse list");
    actionCodes.emplace_back("browse-list");
  }
  // X3/X4 profiles have no touch controller. Keep page navigation in the
  // hardware-accessible Actions popup; the rendered tap targets below remain
  // an optional convenience for touch-capable sibling boards.
  if (pageHistory.pageIndex() > 0) {
    actionNames.emplace_back(tr(STR_PREV_PAGE));
    actionCodes.emplace_back("page-previous");
  }
  if (hasOlderItems) {
    actionNames.emplace_back(tr(STR_NEXT_PAGE));
    actionCodes.emplace_back("page-next");
  }
  if (itemCount > 0) {
    const auto& selected = items[selectorIndex];
    if (selected.actions & XTINCT_ACTION_KEEP) {
      actionNames.emplace_back(tr(STR_KEEP));
      actionCodes.emplace_back("keep");
    }
    if (selected.actions & XTINCT_ACTION_ARCHIVE) {
      actionNames.emplace_back(tr(STR_ARCHIVE));
      actionCodes.emplace_back("archive");
    }
    if (selected.actions & XTINCT_ACTION_DONE) {
      actionNames.emplace_back(tr(STR_DONE));
      actionCodes.emplace_back("done");
    }
    if (selected.actions & XTINCT_ACTION_DEFER) {
      actionNames.emplace_back(tr(STR_DEFER));
      actionCodes.emplace_back("defer");
    }
    if (selected.actions & XTINCT_ACTION_LIKE) {
      actionNames.emplace_back(tr(STR_LIKE));
      actionCodes.emplace_back("like");
    }
    if (selected.actions & XTINCT_ACTION_DISLIKE) {
      actionNames.emplace_back(tr(STR_DISLIKE));
      actionCodes.emplace_back("dislike");
    }
    if (selected.actions & XTINCT_ACTION_OPEN_PHONE) {
      actionNames.emplace_back(tr(STR_OPEN_ON_PHONE));
      actionCodes.emplace_back("open-phone");
    }
    // Delete is a device-local Inbox operation for every delivered v2 item,
    // independent of the publisher-provided action list. Its cloud receipt is
    // best effort: a full/unreadable outbox must not trap an item on the X3.
    actionNames.emplace_back(tr(STR_DELETE));
    actionCodes.emplace_back("delete");
  }
  std::vector<const char*> actionPointers;
  actionPointers.reserve(actionNames.size());
  for (const auto& name : actionNames) actionPointers.push_back(name.c_str());
  actionPopup.show("XTINCT actions", actionPointers.data(), static_cast<int>(actionPointers.size()), 0,
                   [this](const int index) {
    if (index >= 0 && index < static_cast<int>(actionCodes.size())) applyAction(actionCodes[index]);
  });
  requestUpdate();
}

void InboxActivity::applyAction(const std::string& action) {
  if (action == "sync") {
    startSync();
    return;
  }
  if (action == "page-previous") {
    showPreviousPage();
    return;
  }
  if (action == "page-next") {
    showNextPage();
    return;
  }
  if (action == "browse-list") {
    view = View::LIST;
    statusMessage.clear();
    requestUpdate();
    return;
  }
  if (itemCount == 0 || selectorIndex < 0 || selectorIndex >= static_cast<int>(itemCount)) return;
  const XtinctInboxItem selected = items[selectorIndex];
  const bool receiptQueued = XtinctSyncClient::recordAction(selected, action.c_str());
  if (action != "delete" && !receiptQueued) {
    statusMessage = "Could not save action";
    requestUpdate();
    return;
  }
  if (action == "archive" || action == "done" || action == "delete" || action == "like" || action == "dislike") {
    if (!XtinctSyncClient::removeFromInbox(selected)) {
      statusMessage = receiptQueued ? "Action saved; local remove failed" : "Could not delete locally";
    } else if (action == "done") statusMessage = "Done - sync receipt queued";
    else if (action == "delete" && receiptQueued) statusMessage = "Deleted - sync receipt queued";
    else if (action == "delete") {
      LOG_ERR("XSYNC", "Deleted locally without cloud receipt for %.32s", selected.itemId);
      statusMessage = "Deleted locally - receipt unavailable";
    } else if (action == "like") statusMessage = "Liked - sync receipt queued";
    else if (action == "dislike") statusMessage = "Disliked - sync receipt queued";
    else statusMessage = "Archived - sync receipt queued";
  } else if (action == "keep") {
    if (!XtinctSyncClient::updateInboxState(selected, "kept")) statusMessage = "Action saved; state update failed";
    else statusMessage = "Kept - sync receipt queued";
  } else if (action == "defer") {
    if (!XtinctSyncClient::updateInboxState(selected, "deferred")) statusMessage = "Action saved; state update failed";
    else statusMessage = "Deferred one day";
  } else if (action == "open-phone") {
    statusMessage = "Phone-open request queued";
  }
  resetPaging();
  loadItems();
  if (view == View::PREVIEW && itemCount > 0) loadSelectedPreview();
  if (itemCount == 0) view = View::LIST;
  requestUpdate();
}

void InboxActivity::loop() {
  if (state == State::SYNCING && !syncStarted) {
    syncStarted = true;
    if (!requestUpdateAndWait()) {
      // Do not start Wi-Fi/TLS while an unconfirmed E-Ink render may still own
      // the framebuffer, font cache or SD card. Existing verified Inbox items
      // remain usable and the user can retry from Actions.
      LOG_ERR("XSYNC", "Inbox refresh cancelled: busy screen was not confirmed");
      syncResult = XtinctSyncClient::SyncResult::NETWORK_ERROR;
      statusMessage = "Refresh cancelled: display busy";
      state = State::READY;
      requestUpdate();
      return;
    }
    runSync();
    return;
  }
  if (actionPopup.handleInput(mappedInput, [this] { requestUpdate(); })) return;
  if (state == State::READY && view == View::PREVIEW && itemCount > 0) {
    if (mappedInput.wasPressed(MappedInputManager::Button::Back)) {
      onGoHome(HomeMenuItem::XTINCT_INBOX);
      return;
    }
    // Open the popup on release. Opening it on press lets the same physical
    // button cycle reach OptionPopup as a release and immediately activate
    // its first entry (Sync now) before the user can choose an action.
    if (mappedInput.wasReleased(MappedInputManager::Button::Confirm)) {
      showActions();
      return;
    }
    if (mappedInput.wasPressed(MappedInputManager::Button::Left) ||
        mappedInput.wasPressed(MappedInputManager::Button::Up)) {
      openFullSelected();
      return;
    }
    if (mappedInput.wasPressed(MappedInputManager::Button::Right) ||
        mappedInput.wasPressed(MappedInputManager::Button::Down)) {
      showNextPreview();
      return;
    }
    return;
  }
  if (state == State::READY && itemCount > 0) {
    int contentTop = 0;
    int contentHeight = 0;
    listBounds(contentTop, contentHeight);

    // Check pagination tap
    if (pageHistory.pageIndex() > 0 || hasOlderItems) {
      const int paginationY = contentTop + contentHeight;
      const int buttonWidth = mappedInput.getRenderer().getScreenWidth() / 2;
      const int buttonHeight = UITheme::getInstance().getMetrics().buttonHintsHeight;
      
      if (pageHistory.pageIndex() > 0 && mappedInput.wasTapInRect(0, paginationY, buttonWidth, buttonHeight)) {
        showPreviousPage();
        return;
      }
      if (hasOlderItems && mappedInput.wasTapInRect(buttonWidth, paginationY, buttonWidth, buttonHeight)) {
        showNextPage();
        return;
      }
    }

    int touchedIndex = selectorIndex;
    const auto touch = handleListTouch(touchedIndex, static_cast<int>(itemCount), contentTop, contentHeight, true);
    if (touch != ListTouchResult::None) {
      selectorIndex = touchedIndex;
      if (touch == ListTouchResult::Activated) openSelected();
      return;
    }
  }
  if (mappedInput.wasReleased(MappedInputManager::Button::Back)) {
    if (view == View::LIST && itemCount > 0) {
      openSelected();
    } else {
      onGoHome(HomeMenuItem::XTINCT_INBOX);
    }
    return;
  }
  if (mappedInput.wasReleased(MappedInputManager::Button::Confirm)) {
    openSelected();
    return;
  }
  if (mappedInput.wasReleased(MappedInputManager::Button::Left) ||
      mappedInput.wasReleased(MappedInputManager::Button::Up)) {
    showActions();
    return;
  }
  const int count = static_cast<int>(itemCount);
  buttonNavigator.onNextRelease([this, count] {
    selectorIndex = ButtonNavigator::nextIndex(selectorIndex, count);
    requestUpdate();
  });
  buttonNavigator.onPreviousRelease([this, count] {
    selectorIndex = ButtonNavigator::previousIndex(selectorIndex, count);
    requestUpdate();
  });
}

void InboxActivity::renderPreview() const {
  const auto& metrics = UITheme::getInstance().getMetrics();
  const int width = renderer.getScreenWidth();
  const int height = renderer.getScreenHeight();
  const int margin = metrics.contentSidePadding;
  const int contentWidth = width - margin * 2;
  const XtinctInboxItem& selected = items[selectorIndex];

  const std::string title = renderer.truncatedText(UI_12_FONT_ID, selected.title, contentWidth);
  GUI.drawHeader(renderer, Rect{0, metrics.topPadding, width, metrics.headerHeight}, title.c_str());

  const size_t firstVisible = pageHistory.pageIndex() * VISIBLE_ITEM_LIMIT;
  const size_t absolutePosition = firstVisible + static_cast<size_t>(selectorIndex) + 1;
  const size_t knownTotal = firstVisible + itemCount;
  char visibleTotal[12];
  if (hasOlderItems) std::snprintf(visibleTotal, sizeof(visibleTotal), "%u+", static_cast<unsigned>(knownTotal));
  else std::snprintf(visibleTotal, sizeof(visibleTotal), "%u", static_cast<unsigned>(knownTotal));
  char position[160];
  std::snprintf(position, sizeof(position), "%u/%s  %s  %s", static_cast<unsigned>(absolutePosition),
                visibleTotal, selected.moduleId, selectedKindLabel());
  const std::string clippedPosition = renderer.truncatedText(SMALL_FONT_ID, position, contentWidth);
  GUI.drawSubHeader(renderer, Rect{0, metrics.topPadding + metrics.headerHeight, width, metrics.tabBarHeight},
                    clippedPosition.c_str());

  int y = metrics.topPadding + metrics.headerHeight + metrics.tabBarHeight + metrics.verticalSpacing;
  char updatedLine[64];
  std::snprintf(updatedLine, sizeof(updatedLine), "Updated %s", previewDate[0] ? previewDate : "date unavailable");
  const std::string updated = renderer.truncatedText(SMALL_FONT_ID, updatedLine, contentWidth);
  renderer.drawText(SMALL_FONT_ID, margin, y, updated.c_str());
  y += renderer.getLineHeight(SMALL_FONT_ID) + metrics.verticalSpacing;

  const int summaryHeight = renderer.getLineHeight(UI_10_FONT_ID) * 3;
  UITheme::drawCenteredWrappedText(renderer, Rect{margin, y, contentWidth, summaryHeight}, UI_10_FONT_ID,
                                   previewDigest.summary, 3, true, EpdFontFamily::BOLD,
                                   UITheme::TextVerticalAlignment::TOP);
  y += summaryHeight + metrics.verticalSpacing * 2;

  if (previewDigest.pointCount > 0) {
    renderer.drawText(UI_10_FONT_ID, margin, y, "KEY POINTS", true, EpdFontFamily::BOLD);
    y += renderer.getLineHeight(UI_10_FONT_ID) + 2;
    const int bottom = height - metrics.buttonHintsHeight - metrics.verticalSpacing;
    for (uint8_t index = 0; index < previewDigest.pointCount && y < bottom; ++index) {
      char bullet[xtinct::inbox_digest::MAX_POINT_BYTES + 4];
      std::snprintf(bullet, sizeof(bullet), "- %s", previewDigest.points[index]);
      const std::string line = renderer.truncatedText(SMALL_FONT_ID, bullet, contentWidth);
      renderer.drawText(SMALL_FONT_ID, margin, y, line.c_str());
      y += renderer.getLineHeight(SMALL_FONT_ID) + 2;
    }
  }

  if (!statusMessage.empty()) {
    const std::string status = renderer.truncatedText(SMALL_FONT_ID, statusMessage.c_str(), contentWidth);
    renderer.drawText(SMALL_FONT_ID, margin, height - metrics.buttonHintsHeight -
                      renderer.getLineHeight(SMALL_FONT_ID) - metrics.verticalSpacing, status.c_str());
  }
  const auto labels = mappedInput.mapLabels("Back", "Actions", "Open", itemCount > 1 || hasOlderItems ? "Next" : "");
  GUI.drawButtonHints(renderer, labels.btn1, labels.btn2, labels.btn3, labels.btn4);
}

void InboxActivity::render(RenderLock&&) {
  renderer.clearScreen();
  const auto& metrics = UITheme::getInstance().getMetrics();
  const int width = renderer.getScreenWidth();
  if (state == State::READY && view == View::PREVIEW && itemCount > 0) {
    renderPreview();
    if (actionPopup.processRender(renderer, mappedInput)) return;
    renderer.displayBuffer();
    return;
  }
  char header[40];
  std::snprintf(header, sizeof(header), "XTINCT Inbox · %u", static_cast<unsigned>(pageHistory.pageIndex() + 1));
  GUI.drawHeader(renderer, Rect{0, metrics.topPadding, width, metrics.headerHeight}, header);
  int contentTop = 0;
  int contentHeight = 0;
  listBounds(contentTop, contentHeight);
  if (state == State::SYNCING) {
    UITheme::drawCenteredWrappedText(renderer, Rect{metrics.contentSidePadding, contentTop,
                                                    width - metrics.contentSidePadding * 2, contentHeight},
                                     UI_12_FONT_ID, "Syncing XTINCT...", 2, true, EpdFontFamily::BOLD);
  } else if (itemCount == 0) {
    UITheme::drawCenteredWrappedText(renderer, Rect{metrics.contentSidePadding, contentTop,
                                                    width - metrics.contentSidePadding * 2, contentHeight},
                                     UI_10_FONT_ID, "Inbox empty. Open Actions and choose Sync now.", 4, true);
  } else {
    GUI.drawList(
        renderer, Rect{0, contentTop, width, contentHeight}, static_cast<int>(itemCount), selectorIndex,
        [this](const int index) { return std::string(items[index].title); },
        [this](const int index) {
          char subtitle[96];
          std::snprintf(subtitle, sizeof(subtitle), "%s · %s · %s", items[index].moduleId,
                        xtinct::sync_v2::kindName(items[index].kind), items[index].state);
          return std::string(subtitle);
        },
        [this](const int index) {
          char path[160];
          XtinctSyncClient::artifactPath(items[index], path, sizeof(path));
          return UITheme::getFileIcon(path);
        });
  }
  
  if (pageHistory.pageIndex() > 0 || hasOlderItems) {
    const int paginationY = contentTop + contentHeight;
    const int buttonWidth = width / 2;
    const int buttonHeight = metrics.buttonHintsHeight;
    
    if (pageHistory.pageIndex() > 0) {
      renderer.drawRect(0, paginationY, buttonWidth, buttonHeight);
      UITheme::drawCenteredText(renderer, Rect{0, paginationY, buttonWidth, buttonHeight}, SMALL_FONT_ID, paginationY + 12, tr(STR_PREV_PAGE));
    }
    if (hasOlderItems) {
      renderer.drawRect(buttonWidth, paginationY, buttonWidth, buttonHeight);
      UITheme::drawCenteredText(renderer, Rect{buttonWidth, paginationY, buttonWidth, buttonHeight}, SMALL_FONT_ID, paginationY + 12, tr(STR_NEXT_PAGE));
    }
  }
  if (!statusMessage.empty()) {
    const int paginationHeight =
        (pageHistory.pageIndex() > 0 || hasOlderItems) ? metrics.buttonHintsHeight + metrics.verticalSpacing : 0;
    const std::string status = renderer.truncatedText(SMALL_FONT_ID, statusMessage.c_str(),
                                                      width - metrics.contentSidePadding * 2);
    renderer.drawText(SMALL_FONT_ID, metrics.contentSidePadding,
                      contentTop + contentHeight + paginationHeight, status.c_str());
  }
  const auto labels = mappedInput.mapLabels("Home", itemCount > 0 ? "Open" : "", "Actions", "Next");
  GUI.drawButtonHints(renderer, labels.btn1, labels.btn2, labels.btn3, labels.btn4);
  if (actionPopup.processRender(renderer, mappedInput)) return;
  renderer.displayBuffer();
}
