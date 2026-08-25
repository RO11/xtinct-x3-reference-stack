#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "activities/Activity.h"
#include "components/OptionPopup.h"
#include "network/XtinctSyncClient.h"
#include "util/ButtonNavigator.h"
#include "util/InboxDigestText.h"
#include "util/InboxNewestSelection.h"

class InboxActivity final : public Activity {
 public:
  explicit InboxActivity(GfxRenderer& renderer, MappedInputManager& mappedInput)
      : Activity("XtinctInbox", renderer, mappedInput) {}

  void onEnter() override;
  void onExit() override;
  void loop() override;
  void render(RenderLock&&) override;
  bool preventAutoSleep() override { return state == State::SYNCING; }
  bool skipLoopDelay() override { return state == State::SYNCING; }

 private:
  static constexpr size_t VISIBLE_ITEM_LIMIT = 8;
  static constexpr size_t MAX_PAGES =
      (xtinct::sync_v2::MAX_INBOX_ITEMS + VISIBLE_ITEM_LIMIT - 1) / VISIBLE_ITEM_LIMIT;
  static_assert(MAX_PAGES == 8);
  enum class State : uint8_t { READY, SYNCING };
  enum class View : uint8_t { PREVIEW, LIST };

  struct PageCursor {
    char createdAt[40] = {0};
    char itemId[33] = {0};
  };
  static_assert(sizeof(PageCursor) * MAX_PAGES <= 600, "Inbox page history exceeded its RAM budget");

  State state = State::READY;
  View view = View::PREVIEW;
  XtinctInboxItem items[VISIBLE_ITEM_LIMIT];
  size_t itemCount = 0;
  int selectorIndex = 0;
  bool hasOlderItems = false;
  xtinct::inbox_selection::BoundedPageHistory<PageCursor, MAX_PAGES> pageHistory;
  bool syncStarted = false;
  XtinctSyncClient::SyncResult syncResult = XtinctSyncClient::SyncResult::CURRENT;
  std::string statusMessage;
  ButtonNavigator buttonNavigator;
  OptionPopup actionPopup;
  std::vector<std::string> actionNames;
  std::vector<std::string> actionCodes;
  xtinct::inbox_digest::DigestText previewDigest;
  char previewDate[32] = {0};

  void loadItems();
  void resetPaging();
  void showPreviousPage();
  void showNextPage();
  void listBounds(int& contentTop, int& contentHeight) const;
  void startSync();
  void runSync();
  void openSelected();
  void openFullSelected();
  void showNextPreview();
  void loadSelectedPreview();
  const char* selectedKindLabel() const;
  void renderPreview() const;
  void showActions();
  void applyAction(const std::string& action);
};
