#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "util/InboxDigestContract.h"
#include "util/XtinctSyncContract.h"

enum XtinctInboxAction : uint8_t {
  XTINCT_ACTION_KEEP = 1U << 0,
  XTINCT_ACTION_ARCHIVE = 1U << 1,
  XTINCT_ACTION_DONE = 1U << 2,
  XTINCT_ACTION_DEFER = 1U << 3,
  XTINCT_ACTION_OPEN_PHONE = 1U << 4,
  XTINCT_ACTION_LIKE = 1U << 5,
  XTINCT_ACTION_DISLIKE = 1U << 6,
};

struct XtinctInboxItem {
  char deliveryId[33] = {0};
  char itemId[33] = {0};
  char moduleId[33] = {0};
  xtinct::sync_v2::Kind kind = xtinct::sync_v2::Kind::Invalid;
  char title[121] = {0};
  char revision[65] = {0};
  char sha256[65] = {0};
  uint32_t bytes = 0;
  char mime[64] = {0};
  char createdAt[40] = {0};
  char expiresAt[40] = {0};
  char state[16] = {0};
  uint8_t actions = 0;
  bool activateSleepScreen = false;
  xtinct::inbox_digest_contract::Digest digest;
};

static_assert(sizeof(XtinctInboxItem) == 796, "Inbox item fixed RAM contract changed");

class XtinctSyncClient {
 public:
  enum class SyncResult : uint8_t {
    UPDATED,
    CURRENT,
    CATCH_UP_PENDING,
    NO_CONFIG,
    NO_WIFI,
    UNAUTHORIZED,
    NETWORK_ERROR,
    INVALID_DATA,
    STORAGE_ERROR,
  };

  SyncResult sync();

  static size_t loadInbox(XtinctInboxItem* items, size_t capacity);
  static size_t loadInboxPage(XtinctInboxItem* items, size_t capacity, const char* beforeCreatedAt,
                              const char* beforeItemId, bool& hasOlderItems);
  static bool artifactPath(const XtinctInboxItem& item, char* path, size_t pathSize);
  // Opening an already-verified local artifact must never depend on telemetry
  // storage. When queued, the ordinary outbox retries this receipt on a later
  // sync; when unavailable, the bounded diagnostic is the only side effect.
  static void recordOpenedBestEffort(const XtinctInboxItem& item);
  static bool recordAction(const XtinctInboxItem& item, const char* action);
  static bool removeFromInbox(const XtinctInboxItem& item);
  static bool updateInboxState(const XtinctInboxItem& item, const char* state);
  // Pocket Sync shares this acceleration layer with cloud sync. Invalidation
  // is fail-closed; refresh is best-effort after the durable transaction.
  static bool invalidateInboxFastPage();
  static bool refreshInboxFastPage();
  // True only when the durable cursor is covered by a complete V2 sync marker
  // for the reader's current configured local day. CATCH_UP_PENDING is
  // explicitly incomplete; UPDATED/CURRENT still require this durable marker.
  static bool isInboxSyncCompleteToday();
  static bool queueReaderProgress(const std::string& artifactPath, uint16_t progress, bool bookmark = false,
                                  bool bookmarkRemoved = false);
  static const char* resultMessage(SyncResult result);

  // Pocket Sync uses the exact V2 delivery/artifact validators and cache
  // naming rules. Destination paths are derived from validated IDs/digests;
  // no phone-supplied filesystem path is accepted.
  static bool validatePocketDeliveryJson(const std::string& json, XtinctInboxItem& item);
  static bool validatePocketDeliveryFile(const char* stagedPath, XtinctInboxItem& item);
  static bool validatePocketArtifactFile(const XtinctInboxItem& item, const char* stagedPath);
  static bool writePocketMetadataFile(const XtinctInboxItem& item, const char* destinationPath);
  static bool pocketMetadataFinalPath(const char* itemId, char* path, size_t pathSize);
  static bool pocketArtifactFinalPath(const XtinctInboxItem& item, char* path, size_t pathSize);
  static bool pocketTombstoneMatches(const char* itemId, const char* revision);
  static bool pocketReadCursor(uint64_t& cursor);
  static bool pocketRecoverInboxMetadata();
  static const char* pocketCursorFinalPath();

 private:
  static bool queueEvent(const char* itemId, const char* revision, const char* type, const char* dataJson);
  static bool sendPendingAcks();
  static bool queueDeviceStatus(SyncResult result);
};
