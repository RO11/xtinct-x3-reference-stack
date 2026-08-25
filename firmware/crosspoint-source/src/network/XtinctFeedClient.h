#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace freeink {
class SecureHttpClient;
}

enum class XtinctCardState : uint8_t { OK, EMPTY, ATTENTION, ERROR };

struct XtinctCardMetric {
  char label[41] = {0};
  char value[81] = {0};
  char tone[8] = {0};
};

struct XtinctCardSection {
  char heading[49] = {0};
  uint8_t lineCount = 0;
  char lines[4][241] = {{0}};
};

struct XtinctDailyCard {
  char taskId[33] = {0};
  char revision[129] = {0};
  char generatedAt[40] = {0};
  char title[81] = {0};
  char summary[321] = {0};
  uint8_t priority = 0;
  XtinctCardState state = XtinctCardState::OK;
  uint8_t metricCount = 0;
  XtinctCardMetric metrics[4];
  uint8_t sectionCount = 0;
  XtinctCardSection sections[3];
  // Full reports stay on SD and are streamed into the existing TXT reader.
  // Keeping only integrity metadata here avoids adding a 24 KiB body to every
  // in-memory card copy on the constrained X3.
  bool hasReport = false;
  uint32_t reportBytes = 0;
  char reportSha256[65] = {0};
};

class XtinctFeedClient {
 public:
  enum class SyncResult : uint8_t {
    UPDATED,
    NOT_MODIFIED,
    NO_CONFIG,
    NO_WIFI,
    CLOCK_ERROR,
    UNAUTHORIZED,
    NETWORK_ERROR,
    INVALID_DATA,
    STORAGE_ERROR,
  };

  SyncResult sync();

  // Connects to a bounded set of saved networks without presenting a UI.
  // Passwords never leave WifiCredentialStore and are not logged.
  static bool connectSavedWifi();
  static void disconnectWifi();

  static size_t cachedCardCount();
  static bool loadCachedCard(size_t availableIndex, XtinctDailyCard& out);
  static bool loadBestCachedCard(XtinctDailyCard& out, size_t& availableIndex);
  static bool cachedReportPath(const XtinctDailyCard& card, char* path, size_t pathSize);
  static const char* resultMessageKey(SyncResult result);

  // Pocket Sync imports exact cloud semantics through the same validators and
  // cache naming rules as HTTPS V1. These helpers never accept an SD path from
  // the phone; callers receive destinations derived from the fixed task/revision
  // allow-list only.
  static bool validatePocketCardJson(const char* expectedTaskId, const char* expectedRevision,
                                     const std::string& body, XtinctDailyCard* parsedCard = nullptr);
  static bool validatePocketCardFile(const char* expectedTaskId, const char* expectedRevision,
                                     const char* stagedPath, XtinctDailyCard* parsedCard = nullptr);
  static bool validatePocketReportFile(const XtinctDailyCard& card, const char* stagedPath);
  static bool pocketCardFinalPath(const char* taskId, char* path, size_t pathSize);
  static bool pocketReportFinalPath(const char* taskId, const char* revision, char* path, size_t pathSize);
  static const char* pocketManifestFinalPath();
  static const char* pocketManifestEtagFinalPath();
  static uint8_t pocketCachedRevisionMask(char revisions[4][33]);

 private:
  static constexpr size_t TASK_COUNT = 4;

  struct RemoteCardRef {
    char id[33] = {0};
    char revision[129] = {0};
    char url[128] = {0};
  };

  struct CachedRevision {
    char id[33] = {0};
    char revision[129] = {0};
  };

  struct V1TransactionPlan {
    char targetEtag[96] = {0};
    char targetManifestSha256[65] = {0};
    char previousManifestSha256[65] = {0};
    char targetRevisions[TASK_COUNT][33] = {{0}};
    char targetCardSha256[TASK_COUNT][65] = {{0}};
    char previousCardSha256[TASK_COUNT][65] = {{0}};
    uint8_t remoteMask = 0;
    uint8_t changedMask = 0;
    uint8_t previousCardMask = 0;
    bool previousManifestExisted = false;
  };

  RemoteCardRef remoteCards[TASK_COUNT];
  CachedRevision cachedRevisions[TASK_COUNT];
  uint8_t remoteCardCount = 0;
  uint8_t cachedRevisionCount = 0;

  void loadCachedRevisions();
  bool parseManifest(const char* body, size_t bodyLength, char* bodyEtag, size_t bodyEtagSize);
  bool validateCachedManifestAndCards(const char* expectedManifestEtag);
  SyncResult downloadAndStageChangedCards(V1TransactionPlan& plan);
  bool promoteStagedCards(const V1TransactionPlan& plan);
  static bool validateTargetCards(const V1TransactionPlan& plan);
  static bool recoverPendingTransaction();
  static bool readTransactionPlan(V1TransactionPlan& plan);
  static bool writeTransactionPlan(const V1TransactionPlan& plan);
  static bool finishCommittedTransaction(const V1TransactionPlan& plan);
  static bool rollBackTransaction(const V1TransactionPlan& plan);
  static bool sweepReportCache();
  static bool validateCachedReport(const XtinctDailyCard& card);
  static SyncResult downloadAndCacheReport(freeink::SecureHttpClient& http, const std::string& baseUrl,
                                           const std::string& token, const XtinctDailyCard& card,
                                           bool& promotedReport);

  static bool parseCard(const char* expectedTaskId, const char* expectedRevision, const char* body,
                        size_t bodyLength,
                        XtinctDailyCard* parsedCard = nullptr);
  static bool loadCardByTaskId(const char* taskId, XtinctDailyCard& out);
  static bool writeAtomic(const char* finalPath, const char* content, size_t contentLength);
  static bool writeAtomic(const char* finalPath, const std::string& content);
  static bool writeAtomic(const char* finalPath, const char* content);
};
