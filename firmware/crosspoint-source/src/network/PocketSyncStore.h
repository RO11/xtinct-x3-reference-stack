#pragma once

#include <HalStorage.h>

#include <cstddef>
#include <cstdint>

#include "util/PocketSyncContract.h"
#include "util/XtinctSyncContract.h"

class PocketSyncStore {
 public:
  struct Status {
    xtinct::pocket_sync::Phase phase = xtinct::pocket_sync::Phase::Idle;
    xtinct::pocket_sync::Result result = xtinct::pocket_sync::Result::Ok;
    uint8_t stream = xtinct::pocket_sync::MANIFEST_STREAM;
    uint8_t negotiatedChunk = 0;
    uint32_t durableOffset = 0;
    uint32_t sequence = 0;
    uint8_t packPrefix[4] = {0};
  };

  PocketSyncStore();
  ~PocketSyncStore();

  xtinct::pocket_sync::Result start(const uint8_t packDigest[32], uint32_t manifestBytes,
                                    const uint8_t manifestSha256[32], uint32_t totalObjectBytes,
                                    uint8_t objectCount, uint8_t negotiatedChunk);
  xtinct::pocket_sync::Result write(uint8_t stream, uint32_t offset, const uint8_t* bytes, uint8_t length);
  xtinct::pocket_sync::Result sealManifest();
  xtinct::pocket_sync::Result commit();
  void abort();
  void fail(xtinct::pocket_sync::Result result, uint8_t stream);

  const Status& status() const { return currentStatus; }
  bool active() const { return sessionActive; }
  bool manifestSealed() const { return sealed; }
  bool complete() const { return currentStatus.phase == xtinct::pocket_sync::Phase::Complete; }

  static bool recoverPendingCommit();
  static bool queryLocalState(uint8_t& revisionMask, char revisions[4][33], uint64_t& v2Cursor,
                              uint8_t lastPackDigest[32]);

 private:
  enum class ObjectSource : uint8_t { Invalid, V1Report, V2Artifact };

  struct ObjectDescriptor {
    ObjectSource source = ObjectSource::Invalid;
    xtinct::sync_v2::Kind kind = xtinct::sync_v2::Kind::Invalid;
    uint8_t index = 0;
    uint8_t references = 0;
    uint32_t bytes = 0;
    char moduleId[33] = {0};
    char revision[65] = {0};
    char sha256[65] = {0};
    char mime[64] = {0};
    char taskId[33] = {0};
  };

  struct ManifestState {
    char packId[69] = {0};
    char v1Status[11] = {0};
    char v2Status[11] = {0};
    char v2Mode[9] = {0};
    uint64_t fromCursor = 0;
    uint64_t toCursor = 0;
    uint8_t objectCount = 0;
    uint32_t totalBytes = 0;
  };

  Status currentStatus;
  ManifestState manifest;
  HalFile streamFile;
  bool sessionActive = false;
  bool sealed = false;
  uint8_t packDigest[32] = {0};
  uint8_t manifestDigest[32] = {0};
  uint32_t expectedManifestBytes = 0;
  uint32_t expectedObjectBytes = 0;
  uint8_t expectedObjectCount = 0;
  char packHex[65] = {0};
  char packRoot[160] = {0};
  uint8_t openStream = 0xfe;
  uint32_t acceptedOffset = 0;
  uint8_t chunksSinceStatus = 0;

  void setStatus(xtinct::pocket_sync::Phase phase, xtinct::pocket_sync::Result result,
                 uint8_t stream, uint32_t offset);
  void recordFailure(const char* site, xtinct::pocket_sync::Result result,
                     uint8_t stream, uint32_t offset) const;
  void closeStream();
  bool ensureBaseDirectories() const;
  bool streamPath(uint8_t stream, char* path, size_t pathSize) const;
  bool markerPath(uint8_t stream, char* path, size_t pathSize) const;
  bool offsetPath(uint8_t stream, char* path, size_t pathSize) const;
  bool readDurableOffset(uint8_t stream, uint32_t& offset) const;
  bool writeDurableOffset(uint8_t stream, uint32_t offset) const;
  bool discardStreamForRetry(uint8_t stream);
  bool prepareStreamForResume(uint8_t stream, uint32_t& offset);
  bool selectNextObjectForResume(uint8_t firstStream, uint8_t& nextStream, uint32_t& offset);
  bool openStreamAt(uint8_t stream, uint32_t offset);
  uint32_t expectedBytesFor(uint8_t stream) const;
  bool validateCompletedObject(uint8_t stream);
  bool allObjectsComplete();
  bool readObjectDescriptor(uint8_t index, ObjectDescriptor& descriptor) const;
  bool writeObjectDescriptor(const ObjectDescriptor& descriptor) const;
  bool parseAndPrepareManifest();
  bool buildCommitPlan();
  bool runCommitPlan();
  bool writeSessionRecord() const;
  bool readAndValidateSessionRecord() const;
  bool isCompletedReplay() const;
};

// The manifest/object index belongs on SD. Keep the live transactional store
// small enough to coexist with NimBLE at the X3's measured low-heap floor.
static_assert(sizeof(PocketSyncStore) <= 1536, "Pocket Sync store exceeded its persistent RAM budget");
