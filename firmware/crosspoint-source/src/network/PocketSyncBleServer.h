#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>

#include "util/PocketSyncContract.h"

class PocketSyncBleServer final {
 public:
  enum class UiStage : uint8_t {
    Stopped,
    Advertising,
    Pairing,
    Secured,
    Gathering,
    Receiving,
    Validating,
    Committing,
    Complete,
    Failed,
  };

  struct Snapshot {
    UiStage stage = UiStage::Stopped;
    xtinct::pocket_sync::Phase phase = xtinct::pocket_sync::Phase::Idle;
    xtinct::pocket_sync::Result result = xtinct::pocket_sync::Result::Ok;
    uint8_t stream = xtinct::pocket_sync::MANIFEST_STREAM;
    uint8_t negotiatedChunk = 0;
    uint32_t durableOffset = 0;
    uint32_t statusSequence = 0;
    uint32_t freeHeap = 0;
    uint32_t minimumFreeHeap = 0;
    uint32_t phoneSyncLoopStackFreeBytes = 0;
    bool configured = false;
    bool connected = false;
    bool authenticated = false;
    bool enrollmentOpen = false;
  };

  PocketSyncBleServer();
  ~PocketSyncBleServer();
  PocketSyncBleServer(const PocketSyncBleServer&) = delete;
  PocketSyncBleServer& operator=(const PocketSyncBleServer&) = delete;

  bool begin();
  void loop();
  void end();
  bool resetPairing();

  uint32_t passkey() const;
  uint32_t uiGeneration() const;
  Snapshot snapshot() const;
  size_t persistentBytes() const;

 private:
  class Impl;
  std::unique_ptr<Impl> impl;
};
