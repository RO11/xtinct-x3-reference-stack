#include "PocketSyncBleServer.h"

#include <Arduino.h>
#include <Logging.h>
#include <NimBLEDevice.h>
#include <Preferences.h>
#include <WiFi.h>
#include <esp_system.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
#include <freertos/task.h>
#include <mbedtls/md.h>

#include <algorithm>
#include <atomic>
#include <cstring>

#include "network/PocketSyncStore.h"

namespace {
using xtinct::pocket_sync::CONTROL_FRAGMENT_HEADER_BYTES;
using xtinct::pocket_sync::DataFrameView;
using xtinct::pocket_sync::MANIFEST_STREAM;
using xtinct::pocket_sync::MAX_CONTROL_FRAGMENTS;
using xtinct::pocket_sync::MAX_CONTROL_MESSAGE_BYTES;
using xtinct::pocket_sync::Opcode;
using xtinct::pocket_sync::Phase;
using xtinct::pocket_sync::Result;
using xtinct::pocket_sync::STATUS_BYTES;
using xtinct::pocket_sync::WINDOW_CHUNKS;

constexpr char DEVICE_NAME[] = "XTINCT X3 Pocket";
constexpr char NVS_NAMESPACE[] = "xtinct_ps";
constexpr char NVS_PAIRING_KEY[] = "pair_v1";
constexpr uint8_t PAIRING_VERSION = 1;
constexpr size_t APP_KEY_BYTES = xtinct::pocket_sync::ENROLL_APP_KEY_BYTES;
constexpr size_t PHONE_ID_BYTES = xtinct::pocket_sync::ENROLL_PHONE_ID_BYTES;
constexpr size_t PEER_ID_BYTES = xtinct::pocket_sync::BONDED_PEER_ID_BYTES;
constexpr size_t PAIRING_BODY_BYTES = 1 + APP_KEY_BYTES + PHONE_ID_BYTES + PEER_ID_BYTES;
constexpr size_t PAIRING_RECORD_BYTES = PAIRING_BODY_BYTES + 4;
constexpr unsigned long ENROLLMENT_WINDOW_MS = 120UL * 1000UL;
constexpr unsigned long CONTROL_ASSEMBLY_TIMEOUT_MS = 5000UL;
// Six seconds tolerates normal phone/watch/headphone radio coexistence without
// making a genuinely lost transfer wait beyond the app's operation timeout.
constexpr uint16_t CONNECTION_SUPERVISION_TIMEOUT_UNITS = 600;
constexpr int16_t INDICATION_IDLE = -32768;
constexpr int16_t INDICATION_WAITING = -32767;

uint32_t crc32(const uint8_t* data, const size_t length) {
  uint32_t crc = 0xffffffffU;
  for (size_t index = 0; index < length; ++index) {
    crc ^= data[index];
    for (uint8_t bit = 0; bit < 8; ++bit) {
      crc = (crc >> 1) ^ (0xedb88320U & static_cast<uint32_t>(-static_cast<int32_t>(crc & 1U)));
    }
  }
  return ~crc;
}

void secureZero(void* value, const size_t length) {
  volatile uint8_t* bytes = static_cast<volatile uint8_t*>(value);
  for (size_t index = 0; index < length; ++index) bytes[index] = 0;
}

bool constantTimeEqual(const uint8_t* left, const uint8_t* right, const size_t length) {
  if (!left || !right) return false;
  uint8_t difference = 0;
  for (size_t index = 0; index < length; ++index) difference |= left[index] ^ right[index];
  return difference == 0;
}

bool hmac16(const uint8_t key[APP_KEY_BYTES], const uint8_t nonce[16], const uint8_t opcode,
            const uint8_t messageId, const uint8_t sequence[4], const uint8_t* payload,
            const size_t payloadLength, uint8_t output[16]) {
  if (!key || !nonce || !sequence || (!payload && payloadLength != 0) || !output) return false;
  const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (!info) return false;
  mbedtls_md_context_t context;
  mbedtls_md_init(&context);
  uint8_t digest[32] = {0};
  const bool ok = mbedtls_md_setup(&context, info, 1) == 0 &&
                  mbedtls_md_hmac_starts(&context, key, APP_KEY_BYTES) == 0 &&
                  mbedtls_md_hmac_update(&context, nonce, 16) == 0 &&
                  mbedtls_md_hmac_update(&context, &opcode, 1) == 0 &&
                  mbedtls_md_hmac_update(&context, &messageId, 1) == 0 &&
                  mbedtls_md_hmac_update(&context, sequence, 4) == 0 &&
                  (payloadLength == 0 || mbedtls_md_hmac_update(&context, payload, payloadLength) == 0) &&
                  mbedtls_md_hmac_finish(&context, digest) == 0;
  if (ok) std::memcpy(output, digest, 16);
  secureZero(digest, sizeof(digest));
  mbedtls_md_free(&context);
  return ok;
}

bool hex32To16(const char* input, uint8_t output[16]) {
  if (!input || std::strlen(input) != 32 || !output) return false;
  auto nibble = [](const char c, uint8_t& value) {
    if (c >= '0' && c <= '9') value = static_cast<uint8_t>(c - '0');
    else if (c >= 'a' && c <= 'f') value = static_cast<uint8_t>(c - 'a' + 10);
    else return false;
    return true;
  };
  for (size_t index = 0; index < 16; ++index) {
    uint8_t high = 0;
    uint8_t low = 0;
    if (!nibble(input[index * 2], high) || !nibble(input[index * 2 + 1], low)) return false;
    output[index] = static_cast<uint8_t>((high << 4) | low);
  }
  return true;
}

bool snapshotUiChanged(const PocketSyncBleServer::Snapshot& left,
                       const PocketSyncBleServer::Snapshot& right) {
  return left.stage != right.stage || left.result != right.result || left.stream != right.stream ||
         left.negotiatedChunk != right.negotiatedChunk || left.configured != right.configured ||
         left.connected != right.connected || left.authenticated != right.authenticated ||
         left.enrollmentOpen != right.enrollmentOpen ||
         left.durableOffset / 65536U != right.durableOffset / 65536U;
}
}  // namespace

class PocketSyncBleServer::Impl final : public NimBLEServerCallbacks,
                                        public NimBLECharacteristicCallbacks {
 public:
  Impl() = default;
  ~Impl() override { stop(); }

  bool start() {
    if (running.load()) return true;
    heapBeforeInit = ESP.getFreeHeap();
    minimumFreeHeap = heapBeforeInit;
    pairingState.store(loadPairing());
    generateSessionSecrets();
    enrollmentDeadline.store(millis() + ENROLLMENT_WINDOW_MS);

    // Pocket Sync is a BLE-only transport.  Keeping Wi-Fi active here competes
    // for the ESP32-C3 radio and lets unrelated network code hold GATT idle.
    if (WiFi.getMode() != WIFI_MODE_NULL) {
      WiFi.disconnect(true, true);
      WiFi.mode(WIFI_OFF);
      delay(30);
    }

    dataQueue = xQueueCreateStatic(WINDOW_CHUNKS, sizeof(DataItem), dataQueueStorage, &dataQueueState);
    if (!dataQueue || !NimBLEDevice::init(DEVICE_NAME)) {
      pairingState.store(PairingState::Corrupt);
      updateSnapshot();
      return false;
    }
    nimbleInitialized = true;
    NimBLEDevice::setMTU(247);
    NimBLEDevice::setSecurityAuth(true, true, true);
    NimBLEDevice::setSecurityIOCap(BLE_HS_IO_DISPLAY_ONLY);
    NimBLEDevice::setSecurityPasskey(displayPasskey.load());

    server = NimBLEDevice::createServer();
    if (!server) return failStart();
    server->setCallbacks(this, false);
    server->advertiseOnDisconnect(false);
    service = server->createService(xtinct::pocket_sync::SERVICE_UUID);
    if (!service) return failStart();

    capabilitiesCharacteristic = service->createCharacteristic(
        xtinct::pocket_sync::CAPABILITIES_UUID, NIMBLE_PROPERTY::READ | NIMBLE_PROPERTY::READ_AUTHEN,
        xtinct::pocket_sync::CAPABILITIES_BYTES);
    controlCharacteristic = service->createCharacteristic(
        xtinct::pocket_sync::CONTROL_UUID,
        NIMBLE_PROPERTY::WRITE | NIMBLE_PROPERTY::WRITE_AUTHEN | NIMBLE_PROPERTY::INDICATE,
        CONTROL_FRAGMENT_HEADER_BYTES + MAX_CONTROL_MESSAGE_BYTES);
    dataCharacteristic = service->createCharacteristic(
        xtinct::pocket_sync::DATA_UUID, NIMBLE_PROPERTY::WRITE_NR | NIMBLE_PROPERTY::WRITE_AUTHEN,
        xtinct::pocket_sync::DATA_HEADER_BYTES + xtinct::pocket_sync::DEVICE_MAX_CHUNK_BYTES);
    statusCharacteristic = service->createCharacteristic(
        xtinct::pocket_sync::STATUS_UUID,
        NIMBLE_PROPERTY::READ | NIMBLE_PROPERTY::READ_AUTHEN | NIMBLE_PROPERTY::NOTIFY, STATUS_BYTES);
    if (!capabilitiesCharacteristic || !controlCharacteristic || !dataCharacteristic || !statusCharacteristic) {
      return failStart();
    }
    capabilitiesCharacteristic->setCallbacks(this);
    controlCharacteristic->setCallbacks(this);
    dataCharacteristic->setCallbacks(this);
    statusCharacteristic->setCallbacks(this);
    refreshCapabilities();
    publishStatus(false);
    if (!server->start()) return failStart();

    auto* advertising = NimBLEDevice::getAdvertising();
    if (!advertising || !advertising->setName(DEVICE_NAME) ||
        !advertising->addServiceUUID(xtinct::pocket_sync::SERVICE_UUID)) {
      return failStart();
    }
    advertising->enableScanResponse(true);
    advertising->setMinInterval(160);  // 100 ms while the physical screen is open.
    advertising->setMaxInterval(240);  // 150 ms.
    running.store(true);
    if (!advertising->start()) return failStart();
    heapAfterInit = ESP.getFreeHeap();
    sampleRuntimeBudget();
    LOG_INF("PSYNC", "Pocket Sync BLE ready (heap_before=%u heap_after=%u persistent=%u)",
            static_cast<unsigned>(heapBeforeInit), static_cast<unsigned>(heapAfterInit),
            static_cast<unsigned>(sizeof(Impl)));
    updateSnapshot();
    return true;
  }

  void stop() {
    if (stopping.exchange(true)) return;
    if (running.load()) {
      sampleRuntimeBudget();
      LOG_INF("PSYNC", "Pocket Sync budget (heap_min=%u loop_stack_free=%u)",
              static_cast<unsigned>(minimumFreeHeap),
              static_cast<unsigned>(phoneSyncLoopStackFreeBytes));
    }
    running.store(false);
    if (nimbleInitialized) {
      NimBLEDevice::stopAdvertising();
      if (server && connectionHandle.load() != BLE_HS_CONN_HANDLE_NONE) {
        server->disconnect(connectionHandle.load());
      }
      NimBLEDevice::deinit(false);
    }
    server = nullptr;
    service = nullptr;
    capabilitiesCharacteristic = nullptr;
    controlCharacteristic = nullptr;
    dataCharacteristic = nullptr;
    statusCharacteristic = nullptr;
    nimbleInitialized = false;
    connected = false;
    authenticated = false;
    connectionHandle = BLE_HS_CONN_HANDLE_NONE;
    controlIndicationHandle = BLE_HS_CONN_HANDLE_NONE;
    disconnectRequested = false;
    clearControlAssembly();
    secureZero(appKey, sizeof(appKey));
    secureZero(phoneId, sizeof(phoneId));
    portENTER_CRITICAL(&pairingMux);
    secureZero(peerId, sizeof(peerId));
    secureZero(currentPeerId, sizeof(currentPeerId));
    portEXIT_CRITICAL(&pairingMux);
    secureZero(sessionNonce, sizeof(sessionNonce));
    updateSnapshot();
  }

  void run() {
    if (!running.load()) return;
    sampleRuntimeBudget();
    serviceDisconnectRequest();
    bool restartAdvertising = false;
    if (disconnectObserved.exchange(false)) {
      disconnectRequested.store(false);
      if (dataQueue) xQueueReset(dataQueue);
      dataEnabled.store(false);
      queriedThisConnection = false;
      gathering = false;
      clearControlAssembly();
      resetResponseAfterDisconnect();
      restartAdvertising = true;
    }
    if (transportFault.exchange(false)) {
      store.fail(Result::Sequence, queuedFaultStream.load());
      dataEnabled.store(false);
      publishStatus(!isClosing());
    }
    if (restartAdvertising && running.load() && !stopping.load() &&
        connectionHandle.load() == BLE_HS_CONN_HANDLE_NONE) {
      NimBLEDevice::startAdvertising();
    }
    if (quiesceClosing()) return;
    if (expireControlAssembly(millis())) requestDisconnect();
    if (quiesceClosing()) return;
    // Retire an acknowledged response before dispatching a CONTROL request
    // which may already have arrived from the NimBLE host task.
    pumpIndication();
    if (quiesceClosing()) return;
    processPendingControl();
    if (quiesceClosing()) return;
    processQueuedData();
    if (quiesceClosing()) return;
    // Preserve the previous one-loop response latency for newly dispatched
    // controls while keeping the retirement ordering above.
    pumpIndication();
    if (quiesceClosing()) return;
    updateSnapshot();
  }

  bool resetPairing() {
    if (!running.load()) return false;
    // Stop admission before replacing live pairing material, and latch Closing
    // first when a peer still exists.
    NimBLEDevice::stopAdvertising();
    const bool disconnecting = connected.load() ||
                               connectionHandle.load() != BLE_HS_CONN_HANDLE_NONE ||
                               disconnectObserved.load() || isClosing();
    if (disconnecting) requestDisconnect();
    if (!clearPairingRecord() || !NimBLEDevice::deleteAllBonds()) {
      if (!disconnecting && running.load() && !stopping.load()) NimBLEDevice::startAdvertising();
      return false;
    }
    if (store.active()) store.abort();
    secureZero(appKey, sizeof(appKey));
    secureZero(phoneId, sizeof(phoneId));
    portENTER_CRITICAL(&pairingMux);
    secureZero(peerId, sizeof(peerId));
    secureZero(currentPeerId, sizeof(currentPeerId));
    portEXIT_CRITICAL(&pairingMux);
    pairingState.store(PairingState::Missing);
    activePack = false;
    dataEnabled.store(false);
    queriedThisConnection = false;
    enrollmentDeadline.store(millis() + ENROLLMENT_WINDOW_MS);
    displayPasskey.store(100000U + esp_random() % 900000U);
    NimBLEDevice::setSecurityPasskey(displayPasskey.load());
    if (!disconnecting && running.load() && !stopping.load()) NimBLEDevice::startAdvertising();
    updateSnapshot();
    return true;
  }

  uint32_t passkey() const { return displayPasskey.load(); }
  uint32_t generation() const { return uiGeneration.load(); }
  size_t bytes() const { return sizeof(Impl); }

  Snapshot getSnapshot() const {
    portENTER_CRITICAL(&snapshotMux);
    const Snapshot result = currentSnapshot;
    portEXIT_CRITICAL(&snapshotMux);
    return result;
  }

 private:
  enum class PairingState : uint8_t { Missing, Valid, Corrupt };

  struct DataItem {
    uint32_t offset = 0;
    uint8_t stream = MANIFEST_STREAM;
    uint8_t length = 0;
    uint8_t bytes[xtinct::pocket_sync::DEVICE_MAX_CHUNK_BYTES] = {0};
  };

  static_assert(sizeof(DataItem) <= 240, "Pocket Sync DATA queue item grew unexpectedly");

  PocketSyncStore store;
  NimBLEServer* server = nullptr;
  NimBLEService* service = nullptr;
  NimBLECharacteristic* capabilitiesCharacteristic = nullptr;
  NimBLECharacteristic* controlCharacteristic = nullptr;
  NimBLECharacteristic* dataCharacteristic = nullptr;
  NimBLECharacteristic* statusCharacteristic = nullptr;
  QueueHandle_t dataQueue = nullptr;
  StaticQueue_t dataQueueState{};
  alignas(uint32_t) uint8_t dataQueueStorage[WINDOW_CHUNKS * sizeof(DataItem)] = {0};

  mutable portMUX_TYPE snapshotMux = portMUX_INITIALIZER_UNLOCKED;
  mutable portMUX_TYPE pairingMux = portMUX_INITIALIZER_UNLOCKED;
  portMUX_TYPE controlMux = portMUX_INITIALIZER_UNLOCKED;
  Snapshot currentSnapshot{};
  std::atomic<uint32_t> uiGeneration{0};
  std::atomic<bool> stopping{false};
  std::atomic<bool> connected{false};
  std::atomic<bool> authenticated{false};
  std::atomic<bool> disconnectObserved{false};
  std::atomic<bool> disconnectRequested{false};
  std::atomic<bool> transportFault{false};
  std::atomic<uint8_t> queuedFaultStream{MANIFEST_STREAM};
  std::atomic<uint16_t> connectionHandle{BLE_HS_CONN_HANDLE_NONE};
  std::atomic<uint16_t> controlIndicationHandle{BLE_HS_CONN_HANDLE_NONE};
  std::atomic<uint16_t> connectionMtu{23};
  std::atomic<int16_t> indicationStatus{INDICATION_IDLE};

  std::atomic<PairingState> pairingState{PairingState::Missing};
  std::atomic<bool> running{false};
  bool nimbleInitialized = false;
  bool gathering = false;
  bool queriedThisConnection = false;
  std::atomic<bool> dataEnabled{false};
  bool activePack = false;
  uint8_t appKey[APP_KEY_BYTES] = {0};
  uint8_t phoneId[PHONE_ID_BYTES] = {0};
  uint8_t peerId[PEER_ID_BYTES] = {0};
  uint8_t currentPeerId[PEER_ID_BYTES] = {0};
  uint8_t sessionNonce[16] = {0};
  uint8_t activePackDigest[32] = {0};
  std::atomic<uint32_t> displayPasskey{0};
  std::atomic<uint32_t> enrollmentDeadline{0};

  uint8_t assemblyOpcode = 0;
  uint8_t assemblyMessageId = 0;
  uint8_t assemblyFragmentCount = 0;
  uint8_t assemblyNextFragment = 0;
  uint8_t assemblyLength = 0;
  uint8_t assemblyBody[MAX_CONTROL_MESSAGE_BYTES] = {0};
  unsigned long controlAssemblyStartedAt = 0;
  bool controlReady = false;
  uint8_t pendingOpcode = 0;
  uint8_t pendingMessageId = 0;
  uint8_t pendingLength = 0;
  uint8_t pendingBody[MAX_CONTROL_MESSAGE_BYTES] = {0};
  uint32_t lastRequestSequence = 0;
  uint32_t responseSequence = 0;

  std::atomic<xtinct::pocket_sync::ControlResponseState> responseState{
      xtinct::pocket_sync::ControlResponseState::Idle};
  std::atomic<bool> finalResponseFrameInFlight{false};
  uint8_t responseOpcode = 0;
  uint8_t responseMessageId = 0;
  uint8_t responseLength = 0;
  uint8_t responseBody[MAX_CONTROL_MESSAGE_BYTES] = {0};
  uint8_t responseFragment = 0;
  uint8_t responseFragments = 0;

  uint32_t heapBeforeInit = 0;
  uint32_t heapAfterInit = 0;
  uint32_t minimumFreeHeap = 0;
  uint32_t phoneSyncLoopStackFreeBytes = 0;
  uint32_t lastPublishedStatusSequence = 0;

  PairingState loadPairing() {
    Preferences preferences;
    if (!preferences.begin(NVS_NAMESPACE, true)) return PairingState::Corrupt;
    const size_t length = preferences.getBytesLength(NVS_PAIRING_KEY);
    if (length == 0) {
      preferences.end();
      return PairingState::Missing;
    }
    uint8_t record[PAIRING_RECORD_BYTES] = {0};
    const size_t read = length == sizeof(record)
                            ? preferences.getBytes(NVS_PAIRING_KEY, record, sizeof(record))
                            : 0;
    preferences.end();
    const uint32_t expectedCrc = xtinct::pocket_sync::readLittle32(record + PAIRING_BODY_BYTES);
    if (read != sizeof(record) || record[0] != PAIRING_VERSION ||
        expectedCrc != crc32(record, PAIRING_BODY_BYTES) || record[1 + APP_KEY_BYTES + PHONE_ID_BYTES] > 3) {
      secureZero(record, sizeof(record));
      return PairingState::Corrupt;
    }
    std::memcpy(appKey, record + 1, APP_KEY_BYTES);
    std::memcpy(phoneId, record + 1 + APP_KEY_BYTES, PHONE_ID_BYTES);
    portENTER_CRITICAL(&pairingMux);
    std::memcpy(peerId, record + 1 + APP_KEY_BYTES + PHONE_ID_BYTES, PEER_ID_BYTES);
    portEXIT_CRITICAL(&pairingMux);
    secureZero(record, sizeof(record));
    return PairingState::Valid;
  }

  bool savePairing(const uint8_t newKey[APP_KEY_BYTES], const uint8_t newPhone[PHONE_ID_BYTES],
                   const uint8_t newPeer[PEER_ID_BYTES]) {
    uint8_t record[PAIRING_RECORD_BYTES] = {0};
    record[0] = PAIRING_VERSION;
    std::memcpy(record + 1, newKey, APP_KEY_BYTES);
    std::memcpy(record + 1 + APP_KEY_BYTES, newPhone, PHONE_ID_BYTES);
    std::memcpy(record + 1 + APP_KEY_BYTES + PHONE_ID_BYTES, newPeer, PEER_ID_BYTES);
    xtinct::pocket_sync::writeLittle32(record + PAIRING_BODY_BYTES, crc32(record, PAIRING_BODY_BYTES));
    Preferences preferences;
    if (!preferences.begin(NVS_NAMESPACE, false)) {
      secureZero(record, sizeof(record));
      return false;
    }
    const bool written = preferences.putBytes(NVS_PAIRING_KEY, record, sizeof(record)) == sizeof(record);
    preferences.end();
    uint8_t verified[PAIRING_RECORD_BYTES] = {0};
    Preferences reader;
    const bool opened = reader.begin(NVS_NAMESPACE, true);
    const bool matches = opened && reader.getBytesLength(NVS_PAIRING_KEY) == sizeof(verified) &&
                         reader.getBytes(NVS_PAIRING_KEY, verified, sizeof(verified)) == sizeof(verified) &&
                         constantTimeEqual(record, verified, sizeof(record));
    if (opened) reader.end();
    secureZero(record, sizeof(record));
    secureZero(verified, sizeof(verified));
    return written && matches;
  }

  bool clearPairingRecord() {
    Preferences preferences;
    if (!preferences.begin(NVS_NAMESPACE, false)) return false;
    const bool removed = !preferences.isKey(NVS_PAIRING_KEY) || preferences.remove(NVS_PAIRING_KEY);
    const bool absent = !preferences.isKey(NVS_PAIRING_KEY);
    preferences.end();
    return removed && absent;
  }

  void generateSessionSecrets() {
    displayPasskey.store(100000U + esp_random() % 900000U);
    esp_fill_random(sessionNonce, sizeof(sessionNonce));
    bool nonzero = false;
    for (const uint8_t value : sessionNonce) nonzero = nonzero || value != 0;
    if (!nonzero) sessionNonce[0] = 1;
  }

  bool failStart() {
    stop();
    return false;
  }

  void refreshCapabilities() {
    if (!capabilitiesCharacteristic) return;
    uint8_t bytes[xtinct::pocket_sync::CAPABILITIES_BYTES];
    if (xtinct::pocket_sync::writeCapabilities(bytes, sizeof(bytes), sessionNonce)) {
      capabilitiesCharacteristic->setValue(bytes, sizeof(bytes));
    }
  }

  void publishStatus(const bool notify, const uint8_t ackStream = 0xfe, const uint32_t ackOffset = 0) {
    if (!statusCharacteristic) return;
    const auto& status = store.status();
    uint8_t bytes[STATUS_BYTES];
    const bool customAck = ackStream != 0xfe;
    const Phase phase = customAck ? Phase::Objects : status.phase;
    const uint8_t stream = customAck ? ackStream : status.stream;
    const uint32_t offset = customAck ? ackOffset : status.durableOffset;
    if (!xtinct::pocket_sync::writeStatusFrame(bytes, sizeof(bytes), phase, status.result, stream,
                                               status.negotiatedChunk, offset, status.sequence,
                                               status.packPrefix)) {
      return;
    }
    if (notify && !isClosing() && connected.load() && authenticated.load()) {
      statusCharacteristic->notify(bytes, sizeof(bytes), connectionHandle.load());
    }
    if (customAck) {
      if (!xtinct::pocket_sync::writeStatusFrame(bytes, sizeof(bytes), status.phase, status.result,
                                                 status.stream, status.negotiatedChunk,
                                                 status.durableOffset, status.sequence,
                                                 status.packPrefix)) {
        return;
      }
    }
    statusCharacteristic->setValue(bytes, sizeof(bytes));
    lastPublishedStatusSequence = status.sequence;
  }

  void sampleRuntimeBudget() {
    const uint32_t freeHeap = ESP.getFreeHeap();
    minimumFreeHeap = minimumFreeHeap == 0 ? freeHeap : std::min(minimumFreeHeap, freeHeap);
    const UBaseType_t words = uxTaskGetStackHighWaterMark(nullptr);
    phoneSyncLoopStackFreeBytes = static_cast<uint32_t>(words) * sizeof(StackType_t);
  }

  void updateSnapshot() {
    Snapshot next{};
    const auto& status = store.status();
    next.phase = status.phase;
    next.result = status.result;
    next.stream = status.stream;
    next.negotiatedChunk = status.negotiatedChunk;
    next.durableOffset = status.durableOffset;
    next.statusSequence = status.sequence;
    next.freeHeap = ESP.getFreeHeap();
    next.minimumFreeHeap = minimumFreeHeap;
    next.phoneSyncLoopStackFreeBytes = phoneSyncLoopStackFreeBytes;
    const PairingState pairing = pairingState.load();
    next.configured = pairing == PairingState::Valid;
    next.connected = connected.load();
    next.authenticated = authenticated.load();
    next.enrollmentOpen = pairing == PairingState::Missing &&
                          static_cast<int32_t>(enrollmentDeadline.load() - millis()) > 0;
    if (!running.load()) next.stage = UiStage::Stopped;
    else if (responseState.load() == xtinct::pocket_sync::ControlResponseState::Closing ||
             pairing == PairingState::Corrupt || status.phase == Phase::Error) next.stage = UiStage::Failed;
    else if (status.phase == Phase::Complete) next.stage = UiStage::Complete;
    else if (status.phase == Phase::Committing) next.stage = UiStage::Committing;
    else if (status.phase == Phase::Validating) next.stage = UiStage::Validating;
    else if (status.phase == Phase::Manifest || status.phase == Phase::Objects) next.stage = UiStage::Receiving;
    else if (gathering) next.stage = UiStage::Gathering;
    else if (next.authenticated) next.stage = UiStage::Secured;
    else if (next.connected) next.stage = UiStage::Pairing;
    else next.stage = UiStage::Advertising;

    portENTER_CRITICAL(&snapshotMux);
    const bool changed = snapshotUiChanged(currentSnapshot, next);
    currentSnapshot = next;
    portEXIT_CRITICAL(&snapshotMux);
    if (changed) ++uiGeneration;
  }

  void capturePeer(const NimBLEConnInfo& info, uint8_t output[PEER_ID_BYTES]) const {
    const NimBLEAddress address = info.getIdAddress();
    output[0] = address.getType();
    std::memcpy(output + 1, address.getVal(), 6);
  }

  bool isClosing() const {
    return responseState.load() == xtinct::pocket_sync::ControlResponseState::Closing;
  }

  bool isCurrentConnection(const NimBLEConnInfo& info) const {
    const uint16_t handle = connectionHandle.load();
    return connected.load() && handle != BLE_HS_CONN_HANDLE_NONE && info.getConnHandle() == handle;
  }

  bool controlIndicationsSubscribed() const {
    const uint16_t handle = connectionHandle.load();
    return connected.load() && handle != BLE_HS_CONN_HANDLE_NONE &&
           controlIndicationHandle.load() == handle;
  }

  bool quiesceClosing() {
    if (!isClosing()) return false;
    dataEnabled.store(false);
    if (dataQueue) xQueueReset(dataQueue);
    updateSnapshot();
    return true;
  }

  bool securePeer(const NimBLEConnInfo& info, uint8_t output[PEER_ID_BYTES]) const {
    if (!info.isBonded() || !info.isEncrypted() || !info.isAuthenticated() || info.getSecKeySize() != 16) {
      return false;
    }
    capturePeer(info, output);
    const PairingState pairing = pairingState.load();
    if (pairing == PairingState::Corrupt) return false;
    if (pairing != PairingState::Valid) return true;
    portENTER_CRITICAL(&pairingMux);
    const bool matches = constantTimeEqual(output, peerId, PEER_ID_BYTES);
    portEXIT_CRITICAL(&pairingMux);
    return matches;
  }

  void onConnect(NimBLEServer* connectedServer, NimBLEConnInfo& info) override {
    if (stopping.load()) return;
    connected = true;
    authenticated = false;
    connectionHandle = info.getConnHandle();
    controlIndicationHandle = BLE_HS_CONN_HANDLE_NONE;
    if (!running.load() || isClosing()) {
      requestDisconnect();
      return;
    }
    connectionMtu = std::max<uint16_t>(23, info.getMTU());
    lastRequestSequence = 0;
    responseSequence = 0;
    esp_fill_random(sessionNonce, sizeof(sessionNonce));
    refreshCapabilities();
    connectedServer->updateConnParams(info.getConnHandle(), 12, 24, 0,
                                      CONNECTION_SUPERVISION_TIMEOUT_UNITS);
  }

  void onDisconnect(NimBLEServer*, NimBLEConnInfo& info, int) override {
    if (info.getConnHandle() != connectionHandle.load()) return;
    connected = false;
    authenticated = false;
    connectionHandle = BLE_HS_CONN_HANDLE_NONE;
    controlIndicationHandle = BLE_HS_CONN_HANDLE_NONE;
    disconnectObserved = true;
  }

  void onMTUChange(const uint16_t mtu, NimBLEConnInfo& info) override {
    if (stopping.load() || !running.load() || !isCurrentConnection(info)) return;
    connectionMtu = std::max<uint16_t>(23, mtu);
  }

  uint32_t onPassKeyDisplay() override { return displayPasskey.load(); }

  void onAuthenticationComplete(NimBLEConnInfo& info) override {
    if (stopping.load() || !running.load() || isClosing() || !isCurrentConnection(info)) return;
    uint8_t candidate[PEER_ID_BYTES] = {0};
    const bool accepted = securePeer(info, candidate);
    if (accepted) {
      portENTER_CRITICAL(&pairingMux);
      std::memcpy(currentPeerId, candidate, sizeof(currentPeerId));
      portEXIT_CRITICAL(&pairingMux);
      authenticated = true;
    } else {
      authenticated = false;
      requestDisconnect();
    }
    secureZero(candidate, sizeof(candidate));
  }

  void onWrite(NimBLECharacteristic* characteristic, NimBLEConnInfo& info) override {
    if (stopping.load() || !running.load() || isClosing() || !isCurrentConnection(info)) return;
    uint8_t candidate[PEER_ID_BYTES] = {0};
    if (!securePeer(info, candidate)) {
      secureZero(candidate, sizeof(candidate));
      requestDisconnect();
      return;
    }
    portENTER_CRITICAL(&pairingMux);
    std::memcpy(currentPeerId, candidate, sizeof(currentPeerId));
    portEXIT_CRITICAL(&pairingMux);
    secureZero(candidate, sizeof(candidate));
    authenticated = true;
    const NimBLEAttValue value = characteristic->getValue();
    if (characteristic == controlCharacteristic) {
      if (!controlIndicationsSubscribed()) {
        requestDisconnect();
        return;
      }
      acceptControlFragment(value.data(), value.size());
    } else if (characteristic == dataCharacteristic) {
      acceptDataFrame(value.data(), value.size());
    }
  }

  void onSubscribe(NimBLECharacteristic* characteristic, NimBLEConnInfo& info,
                   const uint16_t subValue) override {
    if (stopping.load() || !running.load() || characteristic != controlCharacteristic ||
        !isCurrentConnection(info)) {
      return;
    }
    // NimBLE uses bit 1 for indications (2 = indicate, 3 = notify + indicate).
    controlIndicationHandle.store((subValue & 0x02U) != 0U
                                      ? info.getConnHandle()
                                      : BLE_HS_CONN_HANDLE_NONE);
  }

  void onStatus(NimBLECharacteristic* characteristic, NimBLEConnInfo& info, const int code) override {
    if (stopping.load() || !running.load() || characteristic != controlCharacteristic ||
        !isCurrentConnection(info) || isClosing()) {
      return;
    }
    if (code != BLE_HS_EDONE) {
      requestDisconnect();
      indicationStatus.store(static_cast<int16_t>(code));
      return;
    }
    if (indicationStatus.load() != INDICATION_WAITING) {
      requestDisconnect();
      return;
    }
    if (finalResponseFrameInFlight.load()) {
      auto expected = xtinct::pocket_sync::ControlResponseState::InFlight;
      const auto acknowledged = xtinct::pocket_sync::responseStateAfterIndication(
          xtinct::pocket_sync::ControlResponseState::InFlight, true, true);
      if (!responseState.compare_exchange_strong(expected, acknowledged)) {
        if (expected != xtinct::pocket_sync::ControlResponseState::Closing) requestDisconnect();
        return;
      }
    }
    // Publish FinalAcknowledged before EDONE. pumpIndication observes EDONE as
    // permission to retire, so the reverse order could falsely close a valid ACK.
    indicationStatus.store(static_cast<int16_t>(code));
  }

  void acceptControlFragment(const uint8_t* bytes, const size_t length) {
    if (isClosing()) return;
    xtinct::pocket_sync::ControlFragmentView fragment;
    if (!xtinct::pocket_sync::parseControlFragment(bytes, length, fragment)) {
      requestDisconnect();
      return;
    }
    const uint8_t opcode = static_cast<uint8_t>(fragment.opcode);
    const PairingState pairing = pairingState.load();
    const bool enrollAllowed = pairing == PairingState::Valid ||
                               (pairing == PairingState::Missing &&
                                static_cast<int32_t>(enrollmentDeadline.load() - millis()) > 0);
    if ((opcode == static_cast<uint8_t>(Opcode::Enroll) && !enrollAllowed) ||
        (opcode != static_cast<uint8_t>(Opcode::Enroll) && pairing != PairingState::Valid)) {
      requestDisconnect();
      return;
    }

    portENTER_CRITICAL(&controlMux);
    bool valid = xtinct::pocket_sync::canQueueControlRequest(
        controlReady, responseState.load(), finalResponseFrameInFlight.load());
    if (valid && assemblyNextFragment == 0) {
      assemblyOpcode = opcode;
      assemblyMessageId = fragment.messageId;
      assemblyFragmentCount = fragment.fragmentCount;
      assemblyLength = 0;
      controlAssemblyStartedAt = millis();
    }
    valid = valid && opcode == assemblyOpcode && fragment.messageId == assemblyMessageId &&
            fragment.fragmentCount == assemblyFragmentCount &&
            fragment.fragmentIndex == assemblyNextFragment &&
            static_cast<size_t>(assemblyLength) + fragment.payloadLength <= sizeof(assemblyBody);
    if (valid) {
      std::memcpy(assemblyBody + assemblyLength, fragment.payload, fragment.payloadLength);
      assemblyLength = static_cast<uint8_t>(assemblyLength + fragment.payloadLength);
      ++assemblyNextFragment;
      if (assemblyNextFragment == assemblyFragmentCount) {
        pendingOpcode = assemblyOpcode;
        pendingMessageId = assemblyMessageId;
        pendingLength = assemblyLength;
        std::memcpy(pendingBody, assemblyBody, pendingLength);
        controlReady = true;
        assemblyNextFragment = 0;
        assemblyLength = 0;
        controlAssemblyStartedAt = 0;
      }
    }
    portEXIT_CRITICAL(&controlMux);
    if (!valid) requestDisconnect();
  }

  void acceptDataFrame(const uint8_t* bytes, const size_t length) {
    DataFrameView frame{};
    if (!xtinct::pocket_sync::canAcceptDataFrame(dataEnabled.load(), responseState.load()) ||
        !xtinct::pocket_sync::parseDataFrame(bytes, length, frame)) {
      queuedFaultStream = frame.stream;
      transportFault = true;
      requestDisconnect();
      return;
    }
    DataItem item;
    item.stream = frame.stream;
    item.offset = frame.offset;
    item.length = frame.length;
    std::memcpy(item.bytes, frame.data, frame.length);
    if (!xtinct::pocket_sync::canAcceptDataFrame(dataEnabled.load(), responseState.load())) {
      secureZero(item.bytes, item.length);
      return;
    }
    // Never block the NimBLE host callback.  Flow control is the phone's job;
    // a full bounded window is a transport fault and closes fail-safe.
    if (xQueueSend(dataQueue, &item, 0) != pdTRUE) {
      queuedFaultStream = frame.stream;
      transportFault = true;
      requestDisconnect();
    }
    secureZero(item.bytes, item.length);
  }

  void clearControlAssemblyLocked() {
    assemblyOpcode = 0;
    assemblyMessageId = 0;
    assemblyFragmentCount = 0;
    assemblyNextFragment = 0;
    assemblyLength = 0;
    controlAssemblyStartedAt = 0;
    controlReady = false;
    pendingLength = 0;
    secureZero(assemblyBody, sizeof(assemblyBody));
    secureZero(pendingBody, sizeof(pendingBody));
  }

  void clearControlAssembly() {
    portENTER_CRITICAL(&controlMux);
    clearControlAssemblyLocked();
    portEXIT_CRITICAL(&controlMux);
  }

  bool expireControlAssembly(const uint32_t now) {
    portENTER_CRITICAL(&controlMux);
    const bool expired = xtinct::pocket_sync::controlAssemblyExpired(
        static_cast<uint32_t>(controlAssemblyStartedAt), now,
        static_cast<uint32_t>(CONTROL_ASSEMBLY_TIMEOUT_MS));
    if (expired) clearControlAssemblyLocked();
    portEXIT_CRITICAL(&controlMux);
    return expired;
  }

  void clearResponseStorage() {
    finalResponseFrameInFlight = false;
    responseLength = 0;
    responseFragment = 0;
    responseFragments = 0;
    indicationStatus = INDICATION_IDLE;
    secureZero(responseBody, sizeof(responseBody));
  }

  void resetResponseAfterDisconnect() {
    clearResponseStorage();
    // Idle is published last, after the disconnected connection's response
    // and request state have been fully erased.
    responseState.store(xtinct::pocket_sync::ControlResponseState::Idle);
  }

  bool retireAcknowledgedResponse() {
    if (responseState.load() != xtinct::pocket_sync::ControlResponseState::FinalAcknowledged) {
      return false;
    }
    clearResponseStorage();
    auto expected = xtinct::pocket_sync::ControlResponseState::FinalAcknowledged;
    return responseState.compare_exchange_strong(
        expected, xtinct::pocket_sync::ControlResponseState::Idle);
  }

  void requestDisconnect() {
    // This latch is intentionally not cleared by an indication error path or
    // by the asynchronous disconnect request. Only disconnect cleanup resets it.
    responseState.store(xtinct::pocket_sync::ControlResponseState::Closing);
    dataEnabled.store(false);
    disconnectRequested.store(true);
  }

  void serviceDisconnectRequest() {
    if (!disconnectRequested.load()) return;
    if (!server) return;
    const uint16_t handle = connectionHandle.load();
    if (handle == BLE_HS_CONN_HANDLE_NONE || !connected.load() || server->getConnectedCount() == 0) {
      // There is no peer left to produce onDisconnect. Schedule the same local
      // cleanup so the fail-closed Closing state cannot become permanent.
      connected.store(false);
      authenticated.store(false);
      connectionHandle.store(BLE_HS_CONN_HANDLE_NONE);
      controlIndicationHandle.store(BLE_HS_CONN_HANDLE_NONE);
      disconnectRequested.store(false);
      disconnectObserved.store(true);
      return;
    }
    // A transient ble_gap_terminate failure must remain pending for the next
    // activity-loop turn. Clearing the latch before this call strands Closing.
    if (server->disconnect(handle)) disconnectRequested.store(false);
  }

  bool verifySignedRequest(const uint8_t opcode, const uint8_t messageId, const uint8_t* body,
                           const size_t bodyLength, const uint8_t*& payload, size_t& payloadLength,
                           Result& error) {
    if (pairingState.load() != PairingState::Valid || !body || bodyLength < 20) {
      error = Result::Auth;
      return false;
    }
    const uint32_t sequence = xtinct::pocket_sync::readLittle32(body);
    payload = body + 4;
    payloadLength = bodyLength - 20;
    const uint8_t* suppliedMac = body + bodyLength - 16;
    uint8_t expectedMac[16] = {0};
    if (sequence == 0 || sequence <= lastRequestSequence) {
      error = Result::Replay;
      return false;
    }
    if (!hmac16(appKey, sessionNonce, opcode, messageId, body, payload, payloadLength, expectedMac) ||
        !constantTimeEqual(expectedMac, suppliedMac, sizeof(expectedMac))) {
      secureZero(expectedMac, sizeof(expectedMac));
      error = Result::Auth;
      return false;
    }
    secureZero(expectedMac, sizeof(expectedMac));
    lastRequestSequence = sequence;
    error = Result::Ok;
    return true;
  }

  bool beginSignedResponse(const uint8_t requestOpcode, const uint8_t messageId,
                           const uint8_t* payload, const size_t payloadLength) {
    if (pairingState.load() != PairingState::Valid || payloadLength + 20 > sizeof(responseBody)) {
      return false;
    }
    auto expected = xtinct::pocket_sync::ControlResponseState::Dispatching;
    if (!responseState.compare_exchange_strong(
            expected, xtinct::pocket_sync::ControlResponseState::InFlight)) {
      return false;
    }
    responseOpcode = static_cast<uint8_t>(requestOpcode | 0x80U);
    responseMessageId = messageId;
    const uint32_t sequence = ++responseSequence;
    xtinct::pocket_sync::writeLittle32(responseBody, sequence);
    if (payloadLength != 0) std::memcpy(responseBody + 4, payload, payloadLength);
    uint8_t mac[16] = {0};
    if (!hmac16(appKey, sessionNonce, responseOpcode, responseMessageId, responseBody,
                responseBody + 4, payloadLength, mac)) {
      secureZero(mac, sizeof(mac));
      requestDisconnect();
      return false;
    }
    std::memcpy(responseBody + 4 + payloadLength, mac, sizeof(mac));
    secureZero(mac, sizeof(mac));
    responseLength = static_cast<uint8_t>(payloadLength + 20);
    const uint16_t mtu = std::max<uint16_t>(23, connectionMtu.load());
    const size_t fragmentPayload = mtu - 3U - CONTROL_FRAGMENT_HEADER_BYTES;
    responseFragments = static_cast<uint8_t>((responseLength + fragmentPayload - 1U) / fragmentPayload);
    if (responseFragments == 0 || responseFragments > MAX_CONTROL_FRAGMENTS) {
      requestDisconnect();
      return false;
    }
    responseFragment = 0;
    finalResponseFrameInFlight = false;
    indicationStatus = INDICATION_IDLE;
    return true;
  }

  void respondResult(const uint8_t opcode, const uint8_t messageId, const Result result) {
    const uint8_t payload[] = {static_cast<uint8_t>(result)};
    if (!beginSignedResponse(opcode, messageId, payload, sizeof(payload))) requestDisconnect();
  }

  bool packMatches(const uint8_t* payload, const size_t length) const {
    return activePack && payload && length == sizeof(activePackDigest) &&
           constantTimeEqual(payload, activePackDigest, sizeof(activePackDigest));
  }

  void processPendingControl() {
    // A request queued just after the final indication ACK must wait until
    // pumpIndication() retires the old response.  Do not consume or reject it.
    uint8_t opcode = 0;
    uint8_t messageId = 0;
    uint8_t length = 0;
    uint8_t body[MAX_CONTROL_MESSAGE_BYTES] = {0};
    portENTER_CRITICAL(&controlMux);
    auto expected = xtinct::pocket_sync::ControlResponseState::Idle;
    const bool ownsDispatch = controlReady && responseState.compare_exchange_strong(
        expected, xtinct::pocket_sync::ControlResponseState::Dispatching);
    if (ownsDispatch) {
      opcode = pendingOpcode;
      messageId = pendingMessageId;
      length = pendingLength;
      std::memcpy(body, pendingBody, length);
      controlReady = false;
      pendingLength = 0;
      secureZero(pendingBody, sizeof(pendingBody));
    }
    portEXIT_CRITICAL(&controlMux);
    if (opcode == 0) return;
    if (isClosing()) {
      secureZero(body, sizeof(body));
      return;
    }

    if (opcode == static_cast<uint8_t>(Opcode::Enroll)) {
      processEnroll(messageId, body, length);
      secureZero(body, sizeof(body));
      return;
    }

    const uint8_t* payload = nullptr;
    size_t payloadLength = 0;
    Result verification = Result::Ok;
    if (!verifySignedRequest(opcode, messageId, body, length, payload, payloadLength, verification)) {
      respondResult(opcode, messageId, verification);
      secureZero(body, sizeof(body));
      return;
    }
    if (isClosing()) {
      secureZero(body, sizeof(body));
      return;
    }

    switch (static_cast<Opcode>(opcode)) {
      case Opcode::QueryState:
        processQuery(messageId, payload, payloadLength);
        break;
      case Opcode::Start:
        processStart(messageId, payload, payloadLength);
        break;
      case Opcode::SealManifest:
        processSeal(messageId, payload, payloadLength);
        break;
      case Opcode::Commit:
        processCommit(messageId, payload, payloadLength);
        break;
      case Opcode::Abort:
        processAbort(messageId, payload, payloadLength);
        break;
      default:
        respondResult(opcode, messageId, Result::Unsupported);
        break;
    }
    secureZero(body, sizeof(body));
  }

  void processEnroll(const uint8_t messageId, const uint8_t* body, const size_t length) {
    if (!authenticated.load() || !body || length != xtinct::pocket_sync::ENROLL_PAYLOAD_BYTES) {
      requestDisconnect();
      return;
    }
    const PairingState pairing = pairingState.load();
    uint8_t storedPeer[PEER_ID_BYTES] = {0};
    uint8_t activePeer[PEER_ID_BYTES] = {0};
    portENTER_CRITICAL(&pairingMux);
    std::memcpy(storedPeer, peerId, sizeof(storedPeer));
    std::memcpy(activePeer, currentPeerId, sizeof(activePeer));
    portEXIT_CRITICAL(&pairingMux);
    if (pairing == PairingState::Valid) {
      const bool replay = xtinct::pocket_sync::enrollmentReplayMatches(
          appKey, phoneId, storedPeer, body, length, activePeer);
      secureZero(storedPeer, sizeof(storedPeer));
      secureZero(activePeer, sizeof(activePeer));
      if (!replay) {
        requestDisconnect();
        return;
      }
      // The persisted enrollment already committed; this is the exact replay
      // used when its signed success indication was lost. Do not rewrite NVS.
      respondResult(static_cast<uint8_t>(Opcode::Enroll), messageId, Result::Ok);
      return;
    }
    secureZero(storedPeer, sizeof(storedPeer));
    if (pairing != PairingState::Missing ||
        static_cast<int32_t>(enrollmentDeadline.load() - millis()) <= 0) {
      secureZero(activePeer, sizeof(activePeer));
      requestDisconnect();
      return;
    }
    if (!savePairing(body, body + APP_KEY_BYTES, activePeer)) {
      secureZero(activePeer, sizeof(activePeer));
      requestDisconnect();
      return;
    }
    std::memcpy(appKey, body, APP_KEY_BYTES);
    std::memcpy(phoneId, body + APP_KEY_BYTES, PHONE_ID_BYTES);
    portENTER_CRITICAL(&pairingMux);
    std::memcpy(peerId, activePeer, PEER_ID_BYTES);
    portEXIT_CRITICAL(&pairingMux);
    secureZero(activePeer, sizeof(activePeer));
    pairingState.store(PairingState::Valid);
    respondResult(static_cast<uint8_t>(Opcode::Enroll), messageId, Result::Ok);
  }

  void processQuery(const uint8_t messageId, const uint8_t*, const size_t payloadLength) {
    if (payloadLength != 0) {
      respondResult(static_cast<uint8_t>(Opcode::QueryState), messageId, Result::Protocol);
      return;
    }
    uint8_t mask = 0;
    char revisions[4][33] = {{0}};
    uint64_t cursor = 0;
    uint8_t lastPack[32] = {0};
    uint8_t response[106] = {0};
    if (!PocketSyncStore::queryLocalState(mask, revisions, cursor, lastPack)) {
      respondResult(static_cast<uint8_t>(Opcode::QueryState), messageId, Result::StorageError);
      return;
    }
    response[0] = static_cast<uint8_t>(Result::Ok);
    response[1] = mask;
    for (uint8_t index = 0; index < 4; ++index) {
      if ((mask & (1U << index)) != 0 && !hex32To16(revisions[index], response + 2 + index * 16)) {
        respondResult(static_cast<uint8_t>(Opcode::QueryState), messageId, Result::StorageError);
        return;
      }
    }
    xtinct::pocket_sync::writeLittle64(response + 66, cursor);
    std::memcpy(response + 74, lastPack, sizeof(lastPack));
    queriedThisConnection = true;
    gathering = true;
    if (!beginSignedResponse(static_cast<uint8_t>(Opcode::QueryState), messageId, response, sizeof(response))) {
      requestDisconnect();
    }
  }

  void processStart(const uint8_t messageId, const uint8_t* payload, const size_t length) {
    if (!queriedThisConnection || length != 74) {
      respondResult(static_cast<uint8_t>(Opcode::Start), messageId, Result::Protocol);
      return;
    }
    const uint32_t manifestBytes = xtinct::pocket_sync::readLittle32(payload + 32);
    const uint32_t totalBytes = xtinct::pocket_sync::readLittle32(payload + 68);
    const uint8_t objectCount = payload[72];
    const uint8_t requestedChunk = payload[73];
    const uint8_t chunk = xtinct::pocket_sync::negotiateChunk(connectionMtu.load(), requestedChunk);
    if (chunk == 0 || !xtinct::pocket_sync::validPackBounds(manifestBytes, objectCount, totalBytes)) {
      respondResult(static_cast<uint8_t>(Opcode::Start), messageId, Result::Bounds);
      return;
    }
    const Result result = store.start(payload, manifestBytes, payload + 36, totalBytes, objectCount, chunk);
    if (result == Result::Ok) {
      std::memcpy(activePackDigest, payload, sizeof(activePackDigest));
      activePack = true;
      gathering = false;
      dataEnabled.store(store.status().phase != Phase::Complete);
      publishStatus(false);
    }
    respondResult(static_cast<uint8_t>(Opcode::Start), messageId, result);
  }

  void processSeal(const uint8_t messageId, const uint8_t* payload, const size_t length) {
    Result result = Result::Sequence;
    if (packMatches(payload, length)) result = store.sealManifest();
    if (result == Result::Ok) {
      dataEnabled.store(true);
      publishStatus(false);
    }
    respondResult(static_cast<uint8_t>(Opcode::SealManifest), messageId, result);
  }

  void processCommit(const uint8_t messageId, const uint8_t* payload, const size_t length) {
    Result result = Result::Sequence;
    if (packMatches(payload, length)) result = store.commit();
    dataEnabled.store(false);
    publishStatus(true);
    respondResult(static_cast<uint8_t>(Opcode::Commit), messageId, result);
  }

  void processAbort(const uint8_t messageId, const uint8_t* payload, const size_t length) {
    const Result result = packMatches(payload, length) ? Result::Ok : Result::Sequence;
    if (result == Result::Ok) {
      store.abort();
      activePack = false;
      dataEnabled.store(false);
      gathering = false;
      publishStatus(true);
    }
    respondResult(static_cast<uint8_t>(Opcode::Abort), messageId, result);
  }

  void processQueuedData() {
    if (!dataQueue) return;
    DataItem item;
    while (xtinct::pocket_sync::canAcceptDataFrame(dataEnabled.load(), responseState.load()) &&
           xQueueReceive(dataQueue, &item, 0) == pdTRUE) {
      if (isClosing()) {
        secureZero(item.bytes, item.length);
        break;
      }
      const uint32_t beforeSequence = store.status().sequence;
      const Result result = store.write(item.stream, item.offset, item.bytes, item.length);
      const auto& status = store.status();
      if (result != Result::Ok) {
        dataEnabled.store(false);
        requestDisconnect();
      }
      if (status.sequence != beforeSequence) {
        const bool streamAdvanced = result == Result::Ok && status.stream != item.stream &&
                                    item.stream != MANIFEST_STREAM;
        publishStatus(!isClosing(), streamAdvanced ? item.stream : 0xfe,
                      streamAdvanced ? item.offset + item.length : 0);
      }
      secureZero(item.bytes, item.length);
      if (isClosing()) break;
    }
    if (isClosing()) xQueueReset(dataQueue);
  }

  void pumpIndication() {
    const auto response = responseState.load();
    if ((response != xtinct::pocket_sync::ControlResponseState::InFlight &&
         response != xtinct::pocket_sync::ControlResponseState::FinalAcknowledged) ||
        !controlCharacteristic || !connected.load()) {
      return;
    }
    if (!controlIndicationsSubscribed()) {
      requestDisconnect();
      return;
    }
    const int16_t state = indicationStatus.load();
    if (state == INDICATION_WAITING) return;
    if (state != INDICATION_IDLE) {
      if (state != BLE_HS_EDONE) {
        requestDisconnect();
        return;
      }
      ++responseFragment;
      indicationStatus = INDICATION_IDLE;
      if (responseFragment >= responseFragments) {
        if (!retireAcknowledgedResponse() && !isClosing()) requestDisconnect();
        return;
      }
    }

    const uint16_t mtu = std::max<uint16_t>(23, connectionMtu.load());
    const size_t fragmentCapacity = mtu - 3U - CONTROL_FRAGMENT_HEADER_BYTES;
    const size_t start = static_cast<size_t>(responseFragment) * fragmentCapacity;
    const size_t amount = std::min(fragmentCapacity, static_cast<size_t>(responseLength) - start);
    uint8_t frame[CONTROL_FRAGMENT_HEADER_BYTES + MAX_CONTROL_MESSAGE_BYTES] = {0};
    frame[0] = 0xc1;
    frame[1] = xtinct::pocket_sync::PROTOCOL_VERSION;
    frame[2] = responseOpcode;
    frame[3] = responseMessageId;
    frame[4] = responseFragment;
    frame[5] = responseFragments;
    frame[6] = static_cast<uint8_t>(amount);
    std::memcpy(frame + CONTROL_FRAGMENT_HEADER_BYTES, responseBody + start, amount);
    finalResponseFrameInFlight = responseFragment + 1U >= responseFragments;
    indicationStatus = INDICATION_WAITING;
    if (!controlCharacteristic->indicate(frame, CONTROL_FRAGMENT_HEADER_BYTES + amount,
                                         connectionHandle.load())) {
      indicationStatus = INDICATION_IDLE;
      finalResponseFrameInFlight = false;
      requestDisconnect();
    }
  }
};

PocketSyncBleServer::PocketSyncBleServer() : impl(std::make_unique<Impl>()) {}

PocketSyncBleServer::~PocketSyncBleServer() = default;

bool PocketSyncBleServer::begin() { return impl && impl->start(); }

void PocketSyncBleServer::loop() {
  if (impl) impl->run();
}

void PocketSyncBleServer::end() {
  if (impl) impl->stop();
}

bool PocketSyncBleServer::resetPairing() { return impl && impl->resetPairing(); }

uint32_t PocketSyncBleServer::passkey() const { return impl ? impl->passkey() : 0; }

uint32_t PocketSyncBleServer::uiGeneration() const { return impl ? impl->generation() : 0; }

PocketSyncBleServer::Snapshot PocketSyncBleServer::snapshot() const {
  return impl ? impl->getSnapshot() : Snapshot{};
}

size_t PocketSyncBleServer::persistentBytes() const { return impl ? impl->bytes() : 0; }
