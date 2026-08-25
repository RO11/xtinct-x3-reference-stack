#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace xtinct::pocket_sync {

constexpr uint8_t PROTOCOL_VERSION = 1;
constexpr size_t MAX_MANIFEST_BYTES = 64U * 1024U;
constexpr uint8_t MAX_V1_CARDS = 4;
constexpr uint8_t MAX_V2_CHANGES = 64;
constexpr uint8_t MAX_OBJECTS = 68;
constexpr uint32_t MAX_OBJECT_BYTES = 20U * 1024U * 1024U;
constexpr uint32_t MAX_PACK_BYTES = 64U * 1024U * 1024U;
constexpr uint8_t PREFERRED_CHUNK_BYTES = 220;
constexpr uint8_t DEVICE_MAX_CHUNK_BYTES = 234;
constexpr uint8_t WINDOW_CHUNKS = 4;
constexpr uint8_t MANIFEST_STREAM = 0xff;
constexpr size_t CONTROL_FRAGMENT_HEADER_BYTES = 7;
constexpr size_t MAX_CONTROL_MESSAGE_BYTES = 128;
constexpr uint8_t MAX_CONTROL_FRAGMENTS = 10;
constexpr size_t DATA_HEADER_BYTES = 10;
constexpr size_t STATUS_BYTES = 20;
constexpr size_t CAPABILITIES_BYTES = 43;
constexpr size_t ENROLL_APP_KEY_BYTES = 32;
constexpr size_t ENROLL_PHONE_ID_BYTES = 16;
constexpr size_t BONDED_PEER_ID_BYTES = 7;
constexpr size_t ENROLL_PAYLOAD_BYTES = ENROLL_APP_KEY_BYTES + ENROLL_PHONE_ID_BYTES;
// The commit plan is an SD-backed JSONL stream, never an in-RAM operation
// array. Worst case: 68 artifact/report installs + 4 V1 card operations +
// manifest/etag + 64 V2 metadata installs + 64 stale snapshot deletes + cursor.
constexpr uint16_t MAX_PLAN_OPERATIONS =
    MAX_OBJECTS + MAX_V1_CARDS + 2U + MAX_V2_CHANGES + MAX_V2_CHANGES + 1U;

// Protected SD metadata is attacker/corruption controlled at boot. Its size
// must be checked from the directory entry before any buffer allocation/read.
inline constexpr bool validBoundedTextFileSize(const uint64_t bytes, const size_t maximum) {
  return bytes > 0 && bytes <= maximum && bytes < static_cast<uint64_t>(SIZE_MAX);
}

constexpr char SERVICE_UUID[] = "9f100000-8b7a-4c2d-a5e6-5854494e4354";
constexpr char CAPABILITIES_UUID[] = "9f100001-8b7a-4c2d-a5e6-5854494e4354";
constexpr char CONTROL_UUID[] = "9f100002-8b7a-4c2d-a5e6-5854494e4354";
constexpr char DATA_UUID[] = "9f100003-8b7a-4c2d-a5e6-5854494e4354";
constexpr char STATUS_UUID[] = "9f100004-8b7a-4c2d-a5e6-5854494e4354";

enum CapabilityFlag : uint16_t {
  CAP_RESUME = 1U << 0,
  CAP_ATOMIC_V1_V2 = 1U << 1,
  CAP_HMAC_CONTROL = 1U << 2,
  CAP_QUERY_STATE = 1U << 3,
  CAP_GENERIC_KINDS = 1U << 4,
};

enum RendererKindFlag : uint16_t {
  RENDER_CARD = 1U << 0,
  RENDER_TEXT = 1U << 1,
  RENDER_IMAGE_1BIT = 1U << 2,
  RENDER_EPUB = 1U << 3,
  RENDER_ACTION = 1U << 4,
  RENDER_SLEEP_SCREEN = 1U << 5,
};

enum class Opcode : uint8_t {
  Enroll = 0x01,
  QueryState = 0x02,
  Start = 0x03,
  SealManifest = 0x04,
  Commit = 0x05,
  Abort = 0x06,
};

// A CONTROL response remains owned by the server until the final indication is
// acknowledged.  The Bluetooth host may deliver the next request before the
// activity loop gets another turn. One next request may therefore be buffered
// once the final response frame is in flight (including before onStatus), but
// it may be dispatched only after that response is acknowledged and retired to
// Idle. Dispatching owns the dequeued request before a response is constructed,
// so a second request cannot enter that gap. Non-final fragments remain closed.
// Closing is a transport-fault latch: only completed disconnect cleanup may
// return it to Idle.
enum class ControlResponseState : uint8_t {
  Idle = 0,
  Dispatching = 1,
  InFlight = 2,
  FinalAcknowledged = 3,
  Closing = 4,
};

inline constexpr bool canQueueControlRequest(const bool controlAlreadyReady,
                                             const ControlResponseState responseState,
                                             const bool finalResponseFrameInFlight) {
  return !controlAlreadyReady &&
         (responseState == ControlResponseState::Idle ||
          responseState == ControlResponseState::FinalAcknowledged ||
          (responseState == ControlResponseState::InFlight && finalResponseFrameInFlight));
}

inline constexpr bool canDispatchControlRequest(const bool controlReady,
                                                const ControlResponseState responseState) {
  return controlReady && responseState == ControlResponseState::Idle;
}

inline constexpr bool canAcceptDataFrame(const bool dataEnabled,
                                         const ControlResponseState responseState) {
  return dataEnabled && responseState != ControlResponseState::Closing;
}

inline constexpr ControlResponseState responseStateAfterIndication(
    const ControlResponseState responseState, const bool finalFrame,
    const bool acknowledged) {
  if (!acknowledged) return ControlResponseState::Closing;
  if (responseState == ControlResponseState::InFlight && finalFrame) {
    return ControlResponseState::FinalAcknowledged;
  }
  return responseState;
}

inline constexpr bool controlAssemblyExpired(const uint32_t startedAt, const uint32_t now,
                                             const uint32_t timeout) {
  return startedAt != 0 && static_cast<uint32_t>(now - startedAt) > timeout;
}

enum class Phase : uint8_t { Idle = 0, Gathering = 1, Manifest = 2, Objects = 3, Validating = 4, Committing = 5, Complete = 6, Error = 7 };

enum class Result : uint8_t {
  Ok = 0,
  Auth = 1,
  Protocol = 2,
  Bounds = 3,
  Replay = 4,
  Sequence = 5,
  Crc = 6,
  StorageError = 7,
  Manifest = 8,
  Hash = 9,
  Unsupported = 10,
  Incomplete = 11,
  Commit = 12,
};

struct ControlFragmentView {
  Opcode opcode = Opcode::Abort;
  uint8_t messageId = 0;
  uint8_t fragmentIndex = 0;
  uint8_t fragmentCount = 0;
  const uint8_t* payload = nullptr;
  uint8_t payloadLength = 0;
};

struct DataFrameView {
  uint8_t stream = MANIFEST_STREAM;
  uint32_t offset = 0;
  const uint8_t* data = nullptr;
  uint8_t length = 0;
  uint16_t crc = 0;
};

inline uint16_t readLittle16(const uint8_t* value) {
  return static_cast<uint16_t>(value[0]) | static_cast<uint16_t>(value[1]) << 8;
}

inline uint32_t readLittle32(const uint8_t* value) {
  return static_cast<uint32_t>(value[0]) | static_cast<uint32_t>(value[1]) << 8 |
         static_cast<uint32_t>(value[2]) << 16 | static_cast<uint32_t>(value[3]) << 24;
}

inline uint64_t readLittle64(const uint8_t* value) {
  return static_cast<uint64_t>(readLittle32(value)) |
         static_cast<uint64_t>(readLittle32(value + 4)) << 32;
}

inline void writeLittle16(uint8_t* output, const uint16_t value) {
  output[0] = static_cast<uint8_t>(value);
  output[1] = static_cast<uint8_t>(value >> 8);
}

inline void writeLittle32(uint8_t* output, const uint32_t value) {
  output[0] = static_cast<uint8_t>(value);
  output[1] = static_cast<uint8_t>(value >> 8);
  output[2] = static_cast<uint8_t>(value >> 16);
  output[3] = static_cast<uint8_t>(value >> 24);
}

inline void writeLittle64(uint8_t* output, const uint64_t value) {
  writeLittle32(output, static_cast<uint32_t>(value));
  writeLittle32(output + 4, static_cast<uint32_t>(value >> 32));
}

inline constexpr uint16_t capabilityFlags() {
  return CAP_RESUME | CAP_ATOMIC_V1_V2 | CAP_HMAC_CONTROL | CAP_QUERY_STATE | CAP_GENERIC_KINDS;
}

inline constexpr uint16_t rendererKindFlags() {
  return RENDER_CARD | RENDER_TEXT | RENDER_IMAGE_1BIT | RENDER_EPUB | RENDER_ACTION | RENDER_SLEEP_SCREEN;
}

inline bool writeCapabilities(uint8_t* output, const size_t length, const uint8_t sessionNonce[16]) {
  if (!output || length != CAPABILITIES_BYTES || !sessionNonce) return false;
  std::memset(output, 0, length);
  output[0] = 0x58;  // X
  output[1] = 0x43;  // C
  output[2] = PROTOCOL_VERSION;
  output[3] = PROTOCOL_VERSION;
  writeLittle16(output + 4, capabilityFlags());
  output[6] = MAX_OBJECTS;
  writeLittle32(output + 7, static_cast<uint32_t>(MAX_MANIFEST_BYTES));
  writeLittle32(output + 11, MAX_OBJECT_BYTES);
  writeLittle32(output + 15, MAX_PACK_BYTES);
  output[19] = PREFERRED_CHUNK_BYTES;
  output[20] = DEVICE_MAX_CHUNK_BYTES;
  output[21] = WINDOW_CHUNKS;
  writeLittle16(output + 22, rendererKindFlags());
  std::memcpy(output + 24, sessionNonce, 16);
  return true;
}

inline bool writeStatusFrame(uint8_t* output, const size_t length, const Phase phase, const Result result,
                             const uint8_t stream, const uint8_t chunk, const uint32_t durableOffset,
                             const uint32_t sequence, const uint8_t packPrefix[4]) {
  if (!output || length != STATUS_BYTES || !packPrefix) return false;
  output[0] = 0x58;  // X
  output[1] = 0x53;  // S
  output[2] = PROTOCOL_VERSION;
  output[3] = static_cast<uint8_t>(phase);
  output[4] = static_cast<uint8_t>(result);
  output[5] = stream;
  output[6] = chunk;
  output[7] = WINDOW_CHUNKS;
  writeLittle32(output + 8, durableOffset);
  writeLittle32(output + 12, sequence);
  std::memcpy(output + 16, packPrefix, 4);
  return true;
}

inline constexpr bool shouldCheckpoint(const uint8_t chunksSinceCheckpoint, const uint32_t nextOffset,
                                       const uint32_t expectedBytes) {
  return chunksSinceCheckpoint >= WINDOW_CHUNKS || nextOffset == expectedBytes;
}

// Resume metadata describes only uncommitted staging bytes, so an impossible
// combination is safe to discard and retransmit from zero. A file longer than
// the durable offset is not corrupt: those uncheckpointed tail bytes are
// truncated by the store before resuming.
inline constexpr bool resumeStateRequiresReset(const bool offsetReadable, const uint32_t durableOffset,
                                                const uint32_t expectedBytes, const bool streamExists,
                                                const bool streamReadable, const uint64_t streamBytes) {
  return !offsetReadable || durableOffset > expectedBytes ||
         (!streamExists && durableOffset != 0) ||
         (streamExists && (!streamReadable || streamBytes < durableOffset));
}

inline constexpr bool validPlanOperationCount(const size_t count) { return count <= MAX_PLAN_OPERATIONS; }

inline constexpr bool validCommitProgress(const uint16_t next, const uint16_t operations) {
  return validPlanOperationCount(operations) && next <= operations;
}

// `next` is the first operation whose completion has not been durably
// checkpointed. Repeating it after power loss is safe because installs and
// deletes are idempotent; already checkpointed operations are skipped.
inline constexpr bool shouldApplyPlanOperation(const uint16_t operationIndex, const uint16_t next) {
  return operationIndex >= next;
}

inline uint16_t crc16CcittFalse(const uint8_t* data, const size_t length) {
  uint16_t crc = 0xffff;
  for (size_t index = 0; index < length; ++index) {
    crc ^= static_cast<uint16_t>(data[index]) << 8;
    for (uint8_t bit = 0; bit < 8; ++bit) {
      crc = (crc & 0x8000U) != 0 ? static_cast<uint16_t>((crc << 1) ^ 0x1021U)
                                : static_cast<uint16_t>(crc << 1);
    }
  }
  return crc;
}

inline bool parseControlFragment(const uint8_t* bytes, const size_t length, ControlFragmentView& output) {
  if (!bytes || length < CONTROL_FRAGMENT_HEADER_BYTES || bytes[0] != 0xc1 ||
      bytes[1] != PROTOCOL_VERSION || bytes[5] == 0 || bytes[5] > MAX_CONTROL_FRAGMENTS ||
      bytes[4] >= bytes[5] || bytes[6] != length - CONTROL_FRAGMENT_HEADER_BYTES) {
    return false;
  }
  const auto opcode = static_cast<Opcode>(bytes[2]);
  if (opcode < Opcode::Enroll || opcode > Opcode::Abort) return false;
  output.opcode = opcode;
  output.messageId = bytes[3];
  output.fragmentIndex = bytes[4];
  output.fragmentCount = bytes[5];
  output.payloadLength = bytes[6];
  output.payload = bytes + CONTROL_FRAGMENT_HEADER_BYTES;
  return true;
}

inline bool parseDataFrame(const uint8_t* bytes, const size_t length, DataFrameView& output) {
  if (!bytes || length < DATA_HEADER_BYTES || bytes[0] != 0xd1 || bytes[1] != PROTOCOL_VERSION ||
      bytes[7] == 0 || bytes[7] > DEVICE_MAX_CHUNK_BYTES || length != DATA_HEADER_BYTES + bytes[7]) {
    return false;
  }
  if (bytes[2] != MANIFEST_STREAM && bytes[2] >= MAX_OBJECTS) return false;
  output.stream = bytes[2];
  output.offset = readLittle32(bytes + 3);
  output.length = bytes[7];
  output.crc = readLittle16(bytes + 8);
  output.data = bytes + DATA_HEADER_BYTES;
  return crc16CcittFalse(output.data, output.length) == output.crc;
}

inline uint8_t negotiateChunk(const uint16_t attMtu, const uint8_t requested) {
  if (attMtu <= 3U + DATA_HEADER_BYTES) return 0;
  const uint16_t mtuBound = attMtu - 3U - DATA_HEADER_BYTES;
  uint16_t result = requested == 0 ? PREFERRED_CHUNK_BYTES : requested;
  if (result > DEVICE_MAX_CHUNK_BYTES) result = DEVICE_MAX_CHUNK_BYTES;
  if (result > mtuBound) result = mtuBound;
  return static_cast<uint8_t>(result);
}

inline bool validPackBounds(const uint32_t manifestBytes, const uint8_t objectCount,
                            const uint32_t totalObjectBytes) {
  return manifestBytes > 0 && manifestBytes <= MAX_MANIFEST_BYTES && objectCount <= MAX_OBJECTS &&
         totalObjectBytes <= MAX_PACK_BYTES;
}

inline bool isPackId(const char* value) {
  if (!value || std::strlen(value) != 68 || std::memcmp(value, "ps1-", 4) != 0) return false;
  for (size_t index = 4; index < 68; ++index) {
    const char c = value[index];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
  }
  return true;
}

inline constexpr bool textEquals(const char* left, const char* right) {
  if (!left || !right) return false;
  size_t index = 0;
  while (left[index] != '\0' && right[index] != '\0') {
    if (left[index] != right[index]) return false;
    ++index;
  }
  return left[index] == right[index];
}

inline constexpr bool isKnownSourceStatus(const char* value) {
  return textEquals(value, "complete") || textEquals(value, "no_changes");
}

// V1 `complete` means the device-visible card set changed. That includes a
// cached task disappearing even when every returned card is unchanged.
inline constexpr bool validV1SourceTransition(const char* status, const uint8_t changedCards,
                                              const uint8_t cachedMask, const uint8_t returnedMask) {
  if (!isKnownSourceStatus(status)) return false;
  const bool removedCachedTask = (cachedMask & static_cast<uint8_t>(~returnedMask)) != 0;
  const bool meaningfulChange = changedCards != 0 || removedCachedTask;
  return textEquals(status, "complete") == meaningfulChange;
}

// Cursor zero is always a full live-set snapshot. A snapshot may legitimately
// be empty while advancing to the ledger maximum, and never carries a
// tombstone. Non-zero cursors always use deltas with conventional no-change
// semantics.
inline constexpr bool validV2SourceTransition(const char* mode, const char* status,
                                              const uint8_t changeCount, const bool containsTombstone,
                                              const uint64_t fromCursor, const uint64_t toCursor,
                                              const uint64_t localCursor) {
  if (!mode || !isKnownSourceStatus(status) || fromCursor != localCursor || toCursor < fromCursor) {
    return false;
  }
  const bool complete = textEquals(status, "complete");
  if (textEquals(mode, "snapshot")) {
    if (fromCursor != 0 || localCursor != 0 || containsTombstone) return false;
    if (complete) return changeCount != 0 && toCursor > fromCursor;
    return changeCount == 0;  // toCursor may advance over historical tombstones.
  }
  if (!textEquals(mode, "delta") || fromCursor == 0) return false;
  if (complete) return changeCount != 0 && toCursor > fromCursor;
  return changeCount == 0 && toCursor == fromCursor;
}

inline constexpr bool constantTimeBytesEqual(const uint8_t* left, const uint8_t* right,
                                             const size_t length) {
  if (!left || !right) return false;
  uint8_t difference = 0;
  for (size_t index = 0; index < length; ++index) difference |= left[index] ^ right[index];
  return difference == 0;
}

// Enrollment is replayable only to recover a lost success indication. It must
// be the exact pending key and phone identity from the exact bonded peer; a
// mismatch never authorizes replacement of the persisted record.
inline constexpr bool enrollmentReplayMatches(const uint8_t storedKey[ENROLL_APP_KEY_BYTES],
                                              const uint8_t storedPhone[ENROLL_PHONE_ID_BYTES],
                                              const uint8_t storedPeer[BONDED_PEER_ID_BYTES],
                                              const uint8_t* suppliedPayload, const size_t suppliedLength,
                                              const uint8_t currentPeer[BONDED_PEER_ID_BYTES]) {
  return suppliedPayload && suppliedLength == ENROLL_PAYLOAD_BYTES &&
         constantTimeBytesEqual(storedKey, suppliedPayload, ENROLL_APP_KEY_BYTES) &&
         constantTimeBytesEqual(storedPhone, suppliedPayload + ENROLL_APP_KEY_BYTES,
                                ENROLL_PHONE_ID_BYTES) &&
         constantTimeBytesEqual(storedPeer, currentPeer, BONDED_PEER_ID_BYTES);
}

}  // namespace xtinct::pocket_sync
