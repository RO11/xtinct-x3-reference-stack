#include <gtest/gtest.h>

#include <array>
#include <cstring>

// HalStorage.h exposes this legacy macro before the contract in production.
// Keep the host gate reproducing that include-order collision.
#define Storage HalStorage__getInstance_macro_collision
#include "src/util/PocketSyncContract.h"
#undef Storage

using namespace xtinct::pocket_sync;

TEST(PocketSyncContract, PinsCloudBounds) {
  EXPECT_EQ(MAX_MANIFEST_BYTES, 65536U);
  EXPECT_EQ(MAX_OBJECTS, 68);
  EXPECT_EQ(MAX_OBJECT_BYTES, 20U * 1024U * 1024U);
  EXPECT_EQ(MAX_PACK_BYTES, 64U * 1024U * 1024U);
  EXPECT_EQ(static_cast<uint8_t>(Result::StorageError), 7);
  EXPECT_TRUE(validPackBounds(65536, 68, 67108864));
  EXPECT_FALSE(validPackBounds(65537, 68, 1));
  EXPECT_FALSE(validPackBounds(1, 69, 1));
  EXPECT_EQ(MAX_PLAN_OPERATIONS, 203);
  EXPECT_TRUE(validPlanOperationCount(MAX_PLAN_OPERATIONS));
  EXPECT_FALSE(validPlanOperationCount(MAX_PLAN_OPERATIONS + 1U));
}

TEST(PocketSyncContract, StartBoundsCountObjectBytesSeparatelyAndPermitObjectlessPacks) {
  // START knows only the aggregate object ledger. An objectless no-change pack
  // is valid, and the 64 KiB manifest is not charged to the separate 64 MiB
  // object-byte ceiling. Semantic seal later rejects inconsistent count/bytes.
  EXPECT_TRUE(validPackBounds(MAX_MANIFEST_BYTES, 0, 0));
  EXPECT_TRUE(validPackBounds(MAX_MANIFEST_BYTES, MAX_OBJECTS, MAX_PACK_BYTES));
  EXPECT_TRUE(validPackBounds(1, 0, 1));
  EXPECT_FALSE(validPackBounds(0, 0, 0));
  EXPECT_FALSE(validPackBounds(MAX_MANIFEST_BYTES + 1U, 0, 0));
  EXPECT_FALSE(validPackBounds(1, MAX_OBJECTS + 1U, 0));
  EXPECT_FALSE(validPackBounds(1, 0, MAX_PACK_BYTES + 1U));
}

TEST(PocketSyncContract, RejectsOversizedOrEmptyProtectedMetadataBeforeAllocation) {
  EXPECT_TRUE(validBoundedTextFileSize(10, 10));
  EXPECT_TRUE(validBoundedTextFileSize(512, 512));
  EXPECT_TRUE(validBoundedTextFileSize(4096, 4096));
  EXPECT_FALSE(validBoundedTextFileSize(0, 4096));
  EXPECT_FALSE(validBoundedTextFileSize(11, 10));
  EXPECT_FALSE(validBoundedTextFileSize(513, 512));
  EXPECT_FALSE(validBoundedTextFileSize(4097, 4096));
  EXPECT_FALSE(validBoundedTextFileSize(UINT64_MAX, 4096));
}

TEST(PocketSyncContract, ParsesCompactDataAtDefaultMtu) {
  std::array<uint8_t, DATA_HEADER_BYTES + 10> frame{};
  frame[0] = 0xd1;
  frame[1] = 1;
  frame[2] = MANIFEST_STREAM;
  writeLittle32(frame.data() + 3, 42);
  frame[7] = 10;
  std::memcpy(frame.data() + DATA_HEADER_BYTES, "0123456789", 10);
  writeLittle16(frame.data() + 8, crc16CcittFalse(frame.data() + DATA_HEADER_BYTES, 10));
  DataFrameView parsed;
  EXPECT_TRUE(parseDataFrame(frame.data(), frame.size(), parsed));
  EXPECT_EQ(parsed.offset, 42U);
  EXPECT_EQ(parsed.length, 10);
  EXPECT_EQ(negotiateChunk(23, 220), 10);
}

TEST(PocketSyncContract, RejectsCorruptDataAndUnknownStreams) {
  std::array<uint8_t, DATA_HEADER_BYTES + 1> frame{0xd1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 'x'};
  writeLittle16(frame.data() + 8, crc16CcittFalse(frame.data() + DATA_HEADER_BYTES, 1));
  DataFrameView parsed;
  EXPECT_TRUE(parseDataFrame(frame.data(), frame.size(), parsed));
  frame.back() = 'y';
  EXPECT_FALSE(parseDataFrame(frame.data(), frame.size(), parsed));
  frame.back() = 'x';
  frame[2] = MAX_OBJECTS;
  EXPECT_FALSE(parseDataFrame(frame.data(), frame.size(), parsed));
}

TEST(PocketSyncContract, ParsesFragmentedControlEnvelope) {
  const uint8_t frame[] = {0xc1, 1, static_cast<uint8_t>(Opcode::Start), 7, 1, 3, 2, 0xaa, 0xbb};
  ControlFragmentView parsed;
  EXPECT_TRUE(parseControlFragment(frame, sizeof(frame), parsed));
  EXPECT_EQ(parsed.messageId, 7);
  EXPECT_EQ(parsed.fragmentIndex, 1);
  EXPECT_EQ(parsed.fragmentCount, 3);
  EXPECT_EQ(parsed.payloadLength, 2);
}

TEST(PocketSyncContract, RejectsMalformedControlEnvelopeBounds) {
  ControlFragmentView parsed;
  const uint8_t zeroFragments[] = {0xc1, 1, static_cast<uint8_t>(Opcode::Start), 7, 0, 0, 0};
  EXPECT_FALSE(parseControlFragment(zeroFragments, sizeof(zeroFragments), parsed));
  const uint8_t indexPastCount[] = {0xc1, 1, static_cast<uint8_t>(Opcode::Start), 7, 1, 1, 0};
  EXPECT_FALSE(parseControlFragment(indexPastCount, sizeof(indexPastCount), parsed));
  const uint8_t lengthMismatch[] = {0xc1, 1, static_cast<uint8_t>(Opcode::Start), 7, 0, 1, 2, 0xaa};
  EXPECT_FALSE(parseControlFragment(lengthMismatch, sizeof(lengthMismatch), parsed));
  const uint8_t unknownOpcode[] = {0xc1, 1, 0xff, 7, 0, 1, 0};
  EXPECT_FALSE(parseControlFragment(unknownOpcode, sizeof(unknownOpcode), parsed));
  const uint8_t tooManyFragments[] = {
      0xc1, 1, static_cast<uint8_t>(Opcode::Start), 7, 0,
      static_cast<uint8_t>(MAX_CONTROL_FRAGMENTS + 1U), 0};
  EXPECT_FALSE(parseControlFragment(tooManyFragments, sizeof(tooManyFragments), parsed));
}

TEST(PocketSyncContract, RejectsZeroAndOversizedDataPayloadsBeforeStoreDispatch) {
  DataFrameView parsed;
  const uint8_t empty[] = {0xd1, 1, MANIFEST_STREAM, 0, 0, 0, 0, 0, 0, 0};
  EXPECT_FALSE(parseDataFrame(empty, sizeof(empty), parsed));
  std::array<uint8_t, DATA_HEADER_BYTES + DEVICE_MAX_CHUNK_BYTES + 1U> oversized{};
  oversized[0] = 0xd1;
  oversized[1] = 1;
  oversized[2] = MANIFEST_STREAM;
  oversized[7] = static_cast<uint8_t>(DEVICE_MAX_CHUNK_BYTES + 1U);
  EXPECT_FALSE(parseDataFrame(oversized.data(), oversized.size(), parsed));
}

TEST(PocketSyncContract, QueuesStartAfterFinalQueryAckUntilOldResponseIsRetired) {
  // Interleaving A: Android receives QUERY's final indication and writes START
  // before NimBLE delivers onStatus(EDONE) to the server.
  auto response = ControlResponseState::InFlight;
  EXPECT_TRUE(canQueueControlRequest(false, response, true));
  EXPECT_FALSE(canDispatchControlRequest(true, response));

  // Interleaving B: onStatus(EDONE) runs, but the activity/main loop has not
  // yet retired the old response. The one queued START still cannot dispatch.
  response = ControlResponseState::FinalAcknowledged;
  EXPECT_TRUE(canQueueControlRequest(false, response, true));
  EXPECT_FALSE(canDispatchControlRequest(true, response));
  response = ControlResponseState::Idle;
  EXPECT_TRUE(canDispatchControlRequest(true, response));
}

TEST(PocketSyncContract, NonFinalOrUnacknowledgedResponseRemainsFailClosed) {
  // Ordered multi-fragment responses do not open the next control turn after
  // an intermediate ACK, and a second already-queued request is never accepted.
  EXPECT_FALSE(canQueueControlRequest(false, ControlResponseState::InFlight, false));
  EXPECT_FALSE(canQueueControlRequest(true, ControlResponseState::InFlight, true));
  EXPECT_FALSE(canQueueControlRequest(true, ControlResponseState::FinalAcknowledged, true));
  EXPECT_FALSE(canDispatchControlRequest(true, ControlResponseState::InFlight));
  EXPECT_FALSE(canDispatchControlRequest(false, ControlResponseState::Idle));

  // A fully buffered request without the final indication ACK is retained but
  // never authenticated or dispatched; indication/supervision failure closes it.
  EXPECT_FALSE(canDispatchControlRequest(true, ControlResponseState::InFlight));
}

TEST(PocketSyncContract, DispatchOwnershipClosesTheDequeueToResponseGap) {
  EXPECT_TRUE(canDispatchControlRequest(true, ControlResponseState::Idle));
  EXPECT_FALSE(canQueueControlRequest(false, ControlResponseState::Dispatching, false));
  EXPECT_FALSE(canQueueControlRequest(false, ControlResponseState::Dispatching, true));
  EXPECT_FALSE(canDispatchControlRequest(false, ControlResponseState::Dispatching));
}

TEST(PocketSyncContract, ClosingLatchRejectsIndicationFailureAndDuplicateWork) {
  // Non-EDONE / missing-ACK completion transitions the live response to the
  // latched Closing state rather than reopening Idle.
  auto response = responseStateAfterIndication(ControlResponseState::InFlight, true, false);
  EXPECT_EQ(response, ControlResponseState::Closing);
  EXPECT_FALSE(canQueueControlRequest(false, response, true));
  EXPECT_FALSE(canDispatchControlRequest(true, response));
  EXPECT_FALSE(canAcceptDataFrame(true, response));

  // An intermediate ACK preserves InFlight and therefore cannot dispatch a
  // buffered next request. Only the final acknowledged frame may retire later.
  response = responseStateAfterIndication(ControlResponseState::InFlight, false, true);
  EXPECT_EQ(response, ControlResponseState::InFlight);
  EXPECT_FALSE(canDispatchControlRequest(true, response));

  // For a final ACK the callback publishes this state before it publishes
  // EDONE. A main-loop observer of EDONE therefore cannot see stale InFlight.
  response = responseStateAfterIndication(ControlResponseState::InFlight, true, true);
  EXPECT_EQ(response, ControlResponseState::FinalAcknowledged);
  EXPECT_FALSE(canDispatchControlRequest(true, response));

  // A duplicate received while the first request owns Dispatching also closes;
  // neither the duplicate nor any already-buffered request can run meanwhile.
  EXPECT_FALSE(canQueueControlRequest(false, ControlResponseState::Dispatching, true));
  response = ControlResponseState::Closing;
  EXPECT_FALSE(canQueueControlRequest(true, response, true));
  EXPECT_FALSE(canDispatchControlRequest(true, response));
}

TEST(PocketSyncContract, AssemblyTimeoutPolicyIsStrictAndWrapSafe) {
  EXPECT_FALSE(controlAssemblyExpired(0, 6000, 5000));
  EXPECT_FALSE(controlAssemblyExpired(100, 5100, 5000));
  EXPECT_TRUE(controlAssemblyExpired(100, 5101, 5000));
  EXPECT_TRUE(controlAssemblyExpired(0xfffffff0U, 0x00000020U, 32U));
}

TEST(PocketSyncContract, PinsReplaySafePackIdentity) {
  std::string valid = "ps1-" + std::string(64, 'a');
  EXPECT_TRUE(isPackId(valid.c_str()));
  valid[4] = 'A';
  EXPECT_FALSE(isPackId(valid.c_str()));
  EXPECT_TRUE(isKnownSourceStatus("complete"));
  EXPECT_TRUE(isKnownSourceStatus("no_changes"));
  EXPECT_FALSE(isKnownSourceStatus("partial"));
}

TEST(PocketSyncContract, EmitsGoldenCapabilitiesAndStatus) {
  const uint8_t nonce[16] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
                             0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff};
  const uint8_t expectedCapabilities[CAPABILITIES_BYTES] = {
      0x58, 0x43, 0x01, 0x01, 0x1f, 0x00, 0x44, 0x00, 0x00, 0x01, 0x00,
      0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00, 0x04, 0xdc, 0xea, 0x04,
      0x3f, 0x00, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8,
      0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff, 0x00, 0x00, 0x00};
  uint8_t capabilities[CAPABILITIES_BYTES];
  ASSERT_TRUE(writeCapabilities(capabilities, sizeof(capabilities), nonce));
  EXPECT_EQ(std::memcmp(capabilities, expectedCapabilities, sizeof(capabilities)), 0);

  const uint8_t prefix[4] = {0xaa, 0xbb, 0xcc, 0xdd};
  const uint8_t expectedStatus[STATUS_BYTES] = {0x58, 0x53, 0x01, 0x03, 0x00, 0xff, 0x0a,
                                                0x04, 0x2a, 0x00, 0x00, 0x00, 0x07, 0x00,
                                                0x00, 0x00, 0xaa, 0xbb, 0xcc, 0xdd};
  uint8_t status[STATUS_BYTES];
  ASSERT_TRUE(writeStatusFrame(status, sizeof(status), Phase::Objects, Result::Ok, MANIFEST_STREAM, 10, 42, 7,
                               prefix));
  EXPECT_EQ(std::memcmp(status, expectedStatus, sizeof(status)), 0);
}

TEST(PocketSyncContract, CheckpointsOnlyAtDurableWindowOrStreamEnd) {
  EXPECT_FALSE(shouldCheckpoint(1, 10, 100));
  EXPECT_FALSE(shouldCheckpoint(3, 30, 100));
  EXPECT_TRUE(shouldCheckpoint(4, 40, 100));
  EXPECT_TRUE(shouldCheckpoint(1, 100, 100));
}

TEST(PocketSyncContract, ResetsOrphanedOrCorruptResumeState) {
  EXPECT_TRUE(resumeStateRequiresReset(true, 40, 100, false, true, 0));
  EXPECT_TRUE(resumeStateRequiresReset(false, 0, 100, true, true, 40));
  EXPECT_TRUE(resumeStateRequiresReset(true, 101, 100, true, true, 101));
  EXPECT_TRUE(resumeStateRequiresReset(true, 40, 100, true, true, 39));
  EXPECT_TRUE(resumeStateRequiresReset(true, 40, 100, true, false, 0));
}

TEST(PocketSyncContract, PreservesValidResumeStateAndUncheckpointedTailPolicy) {
  EXPECT_FALSE(resumeStateRequiresReset(true, 0, 100, false, true, 0));
  EXPECT_FALSE(resumeStateRequiresReset(true, 40, 100, true, true, 40));
  EXPECT_FALSE(resumeStateRequiresReset(true, 40, 100, true, true, 55));
  EXPECT_FALSE(resumeStateRequiresReset(true, 100, 100, true, true, 100));
}

TEST(PocketSyncContract, TreatsRemovedCachedV1TaskAsMeaningfulChange) {
  EXPECT_TRUE(validV1SourceTransition("complete", 0, 0b0011, 0b0001));
  EXPECT_FALSE(validV1SourceTransition("no_changes", 0, 0b0011, 0b0001));
  EXPECT_TRUE(validV1SourceTransition("complete", 1, 0b0011, 0b0011));
  EXPECT_TRUE(validV1SourceTransition("no_changes", 0, 0b0011, 0b0011));
  EXPECT_FALSE(validV1SourceTransition("complete", 0, 0b0011, 0b0011));
}

TEST(PocketSyncContract, AcceptsEmptySnapshotCursorAdvanceAndPinsDeltaRules) {
  EXPECT_TRUE(validV2SourceTransition("snapshot", "no_changes", 0, false, 0, 15, 0));
  EXPECT_TRUE(validV2SourceTransition("snapshot", "complete", 1, false, 0, 15, 0));
  EXPECT_FALSE(validV2SourceTransition("snapshot", "complete", 0, false, 0, 15, 0));
  EXPECT_FALSE(validV2SourceTransition("snapshot", "no_changes", 0, true, 0, 15, 0));
  EXPECT_FALSE(validV2SourceTransition("snapshot", "no_changes", 0, false, 2, 15, 2));

  EXPECT_TRUE(validV2SourceTransition("delta", "no_changes", 0, false, 12, 12, 12));
  EXPECT_TRUE(validV2SourceTransition("delta", "complete", 1, true, 12, 15, 12));
  EXPECT_FALSE(validV2SourceTransition("delta", "no_changes", 0, false, 12, 15, 12));
  EXPECT_FALSE(validV2SourceTransition("delta", "complete", 0, false, 12, 15, 12));
  EXPECT_FALSE(validV2SourceTransition("delta", "no_changes", 0, false, 0, 0, 0));
}

TEST(PocketSyncContract, EnrollmentReplayRequiresExactKeyPhoneAndBondedPeer) {
  std::array<uint8_t, ENROLL_APP_KEY_BYTES> key{};
  std::array<uint8_t, ENROLL_PHONE_ID_BYTES> phone{};
  std::array<uint8_t, BONDED_PEER_ID_BYTES> peer{};
  std::array<uint8_t, ENROLL_PAYLOAD_BYTES> payload{};
  for (size_t index = 0; index < key.size(); ++index) key[index] = static_cast<uint8_t>(index + 1);
  for (size_t index = 0; index < phone.size(); ++index) phone[index] = static_cast<uint8_t>(0x80U + index);
  for (size_t index = 0; index < peer.size(); ++index) peer[index] = static_cast<uint8_t>(0x20U + index);
  std::memcpy(payload.data(), key.data(), key.size());
  std::memcpy(payload.data() + key.size(), phone.data(), phone.size());

  EXPECT_TRUE(enrollmentReplayMatches(key.data(), phone.data(), peer.data(), payload.data(), payload.size(),
                                      peer.data()));
  payload[0] ^= 1;
  EXPECT_FALSE(enrollmentReplayMatches(key.data(), phone.data(), peer.data(), payload.data(), payload.size(),
                                       peer.data()));
  payload[0] ^= 1;
  payload[key.size()] ^= 1;
  EXPECT_FALSE(enrollmentReplayMatches(key.data(), phone.data(), peer.data(), payload.data(), payload.size(),
                                       peer.data()));
  payload[key.size()] ^= 1;
  auto otherPeer = peer;
  otherPeer.back() ^= 1;
  EXPECT_FALSE(enrollmentReplayMatches(key.data(), phone.data(), peer.data(), payload.data(), payload.size(),
                                       otherPeer.data()));
  EXPECT_FALSE(enrollmentReplayMatches(key.data(), phone.data(), peer.data(), payload.data(), payload.size() - 1,
                                       peer.data()));
}

TEST(PocketSyncContract, InterruptedApplyResumesOnlyUncheckpointedOperations) {
  constexpr uint16_t interruptedNext = 97;
  EXPECT_TRUE(validCommitProgress(interruptedNext, MAX_PLAN_OPERATIONS));
  EXPECT_FALSE(shouldApplyPlanOperation(interruptedNext - 1, interruptedNext));
  EXPECT_TRUE(shouldApplyPlanOperation(interruptedNext, interruptedNext));
  EXPECT_TRUE(shouldApplyPlanOperation(MAX_PLAN_OPERATIONS - 1, interruptedNext));
  EXPECT_TRUE(validCommitProgress(MAX_PLAN_OPERATIONS, MAX_PLAN_OPERATIONS));
  EXPECT_FALSE(validCommitProgress(MAX_PLAN_OPERATIONS + 1U, MAX_PLAN_OPERATIONS));
}
