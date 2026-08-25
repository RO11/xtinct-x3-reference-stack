#include <cstdint>

// Production includes HalStorage.h first, which defines this legacy macro.
// The release gate compiles this file with the ESP32-C3 RISC-V compiler so a
// future contract identifier cannot silently collide with it again.
#define Storage HalStorage__getInstance_macro_collision
#include "src/util/PocketSyncContract.h"
#undef Storage

using namespace xtinct::pocket_sync;

static_assert(static_cast<uint8_t>(Result::StorageError) == 7);
static_assert(resumeStateRequiresReset(true, 40, 100, false, true, 0));
static_assert(resumeStateRequiresReset(true, 40, 100, true, true, 39));
static_assert(!resumeStateRequiresReset(true, 40, 100, true, true, 40));
static_assert(!resumeStateRequiresReset(true, 40, 100, true, true, 55));
static_assert(MAX_PLAN_OPERATIONS == 203);
static_assert(validPlanOperationCount(MAX_PLAN_OPERATIONS));
static_assert(!validPlanOperationCount(MAX_PLAN_OPERATIONS + 1U));
static_assert(validCommitProgress(97, MAX_PLAN_OPERATIONS));
static_assert(!shouldApplyPlanOperation(96, 97));
static_assert(shouldApplyPlanOperation(97, 97));
static_assert(validV1SourceTransition("complete", 0, 0b0011, 0b0001));
static_assert(!validV1SourceTransition("no_changes", 0, 0b0011, 0b0001));
static_assert(validV2SourceTransition("snapshot", "no_changes", 0, false, 0, 15, 0));
static_assert(!validV2SourceTransition("snapshot", "complete", 0, false, 0, 15, 0));
static_assert(validV2SourceTransition("delta", "complete", 1, true, 12, 15, 12));
static_assert(!validV2SourceTransition("delta", "no_changes", 0, false, 12, 15, 12));
// Final QUERY indication delivered -> START write before onStatus(EDONE).
static_assert(canQueueControlRequest(false, ControlResponseState::InFlight, true));
static_assert(!canDispatchControlRequest(true, ControlResponseState::InFlight));
// onStatus(EDONE) -> START write before the activity loop retires QUERY.
static_assert(canQueueControlRequest(false, ControlResponseState::FinalAcknowledged, true));
static_assert(!canDispatchControlRequest(true, ControlResponseState::FinalAcknowledged));
// Only retirement to Idle permits authenticated dispatch.
static_assert(canDispatchControlRequest(true, ControlResponseState::Idle));
// Intermediate fragment, duplicate/overflow and missing ACK remain fail closed.
static_assert(!canQueueControlRequest(false, ControlResponseState::InFlight, false));
static_assert(!canQueueControlRequest(true, ControlResponseState::InFlight, true));
static_assert(!canQueueControlRequest(true, ControlResponseState::FinalAcknowledged, true));
// Dequeue atomically claims Dispatching before controlReady is cleared.
static_assert(!canQueueControlRequest(false, ControlResponseState::Dispatching, false));
static_assert(!canQueueControlRequest(false, ControlResponseState::Dispatching, true));
static_assert(!canDispatchControlRequest(false, ControlResponseState::Dispatching));
// An indication error or duplicate request latches Closing. Even a previously
// buffered request cannot dispatch, and no additional fragment can enter.
static_assert(!canQueueControlRequest(false, ControlResponseState::Closing, true));
static_assert(!canQueueControlRequest(true, ControlResponseState::Closing, true));
static_assert(!canDispatchControlRequest(true, ControlResponseState::Closing));
static_assert(!canAcceptDataFrame(true, ControlResponseState::Closing));
static_assert(!canAcceptDataFrame(false, ControlResponseState::Idle));
static_assert(canAcceptDataFrame(true, ControlResponseState::Idle));
static_assert(responseStateAfterIndication(ControlResponseState::InFlight, true, false) ==
              ControlResponseState::Closing);
static_assert(responseStateAfterIndication(ControlResponseState::InFlight, false, true) ==
              ControlResponseState::InFlight);
static_assert(responseStateAfterIndication(ControlResponseState::InFlight, true, true) ==
              ControlResponseState::FinalAcknowledged);
// Timeout reads and callback writes share the same critical section; the pure
// policy retains unsigned millis wrap behavior and a strict boundary.
static_assert(!controlAssemblyExpired(100, 5100, 5000));
static_assert(controlAssemblyExpired(100, 5101, 5000));
static_assert(controlAssemblyExpired(0xfffffff0U, 0x00000020U, 32U));

constexpr uint8_t ENROLL_KEY[ENROLL_APP_KEY_BYTES] = {};
constexpr uint8_t ENROLL_PHONE[ENROLL_PHONE_ID_BYTES] = {};
constexpr uint8_t ENROLL_PEER[BONDED_PEER_ID_BYTES] = {};
constexpr uint8_t ENROLL_PAYLOAD[ENROLL_PAYLOAD_BYTES] = {};
constexpr uint8_t OTHER_PEER[BONDED_PEER_ID_BYTES] = {1};
static_assert(enrollmentReplayMatches(ENROLL_KEY, ENROLL_PHONE, ENROLL_PEER, ENROLL_PAYLOAD,
                                     sizeof(ENROLL_PAYLOAD), ENROLL_PEER));
static_assert(!enrollmentReplayMatches(ENROLL_KEY, ENROLL_PHONE, ENROLL_PEER, ENROLL_PAYLOAD,
                                      sizeof(ENROLL_PAYLOAD), OTHER_PEER));

int pocketSyncContractSyntaxProbe() { return static_cast<int>(MAX_OBJECTS); }
