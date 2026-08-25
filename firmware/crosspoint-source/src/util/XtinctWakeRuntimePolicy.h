#pragma once

#include <cstdint>

namespace xtinct::wake_runtime {

// The persisted request is consent. Credential readiness is an independent,
// fail-closed execution prerequisite and must never rewrite that consent.
constexpr bool isEffectiveAutoSyncEnabled(const bool requested, const bool credentialReady) {
  return requested && credentialReady;
}

// Diagnostic wakes are deliberately excluded from the ordinary transient
// retry loop. A normal scheduled wake retains the existing bounded retry
// behavior while the current count is below its ceiling.
constexpr bool shouldScheduleRetry(const bool allowScheduledRetries, const bool transientFailure,
                                   const uint8_t currentRetryCount, const uint8_t maximumRetries) {
  return allowScheduledRetries && transientFailure && currentRetryCount < maximumRetries;
}

}  // namespace xtinct::wake_runtime
