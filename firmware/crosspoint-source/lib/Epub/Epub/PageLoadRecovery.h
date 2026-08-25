#pragma once

#include <cstdint>

namespace epub {

enum class PageLoadFailure : uint8_t { None, ResourceRefused, RestartRequired, Corrupt };
enum class PageLoadRecovery : uint8_t { None, PreserveCacheAndShowError, ReloadPreservedCache, ClearAndRebuild };

constexpr PageLoadRecovery pageLoadRecovery(const PageLoadFailure failure) noexcept {
  switch (failure) {
    case PageLoadFailure::None:
      return PageLoadRecovery::None;
    case PageLoadFailure::ResourceRefused:
      return PageLoadRecovery::PreserveCacheAndShowError;
    case PageLoadFailure::RestartRequired:
      return PageLoadRecovery::ReloadPreservedCache;
    case PageLoadFailure::Corrupt:
      return PageLoadRecovery::ClearAndRebuild;
  }
  return PageLoadRecovery::ClearAndRebuild;
}

}  // namespace epub
