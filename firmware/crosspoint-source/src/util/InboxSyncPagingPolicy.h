#pragma once

#include <cstddef>
#include <cstdint>

namespace xtinct::inbox_sync_paging {

// The cloud and Pocket contracts continue to support sixteen changes. Direct
// X3 Wi-Fi sync deliberately asks for eight so its response buffer, parsed JSON
// and fixed page copy can coexist on the ESP32-C3 heap.
constexpr size_t DIRECT_PAGE_CHANGES = 8;
constexpr uint8_t MAX_PAGES_PER_WAKE = 10;
constexpr size_t MAX_CHANGES_PER_WAKE = DIRECT_PAGE_CHANGES * MAX_PAGES_PER_WAKE;

// Eight worst-case delivery envelopes remain below 28 KiB: each allows the
// complete 2 KiB metadata object, a 120-byte title escaped to six JSON bytes
// per byte, and a conservative 640-byte allowance for fixed fields. The page
// envelope stays below the remaining 512 bytes. Tombstones are smaller.
constexpr size_t MAX_DIRECT_RESPONSE_BYTES = 28 * 1024;

constexpr size_t pagesRequired(const size_t changes) {
  return changes == 0 ? 0 : 1 + (changes - 1) / DIRECT_PAGE_CHANGES;
}

constexpr bool completesWithinOneWake(const size_t changes) {
  return pagesRequired(changes) <= MAX_PAGES_PER_WAKE;
}

static_assert(DIRECT_PAGE_CHANGES < 16);
static_assert(MAX_CHANGES_PER_WAKE == 80);
static_assert(pagesRequired(77) == 10);
static_assert(completesWithinOneWake(77));

}  // namespace xtinct::inbox_sync_paging
