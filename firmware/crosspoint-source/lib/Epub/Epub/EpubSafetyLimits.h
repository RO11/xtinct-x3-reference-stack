#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <new>
#include <string>
#include <string_view>
#include <stdexcept>
#include <type_traits>
#include <utility>
#include <vector>

#if !defined(__cpp_exceptions)
#error "EPUB allocation safety requires effective C++ exception support"
#endif

#if __has_include(<esp_heap_caps.h>)
#include <esp_heap_caps.h>
#define EPUB_HAS_HEAP_CAPS 1
#else
#define EPUB_HAS_HEAP_CAPS 0
#endif

namespace epub::limits {

// The X3 has roughly 380 KiB of working heap. These limits are deliberately
// above known large omnibus books (1,732 spines) while preventing untrusted
// EPUB metadata from driving multi-megabyte container allocations.
// 4,096 is more than twice the largest verified omnibus (1,732 manifest/spine
// entries). Keeping the manifest bound at the same order as the spine avoids a
// hostile OPF consuming most of DRAM in the idref lookup index alone.
constexpr size_t MAX_MANIFEST_ITEMS = 4096;
constexpr size_t MAX_SPINE_ITEMS = 4096;
constexpr size_t MAX_TOC_ITEMS = 8192;

constexpr size_t MAX_ITEM_ID_BYTES = 512;
constexpr size_t MAX_HREF_BYTES = 2048;
constexpr size_t MAX_TITLE_BYTES = 2048;
constexpr size_t MAX_AUTHOR_BYTES = 2048;
constexpr size_t MAX_LANGUAGE_BYTES = 64;
constexpr size_t MAX_ANCHOR_BYTES = 1024;
constexpr size_t MAX_METADATA_TEXT_BYTES = 4096;
constexpr size_t MAX_CSS_FILES = 64;
// CSS path storage remains resident after the OPF parser is destroyed. Count
// alone was not a useful X3 bound because 64 legal 2 KiB hrefs retained over
// 128 KiB once string/vector slack was included.
constexpr size_t MAX_CSS_HREF_BYTES = 24U * 1024U;
constexpr size_t MAX_CSS_RULES = 512;
constexpr size_t MAX_RETAINED_CSS_RULE_BYTES = 80U * 1024U;
// 32-bit node estimate: CssStyle (~100 B), std::string object, unordered-map
// links/bucket share and allocator metadata. Selector payload is added exactly.
constexpr size_t RETAINED_CSS_RULE_FIXED_BYTES = 144;
constexpr size_t MAX_CONTAINER_XML_BYTES = 64U * 1024U;
constexpr size_t MAX_EPUB_RESOURCE_BYTES = 20U * 1024U * 1024U;
constexpr size_t MAX_IN_MEMORY_RESOURCE_BYTES = 256U * 1024U;
constexpr size_t MAX_COVER_WRAPPER_BYTES = 64U * 1024U;

// A normal 20 MiB EPUB is composed of many much smaller XHTML resources. A
// 16 MiB inflated single spine remains usable through the streaming parser,
// while rejecting ZIP bombs before they write an oversized HTML cache.
constexpr size_t MAX_INFLATED_SPINE_BYTES = 16U * 1024U * 1024U;

// Soft layout flushes normally keep a paragraph below 750 tokens. The hard cap
// covers the worst 1 KiB Expat callback burst (CJK/focus splitting included)
// without permitting arbitrary deque/vector growth.
constexpr size_t MAX_PARAGRAPH_TOKENS = 2048;
// A token-only count is not a memory bound: 2,048 legal 1 KiB tokens retain
// roughly 2 MiB on a device with ~380 KiB total working heap. Keep the live
// paragraph to about one quarter of that heap. The fixed charges are deliberately
// conservative for 32-bit libstdc++: word/ruby string objects and deque slack,
// NUL storage, and up to 2x capacity slack in the style/flag/visible-offset
// parallel vectors are all covered in addition to the exact text payload.
constexpr size_t MAX_RETAINED_PARAGRAPH_BYTES = 96U * 1024U;
constexpr size_t RETAINED_TOKEN_FIXED_BYTES = 64;
constexpr size_t RETAINED_RUBY_SLOT_FIXED_BYTES = 32;
constexpr size_t MAX_TEXT_BLOCK_WORDS = 512;
constexpr size_t MAX_INPUT_WORD_BYTES = 1024;
constexpr size_t MAX_RUBY_TEXT_BYTES = 1024;
constexpr size_t MAX_RUBY_BYTES_PER_PARAGRAPH = 8192;
constexpr size_t MAX_EXPANDED_TEXT_BYTES_PER_SPINE = 32U * 1024U * 1024U;
constexpr size_t MAX_HTML_ELEMENT_DEPTH = 256;
constexpr size_t MAX_HTML_ATTRIBUTE_BYTES = 4096;
constexpr size_t MAX_TOC_DEPTH = 64;
constexpr size_t MAX_PAGE_ELEMENTS = 128;
constexpr size_t MAX_PAGE_LINE_ELEMENTS = 128;
constexpr size_t MAX_PAGE_IMAGE_ELEMENTS = 16;
constexpr size_t MAX_PAGE_RULE_ELEMENTS = 32;
constexpr size_t MAX_PAGES_PER_SPINE = 4096;
constexpr size_t MAX_SECTION_LUT_BYTES = 48U * 1024U;
constexpr size_t SECTION_LUT_ENTRY_BYTES = 12;
constexpr size_t MAX_SERIALIZED_PAGE_BYTES = 160U * 1024U;
constexpr size_t MAX_RETAINED_PAGE_BYTES = 112U * 1024U;
constexpr size_t MAX_PAGE_IMAGE_PATH_BYTES = 12U * 1024U;
constexpr size_t RETAINED_PAGE_ELEMENT_FIXED_BYTES = 64;
constexpr size_t RETAINED_TEXT_BLOCK_FIXED_BYTES = 96;
constexpr size_t RETAINED_IMAGE_BLOCK_FIXED_BYTES = 96;
constexpr size_t MAX_ANCHORS_PER_SPINE = 512;
constexpr size_t MAX_RETAINED_ANCHOR_BYTES = 48U * 1024U;
// During parsing, a moved TOC payload leaves one empty string object in the
// lookup vector and one owning string object in the emitted anchor pair. This
// charge covers both 32-bit objects, vector slack and allocator metadata; the
// payload itself is charged once.
constexpr size_t RETAINED_ANCHOR_FIXED_BYTES = 64;
constexpr size_t MAX_PENDING_FOOTNOTES = 64;
constexpr size_t MAX_PENDING_FOOTNOTE_BYTES = 12U * 1024U;
constexpr size_t MAX_STYLE_STACK_ENTRIES = 128;
constexpr size_t MAX_STYLE_STACK_BYTES = 16U * 1024U;
// A non-CSS paragraph is soft-flushed at ~750 tokens. The worst layout branch
// keeps several 32-bit std::string/vector views at once (ruby, BiDi and focus
// merge), so budget 112 bytes/token plus a small fixed working set. 96 KiB
// admits that normal flush while preventing a 2,048-token paragraph from
// materializing hundreds of KiB of parallel scratch.
constexpr size_t MAX_LAYOUT_SCRATCH_BYTES = 96U * 1024U;
// A rendered ruby line temporarily retains a shift array, one RubyDrawInfo per
// word and a single duplicate of each annotation payload. MAX_TEXT_BLOCK_WORDS
// (512) stays usable while the scratch remains a small fraction of X3 DRAM.
constexpr size_t MAX_RUBY_RENDER_SCRATCH_BYTES = 32U * 1024U;
constexpr size_t MAX_METADATA_BATCH_BYTES = 96U * 1024U;

// Leave room for Expat, the SD/ZIP stack, renderer state and the caller. The
// largest-block check prevents a reassuring total-free figure from masking a
// fragmented heap that cannot satisfy the imminent contiguous allocation.
constexpr size_t EPUB_HEAP_RESERVE_BYTES = 48U * 1024U;
constexpr size_t EPUB_LARGEST_BLOCK_RESERVE_BYTES = 4U * 1024U;

constexpr bool countCanGrow(const size_t current, const size_t additional, const size_t maximum) {
  return current <= maximum && additional <= maximum - current;
}

using AllocationProbe = bool (*)(size_t totalBytes, size_t largestBlockBytes);

// Tests install a deterministic probe so they exercise the production refusal
// path before a container/string/object commits any mutation. Production uses
// the ESP heap's total and largest-block views; non-ESP syntax tests accept.
inline AllocationProbe allocationProbeForTests = nullptr;

inline void setAllocationProbeForTests(const AllocationProbe probe) { allocationProbeForTests = probe; }

inline bool allocationPreflight(const size_t totalBytes, size_t largestBlockBytes = 0) {
  if (totalBytes == 0) return true;
  if (largestBlockBytes == 0) largestBlockBytes = totalBytes;
  if (allocationProbeForTests) {
    return allocationProbeForTests(totalBytes, largestBlockBytes);
  }
#if EPUB_HAS_HEAP_CAPS
  const size_t freeBytes = heap_caps_get_free_size(MALLOC_CAP_8BIT);
  const size_t largest = heap_caps_get_largest_free_block(MALLOC_CAP_8BIT);
  const bool accepted = countCanGrow(totalBytes, EPUB_HEAP_RESERVE_BYTES, freeBytes) &&
                        countCanGrow(largestBlockBytes, EPUB_LARGEST_BLOCK_RESERVE_BYTES, largest);
  return accepted;
#else
  return true;
#endif
}

// The heap probe above is advisory: another task or allocator bookkeeping can
// still make the following STL allocation fail.  Production is built with
// exceptions so these helpers catch the allocator's real failure.  A build
// which accidentally loses -fexceptions refuses every growth operation rather
// than reintroducing the old abort-on-OOM behavior.
template <typename Operation>
bool catchAllocationFailure(Operation&& operation) noexcept {
#if defined(__cpp_exceptions)
  try {
    std::forward<Operation>(operation)();
    return true;
  } catch (const std::bad_alloc&) {
    return false;
  } catch (const std::length_error&) {
    return false;
  }
#else
  (void)operation;
  return false;
#endif
}

template <typename T>
bool checkedVectorReserve(std::vector<T>& values, const size_t count, const size_t maximumCount) {
  if (count > maximumCount) return false;
  if (count <= values.capacity()) return true;
  if (count > SIZE_MAX / sizeof(T)) return false;
  const size_t bytes = count * sizeof(T);
  if (!allocationPreflight(bytes, bytes)) return false;
  return catchAllocationFailure([&]() { values.reserve(count); }) && values.capacity() >= count;
}

template <typename T, typename U>
bool checkedVectorPushBack(std::vector<T>& values, U&& value, const size_t maximumCount) {
  if (values.size() >= maximumCount) return false;
  if (values.size() == values.capacity()) {
    const size_t wanted = values.size() + 1;
    size_t nextCapacity = values.capacity() == 0 ? 1 : values.capacity() * 2;
    if (nextCapacity < wanted || nextCapacity > maximumCount) nextCapacity = wanted;
    if (!checkedVectorReserve(values, nextCapacity, maximumCount)) return false;
  }
  // Forwarding keeps construction/copy inside the caught operation. In
  // particular, copying a string payload must not throw before this helper's
  // allocation boundary is active.
  return catchAllocationFailure([&]() { values.emplace_back(std::forward<U>(value)); });
}

template <typename T>
bool checkedVectorResize(std::vector<T>& values, const size_t count, const size_t maximumCount) {
  if (count > maximumCount || count > SIZE_MAX / sizeof(T)) return false;
  if (count > values.capacity() && !checkedVectorReserve(values, count, maximumCount)) return false;
  return catchAllocationFailure([&]() { values.resize(count); }) && values.size() == count;
}

template <typename T>
bool checkedDequeResize(std::deque<T>& values, const size_t count, const size_t maximumCount) {
  if (count > maximumCount || count > SIZE_MAX / sizeof(T)) return false;
  const size_t bytes = count * sizeof(T);
  if (!allocationPreflight(bytes, bytes < 4096 ? bytes : 4096)) return false;
  return catchAllocationFailure([&]() { values.resize(count); }) && values.size() == count;
}

template <typename T, typename U>
bool checkedDequePushBack(std::deque<T>& values, U&& value, const size_t maximumCount) {
  if (values.size() >= maximumCount) return false;
  // libstdc++ deques grow in small nodes plus an occasional pointer map. Charge
  // a conservative 2 KiB largest block without pretending the whole existing
  // deque is reallocated on every append.
  constexpr size_t growthBytes = sizeof(T) + 2048;
  if (!allocationPreflight(growthBytes, 2048)) return false;
  return catchAllocationFailure([&]() { values.emplace_back(std::forward<U>(value)); });
}

inline bool checkedStringAssign(std::string& target, const std::string_view value, const size_t maximumBytes) {
  if (value.size() > maximumBytes || value.size() == SIZE_MAX ||
      !allocationPreflight(value.size() + 1, value.size() + 1)) return false;
  std::string staged;
  if (!catchAllocationFailure([&]() { staged.assign(value.data(), value.size()); })) return false;
  target.swap(staged);
  return true;
}

inline bool checkedStringResize(std::string& target, const size_t count, const size_t maximumBytes) {
  if (count > maximumBytes || count == SIZE_MAX || !allocationPreflight(count + 1, count + 1)) return false;
  std::string staged;
  if (!catchAllocationFailure([&]() { staged.resize(count); })) return false;
  target.swap(staged);
  return true;
}

inline bool checkedStringAppend(std::string& target, const std::string_view value,
                                const size_t maximumBytes) {
  if (!countCanGrow(target.size(), value.size(), maximumBytes)) return false;
  const size_t wanted = target.size() + value.size();
  if (wanted == SIZE_MAX || !allocationPreflight(wanted + 1, wanted + 1)) return false;
  std::string staged;
  if (!catchAllocationFailure([&]() {
        staged.assign(target);
        staged.append(value.data(), value.size());
      })) {
    return false;
  }
  target.swap(staged);
  return true;
}

class RetainedStageBudget {
 public:
  constexpr explicit RetainedStageBudget(const size_t maximum) : maximum_(maximum) {}
  constexpr bool tryRetain(const size_t additional) {
    if (!countCanGrow(used_, additional, maximum_)) return false;
    used_ += additional;
    return true;
  }
  constexpr void release(const size_t bytes) { used_ = bytes >= used_ ? 0 : used_ - bytes; }
  constexpr void reset() { used_ = 0; }
  constexpr size_t used() const { return used_; }
  constexpr size_t remaining() const { return maximum_ - used_; }

 private:
  size_t maximum_;
  size_t used_ = 0;
};

constexpr size_t cssRuleRetainedBytes(const size_t selectorBytes) {
  return selectorBytes > SIZE_MAX - RETAINED_CSS_RULE_FIXED_BYTES - 1
             ? SIZE_MAX
             : selectorBytes + RETAINED_CSS_RULE_FIXED_BYTES + 1;
}

constexpr size_t anchorRetainedBytes(const size_t payloadBytes) {
  return payloadBytes > SIZE_MAX - RETAINED_ANCHOR_FIXED_BYTES - 1
             ? SIZE_MAX
             : payloadBytes + RETAINED_ANCHOR_FIXED_BYTES + 1;
}

using CssRuleBudget = RetainedStageBudget;
using AnchorBudget = RetainedStageBudget;
using PageBudget = RetainedStageBudget;

class PageDecodeBudget {
 public:
  explicit constexpr PageDecodeBudget(const size_t serializedBytes)
      : serializedRemaining_(serializedBytes), retained_(MAX_RETAINED_PAGE_BYTES) {}

  bool tryConsumeSerialized(const size_t bytes) {
    if (bytes > serializedRemaining_) return false;
    serializedRemaining_ -= bytes;
    return true;
  }
  bool tryRetain(const size_t bytes, const size_t largestBlock = 0) {
    if (bytes > retained_.remaining()) return false;
    if (!allocationPreflight(bytes, largestBlock == 0 ? bytes : largestBlock)) {
      resourceRefused_ = true;
      return false;
    }
    return retained_.tryRetain(bytes);
  }
  bool tryRetainImagePaths(const size_t bytes) {
    if (!countCanGrow(imagePathBytes_, bytes, MAX_PAGE_IMAGE_PATH_BYTES)) return false;
    imagePathBytes_ += bytes;
    return true;
  }
  bool tryNoteElement(const uint8_t kind) {
    if (elementCount_ >= MAX_PAGE_ELEMENTS) return false;
    size_t* counter = nullptr;
    size_t maximum = 0;
    if (kind == 0) {
      counter = &lineCount_;
      maximum = MAX_PAGE_LINE_ELEMENTS;
    } else if (kind == 1) {
      counter = &imageCount_;
      maximum = MAX_PAGE_IMAGE_ELEMENTS;
    } else if (kind == 2) {
      counter = &ruleCount_;
      maximum = MAX_PAGE_RULE_ELEMENTS;
    } else {
      return false;
    }
    if (*counter >= maximum) return false;
    ++*counter;
    ++elementCount_;
    return true;
  }
  constexpr size_t serializedRemaining() const { return serializedRemaining_; }
  constexpr size_t retainedBytes() const { return retained_.used(); }
  constexpr bool resourceRefused() const { return resourceRefused_; }

 private:
  size_t serializedRemaining_;
  RetainedStageBudget retained_;
  size_t imagePathBytes_ = 0;
  size_t elementCount_ = 0;
  size_t lineCount_ = 0;
  size_t imageCount_ = 0;
  size_t ruleCount_ = 0;
  bool resourceRefused_ = false;
};

// Page cache decode failures are deliberately split so a transient resource
// refusal never causes Reader to delete a valid committed/partial cache. Every
// page-decode allocation site propagates this explicit status; malformed or
// short serialized input remains InvalidData.
enum class PageDecodeFailure : uint8_t { None, ResourceRefused, InvalidData };

inline void markPageDecodeResourceRefusal(PageDecodeFailure* const failure) noexcept {
  if (failure) *failure = PageDecodeFailure::ResourceRefused;
}

constexpr bool inflatedSpineFits(const size_t bytes) { return bytes <= MAX_INFLATED_SPINE_BYTES; }

constexpr bool paragraphTokensFit(const size_t current, const size_t additional) {
  return countCanGrow(current, additional, MAX_PARAGRAPH_TOKENS);
}

constexpr size_t retainedTokenBytes(const size_t payloadBytes, const bool rubySlotsActive) {
  const size_t fixed = RETAINED_TOKEN_FIXED_BYTES +
                       (rubySlotsActive ? RETAINED_RUBY_SLOT_FIXED_BYTES : 0);
  return payloadBytes > SIZE_MAX - fixed ? SIZE_MAX : payloadBytes + fixed;
}

constexpr size_t retainedRubyPayloadBytes(const size_t payloadBytes) {
  // The ruby slot itself is charged separately when the dense ruby deque is
  // activated. Non-empty annotations retain their bytes plus a NUL.
  return payloadBytes == 0 ? 0 : (payloadBytes == SIZE_MAX ? SIZE_MAX : payloadBytes + 1);
}

class RetainedParagraphBudget {
 public:
  constexpr bool tryRetain(const size_t additional) {
    if (!countCanGrow(used_, additional, MAX_RETAINED_PARAGRAPH_BYTES)) return false;
    used_ += additional;
    return true;
  }

  constexpr void release(const size_t bytes) { used_ = bytes >= used_ ? 0 : used_ - bytes; }
  constexpr void reset() { used_ = 0; }
  constexpr size_t used() const { return used_; }
  constexpr size_t remaining() const { return MAX_RETAINED_PARAGRAPH_BYTES - used_; }

 private:
  size_t used_ = 0;
};

constexpr bool rubyTextFits(const size_t paragraphBytes, const size_t annotationBytes) {
  return annotationBytes <= MAX_RUBY_TEXT_BYTES &&
         countCanGrow(paragraphBytes, annotationBytes, MAX_RUBY_BYTES_PER_PARAGRAPH);
}

}  // namespace epub::limits
