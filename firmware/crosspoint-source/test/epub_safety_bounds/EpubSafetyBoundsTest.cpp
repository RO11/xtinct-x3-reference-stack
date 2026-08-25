#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <limits>
#include <new>
#include <string>
#include <vector>

#include "Epub/Epub/EpubSafetyLimits.h"
#include "Epub/Epub/Page.h"
#include "Epub/Epub/PageLoadRecovery.h"
#include "Epub/Epub/SectionReadTransaction.h"
#include "Serialization/SerializedLengthPolicy.h"
#include "expat.h"

namespace allocation_fault_test {
thread_local bool enabled = false;
thread_local size_t ordinal = 0;
thread_local size_t failOrdinal = 0;
}  // namespace allocation_fault_test

// Exercise the allocator's real exception path, not a second advisory heap
// probe.  The switch is thread-local and disabled while GoogleTest itself runs.
void* operator new(const std::size_t size) {
  if (allocation_fault_test::enabled &&
      ++allocation_fault_test::ordinal == allocation_fault_test::failOrdinal) {
    throw std::bad_alloc();
  }
  if (void* const value = std::malloc(size == 0 ? 1 : size)) return value;
  throw std::bad_alloc();
}

void* operator new[](const std::size_t size) { return ::operator new(size); }
void* operator new(const std::size_t size, const std::nothrow_t&) noexcept {
  try {
    return ::operator new(size);
  } catch (...) {
    return nullptr;
  }
}
void* operator new[](const std::size_t size, const std::nothrow_t&) noexcept {
  return ::operator new(size, std::nothrow);
}
void operator delete(void* const value) noexcept { std::free(value); }
void operator delete[](void* const value) noexcept { std::free(value); }
void operator delete(void* const value, std::size_t) noexcept { std::free(value); }
void operator delete[](void* const value, std::size_t) noexcept { std::free(value); }
void operator delete(void* const value, const std::nothrow_t&) noexcept { std::free(value); }
void operator delete[](void* const value, const std::nothrow_t&) noexcept { std::free(value); }

namespace {

bool rejectEveryAllocation(size_t, size_t) { return false; }
bool acceptEveryAllocation(size_t, size_t) { return true; }

class ScopedRealAllocationFailure final {
 public:
  explicit ScopedRealAllocationFailure(const size_t failOrdinal) {
    allocation_fault_test::ordinal = 0;
    allocation_fault_test::failOrdinal = failOrdinal;
    allocation_fault_test::enabled = true;
  }
  ~ScopedRealAllocationFailure() {
    allocation_fault_test::enabled = false;
    allocation_fault_test::failOrdinal = 0;
  }
  ScopedRealAllocationFailure(const ScopedRealAllocationFailure&) = delete;
  ScopedRealAllocationFailure& operator=(const ScopedRealAllocationFailure&) = delete;
};

class ScopedAllocationProbe final {
 public:
  explicit ScopedAllocationProbe(epub::limits::AllocationProbe probe) {
    epub::limits::setAllocationProbeForTests(probe);
  }
  ~ScopedAllocationProbe() { epub::limits::setAllocationProbeForTests(nullptr); }
  ScopedAllocationProbe(const ScopedAllocationProbe&) = delete;
  ScopedAllocationProbe& operator=(const ScopedAllocationProbe&) = delete;
};

struct ExpatAllocationCallbackState {
  XML_Parser parser = nullptr;
  bool callbackEntered = false;
  bool allocationFailureContained = false;
};

void XMLCALL allocationFaultingStartElement(void* const userData, const XML_Char*, const XML_Char**) {
  auto* const state = static_cast<ExpatAllocationCallbackState*>(userData);
  state->callbackEntered = true;
  if (!epub::limits::catchAllocationFailure([&]() {
        ScopedRealAllocationFailure failAfterCallbackPreflight(1);
        void* const forcedAllocation = ::operator new(512);
        ::operator delete(forcedAllocation);
      })) {
    state->allocationFailureContained = true;
    XML_StopParser(state->parser, XML_FALSE);
  }
}

}  // namespace

TEST(EpubSafetyBounds, TinyCompressedHugeSpineFailsBeforeInflation) {
  constexpr size_t tinyCompressedBytes = 64;
  (void)tinyCompressedBytes;
  EXPECT_TRUE(epub::limits::inflatedSpineFits(epub::limits::MAX_INFLATED_SPINE_BYTES));
  EXPECT_FALSE(epub::limits::inflatedSpineFits(epub::limits::MAX_INFLATED_SPINE_BYTES + 1));
  EXPECT_FALSE(epub::limits::inflatedSpineFits(512U * 1024U * 1024U));
}

TEST(EpubSafetyBounds, ManifestSpineAndTocCountsHaveExactBoundaries) {
  EXPECT_TRUE(epub::limits::countCanGrow(epub::limits::MAX_MANIFEST_ITEMS - 1, 1,
                                         epub::limits::MAX_MANIFEST_ITEMS));
  EXPECT_FALSE(epub::limits::countCanGrow(epub::limits::MAX_MANIFEST_ITEMS, 1,
                                          epub::limits::MAX_MANIFEST_ITEMS));
  EXPECT_TRUE(epub::limits::countCanGrow(epub::limits::MAX_SPINE_ITEMS - 1, 1,
                                         epub::limits::MAX_SPINE_ITEMS));
  EXPECT_FALSE(epub::limits::countCanGrow(epub::limits::MAX_SPINE_ITEMS, 1,
                                          epub::limits::MAX_SPINE_ITEMS));
  EXPECT_FALSE(epub::limits::countCanGrow(epub::limits::MAX_TOC_ITEMS, 1, epub::limits::MAX_TOC_ITEMS));
}

TEST(EpubSafetyBounds, SingleCallbackCannotOverflowParagraphTokenBudget) {
  EXPECT_TRUE(epub::limits::paragraphTokensFit(epub::limits::MAX_PARAGRAPH_TOKENS - 1024, 1024));
  EXPECT_FALSE(epub::limits::paragraphTokensFit(epub::limits::MAX_PARAGRAPH_TOKENS - 1023, 1024));
  EXPECT_FALSE(epub::limits::paragraphTokensFit(epub::limits::MAX_PARAGRAPH_TOKENS, 1));
}

TEST(EpubSafetyBounds, RubyHasPerAnnotationAndParagraphBudgets) {
  EXPECT_TRUE(epub::limits::rubyTextFits(0, epub::limits::MAX_RUBY_TEXT_BYTES));
  EXPECT_FALSE(epub::limits::rubyTextFits(0, epub::limits::MAX_RUBY_TEXT_BYTES + 1));
  EXPECT_TRUE(epub::limits::rubyTextFits(epub::limits::MAX_RUBY_BYTES_PER_PARAGRAPH - 1, 1));
  EXPECT_FALSE(epub::limits::rubyTextFits(epub::limits::MAX_RUBY_BYTES_PER_PARAGRAPH, 1));
}

TEST(EpubSafetyBounds, RetainedParagraphBudgetHasExactBoundaryAndRelease) {
  epub::limits::RetainedParagraphBudget budget;
  EXPECT_TRUE(budget.tryRetain(epub::limits::MAX_RETAINED_PARAGRAPH_BYTES));
  EXPECT_EQ(budget.remaining(), 0U);
  EXPECT_FALSE(budget.tryRetain(1));
  budget.release(epub::limits::MAX_RETAINED_PARAGRAPH_BYTES);
  EXPECT_EQ(budget.used(), 0U);
  EXPECT_TRUE(budget.tryRetain(1));
}

TEST(EpubSafetyBounds, ManyOneKiBTokensStopAtRetainedByteBudget) {
  epub::limits::RetainedParagraphBudget budget;
  constexpr size_t tokenBytes =
      epub::limits::retainedTokenBytes(epub::limits::MAX_INPUT_WORD_BYTES, false);
  size_t accepted = 0;
  while (budget.tryRetain(tokenBytes)) ++accepted;

  EXPECT_EQ(accepted, epub::limits::MAX_RETAINED_PARAGRAPH_BYTES / tokenBytes);
  EXPECT_LT(accepted, 100U);
  EXPECT_LT(accepted, epub::limits::MAX_PARAGRAPH_TOKENS);
  EXPECT_LE(budget.used(), epub::limits::MAX_RETAINED_PARAGRAPH_BYTES);
  EXPECT_LT(budget.remaining(), tokenBytes);

  constexpr size_t releasedTokens = 10;
  budget.release(releasedTokens * tokenBytes);
  for (size_t i = 0; i < releasedTokens; i++) EXPECT_TRUE(budget.tryRetain(tokenBytes));
  EXPECT_FALSE(budget.tryRetain(tokenBytes));
  budget.reset();
  EXPECT_EQ(budget.used(), 0U);
}

TEST(EpubSafetyBounds, RubySlotAndPayloadChargesAreExplicit) {
  constexpr size_t base = epub::limits::retainedTokenBytes(3, false);
  constexpr size_t withRubySlot = epub::limits::retainedTokenBytes(3, true);
  EXPECT_EQ(withRubySlot - base, epub::limits::RETAINED_RUBY_SLOT_FIXED_BYTES);
  EXPECT_EQ(epub::limits::retainedRubyPayloadBytes(0), 0U);
  EXPECT_EQ(epub::limits::retainedRubyPayloadBytes(3), 4U);
}

TEST(EpubSafetyBounds, CssAndAnchorAggregateBudgetsHaveExactBoundaries) {
  epub::limits::CssRuleBudget css(epub::limits::MAX_RETAINED_CSS_RULE_BYTES);
  EXPECT_TRUE(css.tryRetain(epub::limits::MAX_RETAINED_CSS_RULE_BYTES));
  EXPECT_FALSE(css.tryRetain(1));
  EXPECT_EQ(css.remaining(), 0U);
  css.reset();
  EXPECT_EQ(epub::limits::cssRuleRetainedBytes(0),
            epub::limits::RETAINED_CSS_RULE_FIXED_BYTES + 1);

  epub::limits::AnchorBudget anchors(epub::limits::MAX_RETAINED_ANCHOR_BYTES);
  EXPECT_TRUE(anchors.tryRetain(epub::limits::MAX_RETAINED_ANCHOR_BYTES - 1));
  EXPECT_TRUE(anchors.tryRetain(1));
  EXPECT_FALSE(anchors.tryRetain(1));
  EXPECT_EQ(epub::limits::anchorRetainedBytes(0),
            epub::limits::RETAINED_ANCHOR_FIXED_BYTES + 1);
}

TEST(EpubSafetyBounds, SectionLutAndStageEnvelopesFitX3Caps) {
  EXPECT_EQ(epub::limits::MAX_PAGES_PER_SPINE * epub::limits::SECTION_LUT_ENTRY_BYTES,
            epub::limits::MAX_SECTION_LUT_BYTES);
  EXPECT_GT((epub::limits::MAX_PAGES_PER_SPINE + 1) *
                epub::limits::SECTION_LUT_ENTRY_BYTES,
            epub::limits::MAX_SECTION_LUT_BYTES);
  EXPECT_LE(epub::limits::MAX_RUBY_RENDER_SCRATCH_BYTES, 32U * 1024U);
  EXPECT_LE(epub::limits::MAX_METADATA_BATCH_BYTES, 96U * 1024U);
  EXPECT_LE(epub::limits::MAX_CSS_HREF_BYTES, 24U * 1024U);
}

TEST(EpubSafetyBounds, PageDecodeAggregateBudgetsHaveExactBoundaries) {
  epub::limits::PageDecodeBudget serialized(epub::limits::MAX_SERIALIZED_PAGE_BYTES);
  EXPECT_TRUE(serialized.tryConsumeSerialized(epub::limits::MAX_SERIALIZED_PAGE_BYTES));
  EXPECT_FALSE(serialized.tryConsumeSerialized(1));

  epub::limits::PageDecodeBudget retained(0);
  EXPECT_TRUE(retained.tryRetain(epub::limits::MAX_RETAINED_PAGE_BYTES));
  EXPECT_FALSE(retained.tryRetain(1));
  EXPECT_EQ(retained.retainedBytes(), epub::limits::MAX_RETAINED_PAGE_BYTES);

  epub::limits::PageDecodeBudget paths(0);
  EXPECT_TRUE(paths.tryRetainImagePaths(epub::limits::MAX_PAGE_IMAGE_PATH_BYTES));
  EXPECT_FALSE(paths.tryRetainImagePaths(1));
}

TEST(EpubSafetyBounds, PageElementTypesAreBoundedBeforeRetention) {
  epub::limits::PageDecodeBudget images(0);
  for (size_t i = 0; i < epub::limits::MAX_PAGE_IMAGE_ELEMENTS; ++i) {
    EXPECT_TRUE(images.tryNoteElement(1));
  }
  EXPECT_FALSE(images.tryNoteElement(1));

  epub::limits::PageDecodeBudget rules(0);
  for (size_t i = 0; i < epub::limits::MAX_PAGE_RULE_ELEMENTS; ++i) {
    EXPECT_TRUE(rules.tryNoteElement(2));
  }
  EXPECT_FALSE(rules.tryNoteElement(2));

  epub::limits::PageDecodeBudget lines(0);
  for (size_t i = 0; i < epub::limits::MAX_PAGE_LINE_ELEMENTS; ++i) {
    EXPECT_TRUE(lines.tryNoteElement(0));
  }
  EXPECT_FALSE(lines.tryNoteElement(0));
  EXPECT_FALSE(lines.tryNoteElement(99));
}

TEST(EpubSafetyBounds, ForcedAllocationRefusalLeavesContainersTransactional) {
  std::vector<uint32_t> vectorValues;
  std::deque<uint32_t> dequeValues;
  std::string text = "unchanged";
  epub::limits::PageDecodeBudget pageBudget(0);
  {
    ScopedAllocationProbe reject(rejectEveryAllocation);
    EXPECT_FALSE(epub::limits::checkedVectorPushBack(vectorValues, 7U, 8));
    EXPECT_FALSE(epub::limits::checkedDequePushBack(dequeValues, 7U, 8));
    EXPECT_FALSE(epub::limits::checkedDequeResize(dequeValues, 4, 8));
    EXPECT_FALSE(epub::limits::checkedStringAssign(text, "replacement", 32));
    EXPECT_FALSE(pageBudget.tryRetain(16, 16));
  }
  EXPECT_TRUE(vectorValues.empty());
  EXPECT_TRUE(dequeValues.empty());
  EXPECT_EQ(text, "unchanged");
  EXPECT_EQ(pageBudget.retainedBytes(), 0U);
}

TEST(EpubSafetyBounds, RealAllocatorFailureAfterSuccessfulPreflightIsTransactional) {
  ScopedAllocationProbe acceptProbe(acceptEveryAllocation);

  struct TrivialPageLutEntry {
    uint32_t fileOffset;
    uint16_t paragraphIndex;
    uint16_t listItemIndex;
    uint32_t visibleTextOffset;
    bool operator==(const TrivialPageLutEntry&) const = default;
  };

  // Sweep every allocation ordinal until each operation completes. Every real
  // bad_alloc before that point must be caught and leave logical state intact.
  bool vectorCompleted = false;
  for (size_t failAt = 1; failAt <= 8 && !vectorCompleted; ++failAt) {
    std::vector<uint32_t> values = {11U, 22U};
    const auto before = values;
    bool ok = false;
    {
      ScopedRealAllocationFailure fail(failAt);
      ok = epub::limits::checkedVectorReserve(values, 64, 64);
    }
    if (!ok) {
      EXPECT_EQ(values, before) << "vector reserve failure ordinal " << failAt;
    } else {
      vectorCompleted = true;
    }
  }
  EXPECT_TRUE(vectorCompleted);

  bool movedStringPushCompleted = false;
  bool movedStringPushRefused = false;
  for (size_t failAt = 1; failAt <= 12 && !movedStringPushCompleted; ++failAt) {
    std::vector<std::string> values = {"kept"};
    values.shrink_to_fit();
    const auto before = values;
    std::string payload(256, 'm');
    bool ok = false;
    {
      ScopedRealAllocationFailure fail(failAt);
      ok = epub::limits::checkedVectorPushBack(values, std::move(payload), 4);
    }
    if (!ok) {
      movedStringPushRefused = true;
      EXPECT_EQ(values, before) << "moved string vector push failure ordinal " << failAt;
    } else {
      movedStringPushCompleted = true;
      EXPECT_EQ(values.size(), 2U);
    }
  }
  EXPECT_TRUE(movedStringPushRefused);
  EXPECT_TRUE(movedStringPushCompleted);

  bool copiedStringPushCompleted = false;
  bool copiedStringPushRefused = false;
  for (size_t failAt = 1; failAt <= 12 && !copiedStringPushCompleted; ++failAt) {
    std::vector<std::string> values;
    values.reserve(2);
    values.emplace_back("kept");
    const auto before = values;
    const std::string payload(256, 'c');
    bool ok = false;
    {
      ScopedRealAllocationFailure fail(failAt);
      ok = epub::limits::checkedVectorPushBack(values, payload, 4);
    }
    if (!ok) {
      copiedStringPushRefused = true;
      EXPECT_EQ(values, before) << "copied string vector push failure ordinal " << failAt;
    } else {
      copiedStringPushCompleted = true;
      EXPECT_EQ(values.size(), 2U);
    }
  }
  EXPECT_TRUE(copiedStringPushRefused);
  EXPECT_TRUE(copiedStringPushCompleted);

  bool lutPushCompleted = false;
  bool lutPushRefused = false;
  for (size_t failAt = 1; failAt <= 8 && !lutPushCompleted; ++failAt) {
    std::vector<TrivialPageLutEntry> values = {{1, 2, 3, 4}};
    values.shrink_to_fit();
    const auto before = values;
    const TrivialPageLutEntry payload{5, 6, 7, 8};
    bool ok = false;
    {
      ScopedRealAllocationFailure fail(failAt);
      ok = epub::limits::checkedVectorPushBack(values, payload, 4);
    }
    if (!ok) {
      lutPushRefused = true;
      EXPECT_EQ(values, before) << "LUT vector push failure ordinal " << failAt;
    } else {
      lutPushCompleted = true;
      EXPECT_EQ(values.size(), 2U);
    }
  }
  EXPECT_TRUE(lutPushRefused);
  EXPECT_TRUE(lutPushCompleted);

  bool vectorResizeCompleted = false;
  bool vectorResizeRefused = false;
  for (size_t failAt = 1; failAt <= 8 && !vectorResizeCompleted; ++failAt) {
    std::vector<uint32_t> values = {11U, 22U};
    const auto before = values;
    bool ok = false;
    {
      ScopedRealAllocationFailure fail(failAt);
      ok = epub::limits::checkedVectorResize(values, 64, 64);
    }
    if (!ok) {
      vectorResizeRefused = true;
      EXPECT_EQ(values, before) << "vector resize failure ordinal " << failAt;
    } else {
      vectorResizeCompleted = true;
      EXPECT_EQ(values.size(), 64U);
    }
  }
  EXPECT_TRUE(vectorResizeRefused);
  EXPECT_TRUE(vectorResizeCompleted);

  bool dequeCompleted = false;
  for (size_t failAt = 1; failAt <= 16 && !dequeCompleted; ++failAt) {
    std::deque<uint32_t> values = {11U, 22U};
    const auto before = values;
    bool ok = false;
    {
      ScopedRealAllocationFailure fail(failAt);
      ok = epub::limits::checkedDequeResize(values, 64, 64);
    }
    if (!ok) {
      EXPECT_EQ(values, before) << "deque resize failure ordinal " << failAt;
    } else {
      dequeCompleted = true;
    }
  }
  EXPECT_TRUE(dequeCompleted);

  size_t dequeGrowthBoundary = 0;
  for (size_t count = 0; count < 512 && dequeGrowthBoundary == 0; ++count) {
    std::deque<std::string> candidate(count, "kept");
    std::string payload(256, 'p');
    bool ok = false;
    {
      ScopedRealAllocationFailure countOnly(std::numeric_limits<size_t>::max());
      ok = epub::limits::checkedDequePushBack(candidate, std::move(payload), 1024);
    }
    if (ok && allocation_fault_test::ordinal > 0) dequeGrowthBoundary = count;
  }
  ASSERT_GT(dequeGrowthBoundary, 0U);

  bool dequePushCompleted = false;
  bool dequePushRefused = false;
  for (size_t failAt = 1; failAt <= 12 && !dequePushCompleted; ++failAt) {
    // Locate this standard library's node boundary first (libstdc++ and libc++
    // use different node sizes), then inject every allocation ordinal on the
    // real node-growth path used by production paragraph queues.
    std::deque<std::string> values(dequeGrowthBoundary, "kept");
    const auto before = values;
    std::string payload(256, 'd');
    bool ok = false;
    {
      ScopedRealAllocationFailure fail(failAt);
      ok = epub::limits::checkedDequePushBack(values, std::move(payload), 1024);
    }
    if (!ok) {
      dequePushRefused = true;
      EXPECT_EQ(values, before) << "deque push failure ordinal " << failAt;
    } else {
      dequePushCompleted = true;
      EXPECT_EQ(values.size(), dequeGrowthBoundary + 1);
    }
  }
  EXPECT_TRUE(dequePushRefused);
  EXPECT_TRUE(dequePushCompleted);

  const std::string replacement(512, 'x');
  bool stringCompleted = false;
  for (size_t failAt = 1; failAt <= 8 && !stringCompleted; ++failAt) {
    std::string value = "unchanged";
    bool ok = false;
    {
      ScopedRealAllocationFailure fail(failAt);
      ok = epub::limits::checkedStringAssign(value, replacement, 512);
    }
    if (!ok) {
      EXPECT_EQ(value, "unchanged") << "string assignment failure ordinal " << failAt;
    } else {
      stringCompleted = true;
      EXPECT_EQ(value, replacement);
    }
  }
  EXPECT_TRUE(stringCompleted);

  bool stringResizeCompleted = false;
  bool stringResizeRefused = false;
  for (size_t failAt = 1; failAt <= 8 && !stringResizeCompleted; ++failAt) {
    std::string value = "unchanged";
    bool ok = false;
    {
      ScopedRealAllocationFailure fail(failAt);
      ok = epub::limits::checkedStringResize(value, 512, 512);
    }
    if (!ok) {
      stringResizeRefused = true;
      EXPECT_EQ(value, "unchanged") << "string resize failure ordinal " << failAt;
    } else {
      stringResizeCompleted = true;
      EXPECT_EQ(value.size(), 512U);
    }
  }
  EXPECT_TRUE(stringResizeRefused);
  EXPECT_TRUE(stringResizeCompleted);

  const std::string suffix(256, 'b');
  bool stringAppendCompleted = false;
  size_t stringAppendRefusals = 0;
  for (size_t failAt = 1; failAt <= 8 && !stringAppendCompleted; ++failAt) {
    std::string value(256, 'a');
    const auto before = value;
    bool ok = false;
    {
      ScopedRealAllocationFailure fail(failAt);
      ok = epub::limits::checkedStringAppend(value, suffix, 512);
    }
    if (!ok) {
      ++stringAppendRefusals;
      EXPECT_EQ(value, before) << "string append failure ordinal " << failAt;
    } else {
      stringAppendCompleted = true;
      EXPECT_EQ(value, before + suffix);
    }
  }
  EXPECT_GE(stringAppendRefusals, 2U);
  EXPECT_TRUE(stringAppendCompleted);
}

TEST(EpubSafetyBounds, FullPageDeserializeClassifiesPostPreflightFailureWithoutMutatingCache) {
  ScopedAllocationProbe acceptProbe(acceptEveryAllocation);

  // One valid horizontal-rule page: element count, tag, x/y, width,
  // thickness, footnote count. This exercises Page allocation, vector growth,
  // element allocation and promotion through the production deserializer.
  std::array<uint8_t, 12> cache{};
  size_t offset = 0;
  const auto append = [&](const auto value) {
    std::memcpy(cache.data() + offset, &value, sizeof(value));
    offset += sizeof(value);
  };
  append(uint16_t{1});
  append(uint8_t{TAG_PageHorizontalRule});
  append(int16_t{3});
  append(int16_t{4});
  append(uint16_t{20});
  append(uint8_t{1});
  append(uint16_t{0});
  ASSERT_EQ(offset, cache.size());
  const auto committedCache = cache;

  bool completed = false;
  size_t refusals = 0;
  for (size_t failAt = 1; failAt <= 16 && !completed; ++failAt) {
    HalFile file(cache.data(), cache.size());
    epub::limits::PageDecodeFailure failure = epub::limits::PageDecodeFailure::InvalidData;
    std::unique_ptr<Page> page;
    {
      ScopedRealAllocationFailure fail(failAt);
      page = Page::deserialize(file, cache.size(), &failure);
    }
    EXPECT_EQ(cache, committedCache) << "cache bytes changed at allocation ordinal " << failAt;
    if (!page) {
      ++refusals;
      EXPECT_EQ(failure, epub::limits::PageDecodeFailure::ResourceRefused)
          << "allocation ordinal " << failAt << " was misclassified as corruption";
    } else {
      completed = true;
      EXPECT_EQ(failure, epub::limits::PageDecodeFailure::None);
      EXPECT_EQ(page->elements.size(), 1U);
    }
  }
  EXPECT_GT(refusals, 0U);
  EXPECT_TRUE(completed);

  auto malformedCache = committedCache;
  malformedCache[2] = 0xff;  // unknown element tag, not an allocation refusal
  HalFile malformed(malformedCache.data(), malformedCache.size());
  epub::limits::PageDecodeFailure malformedFailure = epub::limits::PageDecodeFailure::None;
  EXPECT_EQ(Page::deserialize(malformed, malformedCache.size(), &malformedFailure), nullptr);
  EXPECT_EQ(malformedFailure, epub::limits::PageDecodeFailure::InvalidData);
}

TEST(EpubSafetyBounds, ActiveBuildCursorRestoreFailureRequestsPreservedCacheReload) {
  ScopedAllocationProbe acceptProbe(acceptEveryAllocation);
  ASSERT_TRUE(epub::limits::allocationPreflight(512, 512));

  struct FakeSectionFile {
    unsigned long position = 100;
    unsigned long appendPosition = 100;
    bool failAppendRestore = false;
    bool seek(const unsigned long target) {
      if (failAppendRestore && target == appendPosition) return false;
      position = target;
      return true;
    }
  } file;

  bool cursorSafe = true;
  bool caughtBadAlloc = false;
  ASSERT_TRUE(file.seek(16));
  file.failAppendRestore = true;
  try {
    epub::detail::FileCursorRestoreGuard<FakeSectionFile> restore(
        file, file.appendPosition, cursorSafe);
    ScopedRealAllocationFailure failAfterSuccessfulPreflight(1);
    std::string forcedAllocation(512, 'x');
    (void)forcedAllocation;
  } catch (const std::bad_alloc&) {
    caughtBadAlloc = true;
  }

  EXPECT_TRUE(caughtBadAlloc);
  EXPECT_FALSE(cursorSafe);
  EXPECT_EQ(file.position, 16U);
  const auto failure = cursorSafe ? epub::PageLoadFailure::ResourceRefused
                                  : epub::PageLoadFailure::RestartRequired;
  EXPECT_EQ(epub::pageLoadRecovery(failure), epub::PageLoadRecovery::ReloadPreservedCache);

  bool sectionOwned = true;
  bool reloadRequested = false;
  if (epub::pageLoadRecovery(failure) == epub::PageLoadRecovery::ReloadPreservedCache) {
    sectionOwned = false;       // mirrors EpubReaderActivity::section.reset()
    reloadRequested = true;    // mirrors requestUpdate(), which reloads the cache
  }
  EXPECT_FALSE(sectionOwned);
  EXPECT_TRUE(reloadRequested);
}

TEST(EpubSafetyBounds, ExpatCallbackContainsAllocatorFailureBeforeReturningThroughC) {
  ScopedAllocationProbe acceptProbe(acceptEveryAllocation);
  ASSERT_TRUE(epub::limits::allocationPreflight(512, 512));

  ExpatAllocationCallbackState state;
  state.parser = XML_ParserCreate(nullptr);
  ASSERT_NE(state.parser, nullptr);
  XML_SetUserData(state.parser, &state);
  XML_SetStartElementHandler(state.parser, allocationFaultingStartElement);
  constexpr char xml[] = "<container><rootfile/></container>";
  bool exceptionEscapedC = false;
  XML_Status status = XML_STATUS_OK;
  try {
    status = XML_Parse(state.parser, xml, sizeof(xml) - 1, XML_TRUE);
  } catch (...) {
    exceptionEscapedC = true;
  }
  EXPECT_FALSE(exceptionEscapedC);
  EXPECT_TRUE(state.callbackEntered);
  EXPECT_TRUE(state.allocationFailureContained);
  EXPECT_EQ(status, XML_STATUS_ERROR);
  EXPECT_EQ(XML_GetErrorCode(state.parser), XML_ERROR_ABORTED);
  XML_ParserFree(state.parser);
}

TEST(SerializedLengthPolicy, RequiresTypeLimitAndRemainingBytesBeforeResize) {
  EXPECT_TRUE(serialization::sizedFieldFits(1024, 1024, 1024));
  EXPECT_FALSE(serialization::sizedFieldFits(1025, 1024, 4096));
  EXPECT_FALSE(serialization::sizedFieldFits(1024, 4096, 1023));
  EXPECT_FALSE(serialization::sizedFieldFits(UINT32_MAX, 4096, 4096));
}

TEST(SerializedLengthPolicy, CheckedAdditionRejectsWraparound) {
  size_t result = 0;
  EXPECT_TRUE(serialization::checkedAdd(4, 5, &result));
  EXPECT_EQ(result, 9U);
  EXPECT_FALSE(serialization::checkedAdd(std::numeric_limits<size_t>::max(), 1, &result));
  EXPECT_FALSE(serialization::checkedAdd(1, 1, nullptr));
}
