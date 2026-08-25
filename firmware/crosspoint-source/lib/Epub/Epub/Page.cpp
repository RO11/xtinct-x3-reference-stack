#include "Page.h"

#include <GfxRenderer.h>
#include <Logging.h>
#include <Serialization.h>

#include <new>

#include "Epub/EpubSafetyLimits.h"

namespace {

template <typename Predicate>
void renderFilteredPageElements(const std::vector<std::unique_ptr<PageElement>>& elements, GfxRenderer& renderer,
                                const int fontId, const int xOffset, const int yOffset, Predicate&& predicate) {
  for (const auto& element : elements) {
    if (predicate(*element)) {
      element->render(renderer, fontId, xOffset, yOffset);
    }
  }
}

template <typename T>
bool readPagePod(HalFile& file, T& value, epub::limits::PageDecodeBudget* const budget) {
  if (budget && !budget->tryConsumeSerialized(sizeof(T))) return false;
  return serialization::readPod(file, value);
}

bool retainForPageDecode(epub::limits::PageDecodeBudget* const budget, const size_t bytes,
                         const size_t largestBlock,
                         epub::limits::PageDecodeFailure* const failure) {
  if (!budget || budget->tryRetain(bytes, largestBlock)) return true;
  if (budget->resourceRefused()) epub::limits::markPageDecodeResourceRefusal(failure);
  return false;
}

}  // namespace

void PageLine::render(GfxRenderer& renderer, const int fontId, const int xOffset, const int yOffset) {
  block->render(renderer, fontId, xPos + xOffset, yPos + yOffset);
}

bool PageLine::serialize(HalFile& file) {
  if (!serialization::writePod(file, xPos) || !serialization::writePod(file, yPos)) return false;

  // serialize TextBlock pointed to by PageLine
  return block->serialize(file);
}

std::unique_ptr<PageLine> PageLine::deserialize(
    HalFile& file, epub::limits::PageDecodeBudget* const budget,
    epub::limits::PageDecodeFailure* const failure) {
  int16_t xPos = 0;
  int16_t yPos = 0;
  if (!readPagePod(file, xPos, budget) || !readPagePod(file, yPos, budget)) return nullptr;

  auto tb = TextBlock::deserialize(file, budget, failure);
  if (!tb) {
    LOG_ERR("PGE", "Deserialization failed: null TextBlock");
    return nullptr;
  }

  auto* line = new (std::nothrow) PageLine(std::move(tb), xPos, yPos);
  if (!line) {
    epub::limits::markPageDecodeResourceRefusal(failure);
    LOG_ERR("PGE", "Deserialization failed: could not allocate PageLine");
    return nullptr;
  }
  return std::unique_ptr<PageLine>(line);
}

void PageImage::render(GfxRenderer& renderer, const int fontId, const int xOffset, const int yOffset) {
  // Images don't use fontId or text rendering
  imageBlock->render(renderer, xPos + xOffset, yPos + yOffset);
}

void PageImage::renderPlaceholder(GfxRenderer& renderer, const int xOffset, const int yOffset) const {
  imageBlock->renderPlaceholder(renderer, xPos + xOffset, yPos + yOffset);
}

bool PageImage::serialize(HalFile& file) {
  if (!serialization::writePod(file, xPos) || !serialization::writePod(file, yPos)) return false;

  // serialize ImageBlock
  return imageBlock->serialize(file);
}

std::unique_ptr<PageImage> PageImage::deserialize(
    HalFile& file, epub::limits::PageDecodeBudget* const budget,
    epub::limits::PageDecodeFailure* const failure) {
  int16_t xPos = 0;
  int16_t yPos = 0;
  if (!readPagePod(file, xPos, budget) || !readPagePod(file, yPos, budget)) return nullptr;

  auto ib = ImageBlock::deserialize(file, budget, failure);
  if (!ib) return nullptr;
  auto* image = new (std::nothrow) PageImage(std::move(ib), xPos, yPos);
  if (!image) epub::limits::markPageDecodeResourceRefusal(failure);
  return std::unique_ptr<PageImage>(image);
}

void PageHorizontalRule::render(GfxRenderer& renderer, const int fontId, const int xOffset, const int yOffset) {
  (void)fontId;
  if (width == 0 || thickness == 0) {
    return;
  }

  renderer.drawLine(xPos + xOffset, yPos + yOffset, xPos + xOffset + width - 1, yPos + yOffset, thickness, true);
}

bool PageHorizontalRule::serialize(HalFile& file) {
  return serialization::writePod(file, xPos) && serialization::writePod(file, yPos) &&
         serialization::writePod(file, width) && serialization::writePod(file, thickness);
}

std::unique_ptr<PageHorizontalRule> PageHorizontalRule::deserialize(HalFile& file,
                                                                    epub::limits::PageDecodeBudget* const budget,
                                                                    epub::limits::PageDecodeFailure* const failure) {
  int16_t xPos = 0;
  int16_t yPos = 0;
  uint16_t width = 0;
  uint8_t thickness = 0;
  if (!readPagePod(file, xPos, budget) || !readPagePod(file, yPos, budget) ||
      !readPagePod(file, width, budget) || !readPagePod(file, thickness, budget)) {
    return nullptr;
  }

  if (width == 0 || thickness == 0) {
    LOG_ERR("PGE", "Deserialization failed: invalid horizontal rule metadata (width=%u thickness=%u)", width,
            thickness);
    return nullptr;
  }

  if (!retainForPageDecode(budget, sizeof(PageHorizontalRule), sizeof(PageHorizontalRule), failure)) return nullptr;

  auto* rule = new (std::nothrow) PageHorizontalRule(width, thickness, xPos, yPos);
  if (!rule) {
    epub::limits::markPageDecodeResourceRefusal(failure);
    LOG_ERR("PGE", "Deserialization failed: could not allocate PageHorizontalRule");
    return nullptr;
  }
  return std::unique_ptr<PageHorizontalRule>(rule);
}

uint8_t Page::budgetKind(const PageElementTag tag) {
  switch (tag) {
    case TAG_PageLine:
      return 0;
    case TAG_PageImage:
      return 1;
    case TAG_PageHorizontalRule:
      return 2;
    default:
      return UINT8_MAX;
  }
}

bool Page::tryAddElement(std::unique_ptr<PageElement> element) {
  if (!buildBudgetValid_ || !element) return false;
  auto staged = buildBudget_;
  const uint8_t kind = budgetKind(element->getTag());
  const size_t serialized = element->serializedSize();
  const size_t retained = element->retainedSize() + epub::limits::RETAINED_PAGE_ELEMENT_FIXED_BYTES;
  if (kind == UINT8_MAX || serialized == SIZE_MAX || !staged.tryNoteElement(kind) ||
      !staged.tryConsumeSerialized(sizeof(uint8_t) + serialized) || !staged.tryRetain(retained, retained) ||
      !staged.tryRetainImagePaths(element->retainedPathBytes()) ||
      !epub::limits::checkedVectorPushBack(elements, std::move(element), epub::limits::MAX_PAGE_ELEMENTS)) {
    return false;
  }
  buildBudget_ = staged;
  return true;
}

bool Page::tryAddDecodedElement(std::unique_ptr<PageElement> element) {
  return element && epub::limits::checkedVectorPushBack(elements, std::move(element),
                                                         epub::limits::MAX_PAGE_ELEMENTS);
}

bool Page::addFootnote(const char* const number, const char* const href) {
  if (!buildBudgetValid_ || !number || !href || footnotes.size() >= MAX_FOOTNOTES_PER_PAGE) return false;
  auto staged = buildBudget_;
  if (!staged.tryConsumeSerialized(sizeof(FootnoteEntry)) ||
      !staged.tryRetain(sizeof(FootnoteEntry) * 2, sizeof(FootnoteEntry))) return false;
  FootnoteEntry entry;
  strncpy(entry.number, number, sizeof(entry.number) - 1);
  entry.number[sizeof(entry.number) - 1] = '\0';
  strncpy(entry.href, href, sizeof(entry.href) - 1);
  entry.href[sizeof(entry.href) - 1] = '\0';
  if (!epub::limits::checkedVectorPushBack(footnotes, entry, MAX_FOOTNOTES_PER_PAGE)) return false;
  buildBudget_ = staged;
  return true;
}

void Page::render(GfxRenderer& renderer, const int fontId, const int xOffset, const int yOffset) const {
  renderFilteredPageElements(elements, renderer, fontId, xOffset, yOffset, [](const PageElement&) { return true; });
}

void Page::renderImages(GfxRenderer& renderer, const int fontId, const int xOffset, const int yOffset) const {
  renderFilteredPageElements(elements, renderer, fontId, xOffset, yOffset,
                             [](const PageElement& element) { return element.getTag() == TAG_PageImage; });
}

void Page::renderWithImagePlaceholders(GfxRenderer& renderer, const int fontId, const int xOffset,
                                       const int yOffset) const {
  for (const auto& element : elements) {
    if (element->getTag() == TAG_PageImage) {
      static_cast<const PageImage&>(*element).renderPlaceholder(renderer, xOffset, yOffset);
    } else {
      element->render(renderer, fontId, xOffset, yOffset);
    }
  }
}

bool Page::serialize(HalFile& file) const {
  if (!buildBudgetValid_ || elements.size() > epub::limits::MAX_PAGE_ELEMENTS ||
      footnotes.size() > MAX_FOOTNOTES_PER_PAGE) return false;
  size_t serializedBytes = 2 * sizeof(uint16_t) + footnotes.size() * sizeof(FootnoteEntry);
  size_t imagePathBytes = 0;
  size_t lineCount = 0, imageCount = 0, ruleCount = 0;
  for (const auto& element : elements) {
    if (!element) return false;
    const size_t bytes = element->serializedSize();
    if (bytes == SIZE_MAX ||
        !epub::limits::countCanGrow(serializedBytes, sizeof(uint8_t) + bytes,
                                    epub::limits::MAX_SERIALIZED_PAGE_BYTES) ||
        !epub::limits::countCanGrow(imagePathBytes, element->retainedPathBytes(),
                                    epub::limits::MAX_PAGE_IMAGE_PATH_BYTES)) return false;
    serializedBytes += sizeof(uint8_t) + bytes;
    imagePathBytes += element->retainedPathBytes();
    if (element->getTag() == TAG_PageLine) ++lineCount;
    else if (element->getTag() == TAG_PageImage) ++imageCount;
    else if (element->getTag() == TAG_PageHorizontalRule) ++ruleCount;
    else return false;
  }
  if (lineCount > epub::limits::MAX_PAGE_LINE_ELEMENTS || imageCount > epub::limits::MAX_PAGE_IMAGE_ELEMENTS ||
      ruleCount > epub::limits::MAX_PAGE_RULE_ELEMENTS || serializedBytes > epub::limits::MAX_SERIALIZED_PAGE_BYTES)
    return false;

  const uint32_t start = file.position();
  const uint16_t count = static_cast<uint16_t>(elements.size());
  if (!serialization::writePod(file, count)) return false;
  for (const auto& element : elements) {
    if (!serialization::writePod(file, static_cast<uint8_t>(element->getTag())) || !element->serialize(file))
      return false;
  }
  const uint16_t fnCount = static_cast<uint16_t>(footnotes.size());
  if (!serialization::writePod(file, fnCount)) return false;
  for (const auto& fn : footnotes) {
    if (file.write(fn.number, sizeof(fn.number)) != sizeof(fn.number) ||
        file.write(fn.href, sizeof(fn.href)) != sizeof(fn.href)) return false;
  }
  return static_cast<size_t>(file.position() - start) == serializedBytes;
}

std::unique_ptr<Page> Page::deserialize(HalFile& file, size_t serializedBytes,
                                       epub::limits::PageDecodeFailure* const failure) {
  if (failure) *failure = epub::limits::PageDecodeFailure::InvalidData;
  if (serializedBytes == epub::limits::MAX_SERIALIZED_PAGE_BYTES && file.available() >= 0 &&
      static_cast<size_t>(file.available()) < serializedBytes)
    serializedBytes = static_cast<size_t>(file.available());
  if (serializedBytes == 0 || serializedBytes > epub::limits::MAX_SERIALIZED_PAGE_BYTES ||
      file.available() < 0 || static_cast<size_t>(file.available()) < serializedBytes) return nullptr;

  epub::limits::PageDecodeBudget budget(serializedBytes);
  if (!retainForPageDecode(&budget, sizeof(Page), sizeof(Page), failure)) return nullptr;
  auto page = std::unique_ptr<Page>(new (std::nothrow) Page());
  if (!page) {
    epub::limits::markPageDecodeResourceRefusal(failure);
    return nullptr;
  }
  if (!page->buildBudgetValid_) {
    if (page->buildBudget_.resourceRefused()) epub::limits::markPageDecodeResourceRefusal(failure);
    return nullptr;
  }

  uint16_t count = 0;
  if (!readPagePod(file, count, &budget) || count > epub::limits::MAX_PAGE_ELEMENTS) return nullptr;
  const size_t vectorBytes = static_cast<size_t>(count) * sizeof(std::unique_ptr<PageElement>) * 2;
  if (!retainForPageDecode(&budget, vectorBytes, vectorBytes, failure)) return nullptr;
  if (!epub::limits::checkedVectorReserve(page->elements, count, epub::limits::MAX_PAGE_ELEMENTS)) {
    epub::limits::markPageDecodeResourceRefusal(failure);
    return nullptr;
  }

  for (uint16_t i = 0; i < count; ++i) {
    uint8_t tag = 0;
    if (!readPagePod(file, tag, &budget)) return nullptr;
    const uint8_t kind = budgetKind(static_cast<PageElementTag>(tag));
    if (kind == UINT8_MAX || !budget.tryNoteElement(kind)) return nullptr;
    if (!retainForPageDecode(&budget, epub::limits::RETAINED_PAGE_ELEMENT_FIXED_BYTES,
                             epub::limits::RETAINED_PAGE_ELEMENT_FIXED_BYTES, failure)) return nullptr;

    std::unique_ptr<PageElement> element;
    if (tag == TAG_PageLine) element = PageLine::deserialize(file, &budget, failure);
    else if (tag == TAG_PageImage) element = PageImage::deserialize(file, &budget, failure);
    else if (tag == TAG_PageHorizontalRule) element = PageHorizontalRule::deserialize(file, &budget, failure);
    if (!element) return nullptr;
    if (!page->tryAddDecodedElement(std::move(element))) {
      epub::limits::markPageDecodeResourceRefusal(failure);
      return nullptr;
    }
  }

  uint16_t fnCount = 0;
  if (!readPagePod(file, fnCount, &budget) || fnCount > MAX_FOOTNOTES_PER_PAGE) return nullptr;
  const size_t footnoteBytes = static_cast<size_t>(fnCount) * sizeof(FootnoteEntry);
  if (footnoteBytes > budget.serializedRemaining() || !budget.tryConsumeSerialized(footnoteBytes)) return nullptr;
  if (!retainForPageDecode(&budget, footnoteBytes * 2, footnoteBytes, failure)) return nullptr;
  if (!epub::limits::checkedVectorReserve(page->footnotes, fnCount, MAX_FOOTNOTES_PER_PAGE)) {
    epub::limits::markPageDecodeResourceRefusal(failure);
    return nullptr;
  }
  for (uint16_t i = 0; i < fnCount; ++i) {
    FootnoteEntry entry;
    if (file.read(entry.number, sizeof(entry.number)) != sizeof(entry.number) ||
        file.read(entry.href, sizeof(entry.href)) != sizeof(entry.href)) return nullptr;
    entry.number[sizeof(entry.number) - 1] = '\0';
    entry.href[sizeof(entry.href) - 1] = '\0';
    if (!epub::limits::checkedVectorPushBack(page->footnotes, entry, MAX_FOOTNOTES_PER_PAGE)) {
      epub::limits::markPageDecodeResourceRefusal(failure);
      return nullptr;
    }
  }
  if (budget.serializedRemaining() != 0) return nullptr;
  page->buildBudget_ = budget;
  page->buildBudgetValid_ = true;
  if (failure) *failure = epub::limits::PageDecodeFailure::None;
  return page;
}
