#pragma once
#include <HalStorage.h>

#include <algorithm>
#include <string>
#include <utility>
#include <vector>

#include "FootnoteEntry.h"
#include "EpubSafetyLimits.h"
#include "blocks/ImageBlock.h"
#include "blocks/TextBlock.h"

enum PageElementTag : uint8_t {
  TAG_PageLine = 1,
  TAG_PageImage = 2,
  TAG_PageHorizontalRule = 3,
};

// represents something that has been added to a page
class PageElement {
 public:
  int16_t xPos;
  int16_t yPos;
  explicit PageElement(const int16_t xPos, const int16_t yPos) : xPos(xPos), yPos(yPos) {}
  virtual ~PageElement() = default;
  virtual void render(GfxRenderer& renderer, int fontId, int xOffset, int yOffset) = 0;
  virtual bool serialize(HalFile& file) = 0;
  virtual PageElementTag getTag() const = 0;  // Add type identification
  virtual size_t serializedSize() const = 0;
  virtual size_t retainedSize() const = 0;
  virtual size_t retainedPathBytes() const { return 0; }
};

// a line from a block element
class PageLine final : public PageElement {
  std::unique_ptr<TextBlock> block;

 public:
  PageLine(std::unique_ptr<TextBlock> block, const int16_t xPos, const int16_t yPos)
      : PageElement(xPos, yPos), block(std::move(block)) {}
  const TextBlock* getBlock() const { return block.get(); }
  void render(GfxRenderer& renderer, int fontId, int xOffset, int yOffset) override;
  bool serialize(HalFile& file) override;
  PageElementTag getTag() const override { return TAG_PageLine; }
  size_t serializedSize() const override { return 2 * sizeof(int16_t) + block->serializedSize(); }
  size_t retainedSize() const override { return sizeof(PageLine) + block->retainedSize(); }
  static std::unique_ptr<PageLine> deserialize(
      HalFile& file, epub::limits::PageDecodeBudget* budget = nullptr,
      epub::limits::PageDecodeFailure* failure = nullptr);
};

// New PageImage class
class PageImage final : public PageElement {
  std::unique_ptr<ImageBlock> imageBlock;

 public:
  PageImage(std::unique_ptr<ImageBlock> block, const int16_t xPos, const int16_t yPos)
      : PageElement(xPos, yPos), imageBlock(std::move(block)) {}
  void render(GfxRenderer& renderer, int fontId, int xOffset, int yOffset) override;
  void renderPlaceholder(GfxRenderer& renderer, int xOffset, int yOffset) const;
  bool serialize(HalFile& file) override;
  PageElementTag getTag() const override { return TAG_PageImage; }
  size_t serializedSize() const override { return 2 * sizeof(int16_t) + imageBlock->serializedSize(); }
  size_t retainedSize() const override { return sizeof(PageImage) + imageBlock->retainedSize(); }
  size_t retainedPathBytes() const override { return imageBlock->retainedPathBytes(); }
  static std::unique_ptr<PageImage> deserialize(
      HalFile& file, epub::limits::PageDecodeBudget* budget = nullptr,
      epub::limits::PageDecodeFailure* failure = nullptr);
  const ImageBlock& getImageBlock() const { return *imageBlock; }
};

class PageHorizontalRule final : public PageElement {
  uint16_t width;
  uint8_t thickness;

 public:
  PageHorizontalRule(uint16_t width, uint8_t thickness, const int16_t xPos, const int16_t yPos)
      : PageElement(xPos, yPos), width(width), thickness(thickness) {}

  void render(GfxRenderer& renderer, int fontId, int xOffset, int yOffset) override;
  bool serialize(HalFile& file) override;
  PageElementTag getTag() const override { return TAG_PageHorizontalRule; }
  size_t serializedSize() const override { return 2 * sizeof(int16_t) + sizeof(width) + sizeof(thickness); }
  size_t retainedSize() const override { return sizeof(PageHorizontalRule); }
  static std::unique_ptr<PageHorizontalRule> deserialize(HalFile& file,
                                                         epub::limits::PageDecodeBudget* budget = nullptr,
                                                         epub::limits::PageDecodeFailure* failure = nullptr);
};

class Page {
  epub::limits::PageDecodeBudget buildBudget_{
      epub::limits::MAX_SERIALIZED_PAGE_BYTES - 2 * sizeof(uint16_t)};
  bool buildBudgetValid_ = false;

  static uint8_t budgetKind(PageElementTag tag);
  bool tryAddDecodedElement(std::unique_ptr<PageElement> element);

 public:
  Page() : buildBudgetValid_(buildBudget_.tryRetain(sizeof(Page), sizeof(Page))) {}

  // the list of block index and line numbers on this page
  std::vector<std::unique_ptr<PageElement>> elements;
  std::vector<FootnoteEntry> footnotes;
  static constexpr uint16_t MAX_FOOTNOTES_PER_PAGE = 16;

  // Zero-based visible-codepoint offset where this page starts. Not part of the serialized page
  // body (it lives in the section's visible-offset LUT); Section::loadPage* fills it in from the
  // build LUT or the on-disk LUT while the page file is already open, so the reader can persist
  // progress without a second section-file open per page turn.
  uint32_t visibleTextOffset = 0;

  bool tryAddElement(std::unique_ptr<PageElement> element);
  bool addFootnote(const char* number, const char* href);

  void render(GfxRenderer& renderer, int fontId, int xOffset, int yOffset) const;
  void renderImages(GfxRenderer& renderer, int fontId, int xOffset, int yOffset) const;
  void renderWithImagePlaceholders(GfxRenderer& renderer, int fontId, int xOffset, int yOffset) const;
  bool serialize(HalFile& file) const;
  static std::unique_ptr<Page> deserialize(HalFile& file,
                                           size_t serializedBytes = epub::limits::MAX_SERIALIZED_PAGE_BYTES,
                                           epub::limits::PageDecodeFailure* failure = nullptr);

  // Check if page contains any images (used to force full refresh)
  bool hasImages() const {
    return std::any_of(elements.begin(), elements.end(),
                       [](const std::unique_ptr<PageElement>& el) { return el->getTag() == TAG_PageImage; });
  }

  bool hasImagesNeedingDecode() const {
    return std::any_of(elements.begin(), elements.end(), [](const std::unique_ptr<PageElement>& element) {
      return element->getTag() == TAG_PageImage &&
             static_cast<const PageImage&>(*element).getImageBlock().needsDecode();
    });
  }

  // Get bounding box of all images on the page (union of image rects)
  // Returns false if no images. Coordinates are relative to page origin.
  bool getImageBoundingBox(int16_t& outX, int16_t& outY, int16_t& outW, int16_t& outH) const {
    bool found = false;
    int16_t minX = INT16_MAX, minY = INT16_MAX, maxX = INT16_MIN, maxY = INT16_MIN;
    for (const auto& el : elements) {
      if (el->getTag() == TAG_PageImage) {
        const auto& img = static_cast<const PageImage&>(*el);
        int16_t x = img.xPos;
        int16_t y = img.yPos;
        int16_t right = x + img.getImageBlock().getWidth();
        int16_t bottom = y + img.getImageBlock().getHeight();
        minX = std::min(minX, x);
        minY = std::min(minY, y);
        maxX = std::max(maxX, right);
        maxY = std::max(maxY, bottom);
        found = true;
      }
    }
    if (found) {
      outX = minX;
      outY = minY;
      outW = maxX - minX;
      outH = maxY - minY;
    }
    return found;
  }
};
