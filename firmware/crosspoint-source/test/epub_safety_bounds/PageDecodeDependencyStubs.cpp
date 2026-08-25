#include "Epub/Epub/blocks/ImageBlock.h"
#include "Epub/Epub/blocks/TextBlock.h"

std::unique_ptr<TextBlock> TextBlock::deserialize(
    HalFile&, epub::limits::PageDecodeBudget*, epub::limits::PageDecodeFailure*) {
  return nullptr;
}

void TextBlock::render(const GfxRenderer&, int, int, int) const {}
bool TextBlock::serialize(HalFile&) const { return false; }
size_t TextBlock::serializedSize() const { return 0; }
size_t TextBlock::retainedSize() const { return 0; }
bool TextBlock::hasRuby() const { return false; }

std::unique_ptr<ImageBlock> ImageBlock::deserialize(
    HalFile&, epub::limits::PageDecodeBudget*, epub::limits::PageDecodeFailure*) {
  return nullptr;
}

void ImageBlock::render(GfxRenderer&, int, int) {}
void ImageBlock::renderPlaceholder(GfxRenderer&, int, int) const {}
bool ImageBlock::serialize(HalFile&) { return false; }
size_t ImageBlock::serializedSize() const { return 0; }
size_t ImageBlock::retainedSize() const { return 0; }
bool ImageBlock::needsDecode() const { return false; }
