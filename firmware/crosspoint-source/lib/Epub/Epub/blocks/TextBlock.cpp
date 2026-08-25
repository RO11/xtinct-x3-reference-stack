#include "TextBlock.h"

#include <BidiUtils.h>
#include <GfxRenderer.h>
#include <Logging.h>
#include <Memory.h>
#include <Serialization.h>

#include <cstring>

#include "../../../../src/fontIds.h"
#include "Epub/EpubSafetyLimits.h"

namespace {

template <typename T>
bool readPagePod(HalFile& file, T& value, epub::limits::PageDecodeBudget* const budget) {
  if (budget && !budget->tryConsumeSerialized(sizeof(T))) return false;
  return serialization::readPod(file, value);
}

bool readPageString(HalFile& file, std::string& value, const size_t maximum,
                    epub::limits::PageDecodeBudget* const budget,
                    epub::limits::PageDecodeFailure* const failure) {
  if (!budget) return serialization::readString(file, value, maximum);
  uint32_t length = 0;
  if (!readPagePod(file, length, budget) || length > maximum || length > budget->serializedRemaining()) return false;
  if (!budget->tryRetain(length == 0 ? 0 : static_cast<size_t>(length) + 1,
                         static_cast<size_t>(length) + 1)) {
    if (budget->resourceRefused()) epub::limits::markPageDecodeResourceRefusal(failure);
    return false;
  }
  if (!budget->tryConsumeSerialized(length)) return false;
  std::string staged;
  if (!epub::limits::checkedStringResize(staged, length, maximum)) {
    epub::limits::markPageDecodeResourceRefusal(failure);
    return false;
  }
  if (length != 0 && file.read(staged.data(), length) != length) return false;
  value.swap(staged);
  return true;
}

constexpr size_t SERIALIZED_BLOCK_STYLE_BYTES = sizeof(CssTextAlign) + sizeof(bool) + 4 * sizeof(int16_t) +
                                                4 * sizeof(int16_t) + sizeof(int16_t) + 3 * sizeof(bool);

}  // namespace

size_t TextBlock::arenaSize(const uint16_t wordCount, const bool hasFocus, const uint16_t textBytes) {
  // Layout documented in TextBlock.h: 16-bit arrays first, then 8-bit arrays, then text.
  size_t size = static_cast<size_t>(wordCount) * (sizeof(uint16_t) + sizeof(int16_t) + sizeof(uint8_t));
  if (hasFocus) {
    size += static_cast<size_t>(wordCount) * (sizeof(uint16_t) + sizeof(uint8_t));
  }
  return size + textBytes;
}

void TextBlock::bindArenaPointers() {
  uint8_t* base = arena.get();
  const size_t wc = numWords;
  textOffArr = reinterpret_cast<const uint16_t*>(base);
  xposArr = reinterpret_cast<const int16_t*>(base + wc * 2);
  size_t off = wc * 4;
  if (focusPresent) {
    focusSuffixXArr = reinterpret_cast<const uint16_t*>(base + off);
    off += wc * 2;
  }
  stylesArr = base + off;
  off += wc;
  if (focusPresent) {
    focusBoundaryArr = base + off;
    off += wc;
  }
  textArr = reinterpret_cast<const char*>(base + off);
}

TextBlock::TextBlock(const std::vector<std::string>& words, const std::vector<int16_t>& wordXpos,
                     const std::vector<EpdFontFamily::Style>& wordStyles, const std::vector<uint8_t>& focusBoundary,
                     const std::vector<uint16_t>& focusSuffixX, const BlockStyle& blockStyle,
                     std::vector<std::string> rubyTexts)
    : blockStyle(blockStyle), rubyTexts(std::move(rubyTexts)) {
  // Same invariant as deserialize(): a block never holds an all-empty rubyTexts, so a
  // ruby-less line costs nothing beyond its arena. The layout engine hands one over for
  // every line it extracts, ruby or not; release it here rather than carrying it for the
  // block's lifetime. Move-assigning an empty vector frees the buffer (clear() would not).
  if (!hasRuby()) {
    this->rubyTexts = std::vector<std::string>{};
  }

  // Focus annotations are optional: empty vectors mean no word in this block has a split.
  // When present, they must be sized in lockstep with words[].
  const bool hasFocus = !focusBoundary.empty();
  if (words.size() != wordXpos.size() || words.size() != wordStyles.size() ||
      words.size() > epub::limits::MAX_TEXT_BLOCK_WORDS ||
      (!this->rubyTexts.empty() && this->rubyTexts.size() != words.size()) ||
      (hasFocus && (words.size() != focusBoundary.size() || words.size() != focusSuffixX.size()))) {
    LOG_ERR("TXB", "Construction failed: size mismatch (words=%u, xpos=%u, styles=%u, boundary=%u, suffixX=%u)",
            static_cast<uint32_t>(words.size()), static_cast<uint32_t>(wordXpos.size()),
            static_cast<uint32_t>(wordStyles.size()), static_cast<uint32_t>(focusBoundary.size()),
            static_cast<uint32_t>(focusSuffixX.size()));
    isValid = false;
    return;
  }

  numWords = static_cast<uint16_t>(words.size());
  focusPresent = hasFocus;
  if (numWords == 0) {
    return;  // valid empty block, no arena
  }

  // Pass 1: total text size, one NUL per word. A line is at most a physical
  // row of the page, so uint16_t offsets are ample; reject anything larger.
  size_t totalText = 0;
  for (const auto& w : words) {
    size_t withTerminator = 0;
    if (w.size() > epub::limits::MAX_INPUT_WORD_BYTES ||
        !serialization::checkedAdd(w.size(), 1, &withTerminator) ||
        !serialization::checkedAdd(totalText, withTerminator, &totalText)) {
      LOG_ERR("TXB", "Construction failed: oversized word data");
      isValid = false;
      return;
    }
  }
  if (totalText > UINT16_MAX) {
    LOG_ERR("TXB", "Construction failed: text size %u exceeds arena limit", static_cast<uint32_t>(totalText));
    numWords = 0;
    focusPresent = false;
    isValid = false;
    return;
  }
  textBytes = static_cast<uint16_t>(totalText);

  size_t rubyBytes = 0;
  for (const auto& ruby : this->rubyTexts) {
    if (!epub::limits::rubyTextFits(rubyBytes, ruby.size())) {
      LOG_ERR("TXB", "Construction failed: oversized ruby data");
      numWords = 0;
      textBytes = 0;
      isValid = false;
      return;
    }
    rubyBytes += ruby.size();
  }

  const size_t size = arenaSize(numWords, focusPresent, textBytes);
  if (!epub::limits::allocationPreflight(size, size)) {
    LOG_ERR("TXB", "Construction refused arena allocation (%u bytes)", static_cast<uint32_t>(size));
    numWords = 0;
    textBytes = 0;
    focusPresent = false;
    isValid = false;
    return;
  }
  arena = makeUniqueNoThrow<uint8_t[]>(size);
  if (!arena) {
    LOG_ERR("TXB", "OOM: arena %u bytes", static_cast<uint32_t>(size));
    numWords = 0;
    textBytes = 0;
    focusPresent = false;
    isValid = false;
    return;
  }
  bindArenaPointers();

  // Pass 2: fill. Mutable aliases of the const views bound above.
  auto* textOff = const_cast<uint16_t*>(textOffArr);
  auto* xpos = const_cast<int16_t*>(xposArr);
  auto* styles = const_cast<uint8_t*>(stylesArr);
  auto* text = const_cast<char*>(textArr);
  uint16_t off = 0;
  for (uint16_t i = 0; i < numWords; i++) {
    textOff[i] = off;
    xpos[i] = wordXpos[i];
    styles[i] = static_cast<uint8_t>(wordStyles[i]);
    memcpy(text + off, words[i].data(), words[i].size());
    off += static_cast<uint16_t>(words[i].size());
    text[off++] = '\0';
  }
  if (focusPresent) {
    auto* suffixX = const_cast<uint16_t*>(focusSuffixXArr);
    auto* boundary = const_cast<uint8_t*>(focusBoundaryArr);
    for (uint16_t i = 0; i < numWords; i++) {
      suffixX[i] = focusSuffixX[i];
      boundary[i] = focusBoundary[i];
    }
  }
}

bool TextBlock::hasRuby() const {
  for (const auto& rt : rubyTexts) {
    if (!rt.empty()) return true;
  }
  return false;
}

void TextBlock::render(const GfxRenderer& renderer, const int fontId, const int x, const int y) const {
  if (!isValid) {
    LOG_ERR("TXB", "Render skipped: invalid block");
    return;
  }

  const bool scanning = renderer.isFontCacheScanning();
  const int ascender = renderer.getFontAscenderSize(fontId);

  // Resolve ruby collisions left-to-right to prevent adjacent ruby texts from overlapping
  struct RubyDrawInfo {
    int x;
    int width;
    std::string text;
    BidiUtils::BidiBaseDir baseDir;
  };
  // hasRuby() is an O(numWords) scan, so resolve it once here rather than per word.
  // Both arrays below are only ever read when the line carries ruby, so they stay
  // empty (zero allocations) for the ruby-less case, which is every line of a
  // non-CJK book. Sized lazily inside the branch.
  const bool blockHasRuby = hasRuby();
  std::vector<int> wordShiftArr;
  std::vector<RubyDrawInfo> rubies;
  if (blockHasRuby) {
    size_t rubyPayloadBytes = 0;
    size_t largestRubyPayload = 0;
    for (const auto& ruby : rubyTexts) {
      if (!epub::limits::countCanGrow(rubyPayloadBytes, ruby.size() + 1,
                                      epub::limits::MAX_RUBY_RENDER_SCRATCH_BYTES)) {
        LOG_ERR("TXB", "Ruby render scratch exceeds retained-memory envelope");
        return;
      }
      rubyPayloadBytes += ruby.size() + 1;
      largestRubyPayload = std::max(largestRubyPayload, ruby.size() + 1);
    }
    const size_t fixedScratch = static_cast<size_t>(numWords) * (sizeof(int) + sizeof(RubyDrawInfo));
    if (!epub::limits::countCanGrow(fixedScratch, rubyPayloadBytes,
                                    epub::limits::MAX_RUBY_RENDER_SCRATCH_BYTES) ||
        !epub::limits::allocationPreflight(
            fixedScratch + rubyPayloadBytes,
            std::max(static_cast<size_t>(numWords) * sizeof(RubyDrawInfo), largestRubyPayload))) {
      LOG_ERR("TXB", "Ruby render scratch allocation refused");
      return;
    }
    if (!epub::limits::catchAllocationFailure([&]() { wordShiftArr.assign(numWords, 0); }) ||
        !epub::limits::checkedVectorResize(rubies, numWords,
                                           epub::limits::MAX_TEXT_BLOCK_WORDS)) {
      LOG_ERR("TXB", "Ruby render scratch allocation failed");
      return;
    }
    int accumulatedShift = 0;
    int lastEnd = -9999;
    for (uint16_t i = 0; i < numWords; i++) {
      wordShiftArr[i] = accumulatedShift;
      if (i < rubyTexts.size() && !rubyTexts[i].empty() && (wordStyle(i) & EpdFontFamily::RUBY_CONTINUE) == 0) {
        // Find the group size (how many words are part of this ruby annotation)
        int groupWordCount = 1;
        while (i + groupWordCount < numWords && (wordStyle(i + groupWordCount) & EpdFontFamily::RUBY_CONTINUE) != 0) {
          groupWordCount++;
        }

        // Compute actual width for the group
        int groupActualWidth = 0;
        for (int k = 0; k < groupWordCount; ++k) {
          groupActualWidth += renderer.getTextAdvanceX(fontId, wordText(i + k), wordStyle(i + k));
        }

        const char* word = wordText(i);
        const int leaderWordX = xposArr[i] + x;
        const int leaderWordX_shifted = leaderWordX + accumulatedShift;
        const auto baseDir =
            static_cast<BidiUtils::BidiBaseDir>(BidiUtils::detectParagraphLevel(word, blockStyle.isRtl ? 1 : 0));
        const int rubyWidth = renderer.getTextAdvanceX(fontId, rubyTexts[i].c_str(), EpdFontFamily::SUP);
        const int screenWidth = renderer.getScreenWidth();

        int rubyX = 0;
        int groupDrawX = 0;
        if (rubyWidth > groupActualWidth) {
          rubyX = leaderWordX_shifted - (rubyWidth - groupActualWidth) / 2;
          if (i == 0) {
            rubyX = std::max(leaderWordX_shifted, rubyX);
          }
          if (rubyX < lastEnd) {
            rubyX = lastEnd;
          }
          groupDrawX = rubyX + (rubyWidth - groupActualWidth) / 2;
        } else {
          groupDrawX = leaderWordX_shifted;
          rubyX = groupDrawX + (groupActualWidth - rubyWidth) / 2;
          if (i == 0) {
            rubyX = std::max(leaderWordX_shifted, rubyX);
          }
          if (rubyX < lastEnd) {
            const int push = lastEnd - rubyX;
            rubyX = lastEnd;
            groupDrawX += push;
          }
        }
        rubyX = std::max(0, std::min(rubyX, screenWidth - rubyWidth));
        // Keep groupDrawX aligned if rubyX was clamped by screen edges
        if (rubyWidth > groupActualWidth) {
          groupDrawX = rubyX + (rubyWidth - groupActualWidth) / 2;
        }

        RubyDrawInfo stagedRuby{rubyX, rubyWidth, {}, baseDir};
        if (!epub::limits::checkedStringAssign(stagedRuby.text, rubyTexts[i],
                                                epub::limits::MAX_RUBY_TEXT_BYTES)) {
          LOG_ERR("TXB", "Ruby render text allocation failed");
          return;
        }
        rubies[i] = std::move(stagedRuby);
        lastEnd = rubyX + rubyWidth;

        // Propagate shift to all words in the group and subsequent words
        const int groupShift = groupDrawX - leaderWordX;
        accumulatedShift = groupShift;
        for (int k = 0; k < groupWordCount; ++k) {
          wordShiftArr[i + k] = accumulatedShift;
        }
        i += groupWordCount - 1;
      }
    }
  }

  struct DecorationLineTracker {
    EpdFontFamily::Style style;
    int yOffset;
    int startX = -1;
    int endX = -1;
    int yPos = 0;

    bool active() const { return startX != -1; }
    void reset() {
      startX = -1;
      endX = -1;
      yPos = 0;
    }
  };

  DecorationLineTracker decorationLines[] = {
      {EpdFontFamily::UNDERLINE, ascender + 2},
      {EpdFontFamily::STRIKETHROUGH, ascender * 4 / 5},
  };

  const auto flushDecoration = [&](DecorationLineTracker& line) {
    if (line.active()) {
      renderer.drawLine(line.startX, line.yPos, line.endX, line.yPos, 2, true);
      line.reset();
    }
  };
  const auto flushDecorations = [&]() {
    for (auto& line : decorationLines) {
      flushDecoration(line);
    }
  };

  // Loop-invariant: hoisted out of the word loop so rubyTexts is scanned once,
  // not once per word.
  const int rubyShift = getRubyShift(ascender);

  for (uint16_t i = 0; i < numWords; i++) {
    const char* word = wordText(i);
    const int wordX = xposArr[i] + x;
    const EpdFontFamily::Style currentStyle = wordStyle(i);
    const auto baseDir =
        static_cast<BidiUtils::BidiBaseDir>(BidiUtils::detectParagraphLevel(word, blockStyle.isRtl ? 1 : 0));
    const uint8_t boundary = focusBoundary(i);

    // SUP/SUB shift the baseline passed to drawText; the glyph is also scaled 50% inside
    // drawText, so these offsets are chosen relative to the full-size ascender:
    //   SUP: raise by 40% of ascender — sits clearly above the cap-height
    //   SUB: lower by 25% of ascender — descends below baseline without clashing with ascenders below
    int wordY = y + rubyShift;
    if ((currentStyle & EpdFontFamily::SUP) != 0) {
      wordY -= ascender * 2 / 5;
    } else if ((currentStyle & EpdFontFamily::SUB) != 0) {
      wordY += ascender / 4;
    }

    const int drawX = wordX + (blockHasRuby ? wordShiftArr[i] : 0);

    if (boundary > 0) {
      // Focus split: draw bold prefix, then the regular suffix at a pre-computed x offset.
      // The bold prefix is bounded to 9 codepoints by the clamp on targetBoldChars in
      // ParsedText::addWord; 9 UTF-8 codepoints occupy at most 9 * 4 = 36 bytes, +1 for null = 37.
      // suffixX is computed at cache-creation time to avoid font metric lookups at render time.
      static constexpr size_t MAX_FOCUS_PREFIX_BYTES = 9 * 4 + 1;
      char boldBuf[40];
      static_assert(sizeof(boldBuf) >= MAX_FOCUS_PREFIX_BYTES,
                    "boldBuf too small for max focus prefix (9 codepoints * 4 UTF-8 bytes + null)");
      const auto boldStyle = static_cast<EpdFontFamily::Style>(currentStyle | EpdFontFamily::BOLD);
      const size_t boldLen =
          std::min<size_t>({static_cast<size_t>(boundary), static_cast<size_t>(wordTextLen(i)), sizeof(boldBuf) - 1});
      memcpy(boldBuf, word, boldLen);
      boldBuf[boldLen] = '\0';
      renderer.drawText(fontId, drawX, wordY, boldBuf, true, boldStyle, baseDir);
      const int suffixX = drawX + focusSuffixXArr[i];
      renderer.drawText(fontId, suffixX, wordY, word + boldLen, true, currentStyle, baseDir);
    } else {
      renderer.drawText(fontId, drawX, wordY, word, true, currentStyle, baseDir);
    }

    // Horizontal ruby text rendering
    if (blockHasRuby && i < rubyTexts.size() && !rubyTexts[i].empty() &&
        (wordStyle(i) & EpdFontFamily::RUBY_CONTINUE) == 0) {
      const int rubyY = wordY - ascender;
      renderer.drawText(fontId, rubies[i].x, rubyY, rubies[i].text.c_str(), true, EpdFontFamily::SUP,
                        rubies[i].baseDir);
    }

    if (scanning) {
      continue;
    }

    if (EpdFontFamily::hasTextDecoration(currentStyle)) {
      int lineStartX = drawX;
      int lineWidth = renderer.getTextWidth(fontId, word, currentStyle, baseDir);

      if ((currentStyle & (EpdFontFamily::SUP | EpdFontFamily::SUB)) != 0) {
        lineWidth = (lineWidth + 1) / 2;
      }

      // Do not decorate the synthetic em-space used for paragraph indentation.
      if (wordTextLen(i) >= 3 && static_cast<uint8_t>(word[0]) == 0xE2 && static_cast<uint8_t>(word[1]) == 0x80 &&
          static_cast<uint8_t>(word[2]) == 0x83) {
        const char* visibleText = word + 3;
        lineStartX += renderer.getTextAdvanceX(fontId, "\xe2\x80\x83", currentStyle);
        lineWidth = renderer.getTextWidth(fontId, visibleText, currentStyle, baseDir);
        if ((currentStyle & (EpdFontFamily::SUP | EpdFontFamily::SUB)) != 0) {
          lineWidth = (lineWidth + 1) / 2;
        }
      }

      for (auto& line : decorationLines) {
        if ((currentStyle & line.style) == 0) {
          flushDecoration(line);
          continue;
        }

        const int lineY = wordY + line.yOffset;
        if (line.active() && line.yPos != lineY) {
          flushDecoration(line);
        }
        if (!line.active()) {
          line.startX = lineStartX;
          line.yPos = lineY;
        }
        line.endX = lineStartX + lineWidth;
      }
    } else {
      flushDecorations();
    }
  }
  flushDecorations();
}

bool TextBlock::serialize(HalFile& file) const {
  if (!isValid) {
    LOG_ERR("TXB", "Serialization failed: invalid block");
    return false;
  }

  // Word data: scalars, then the arena verbatim -- its in-memory layout is
  // exactly the on-disk layout (see TextBlock.h), so one write covers all
  // per-word arrays and the text blob.
  if (!serialization::writePod(file, numWords) ||
      !serialization::writePod(file, static_cast<uint8_t>(focusPresent ? 1 : 0)) ||
      !serialization::writePod(file, textBytes)) {
    return false;
  }
  if (numWords > 0) {
    const size_t size = arenaSize(numWords, focusPresent, textBytes);
    if (file.write(arena.get(), size) != size) {
      LOG_ERR("TXB", "Serialization failed: arena write (%u bytes)", static_cast<uint32_t>(size));
      return false;
    }
  }

  // Ruby text data
  for (size_t i = 0; i < numWords; i++) {
    const std::string empty;
    const std::string& ruby = i < rubyTexts.size() ? rubyTexts[i] : empty;
    if (ruby.size() > epub::limits::MAX_RUBY_TEXT_BYTES || !serialization::writeString(file, ruby)) return false;
  }

  // Style (alignment + margins/padding/indent)
  return serialization::writePod(file, blockStyle.alignment) &&
         serialization::writePod(file, blockStyle.textAlignDefined) &&
         serialization::writePod(file, blockStyle.marginTop) &&
         serialization::writePod(file, blockStyle.marginBottom) &&
         serialization::writePod(file, blockStyle.marginLeft) &&
         serialization::writePod(file, blockStyle.marginRight) &&
         serialization::writePod(file, blockStyle.paddingTop) &&
         serialization::writePod(file, blockStyle.paddingBottom) &&
         serialization::writePod(file, blockStyle.paddingLeft) &&
         serialization::writePod(file, blockStyle.paddingRight) &&
         serialization::writePod(file, blockStyle.textIndent) &&
         serialization::writePod(file, blockStyle.textIndentDefined) &&
         serialization::writePod(file, blockStyle.isRtl) &&
         serialization::writePod(file, blockStyle.directionDefined);
}

size_t TextBlock::serializedSize() const {
  size_t result = sizeof(numWords) + sizeof(uint8_t) + sizeof(textBytes) +
                  arenaSize(numWords, focusPresent, textBytes) + SERIALIZED_BLOCK_STYLE_BYTES;
  for (size_t i = 0; i < numWords; ++i) {
    const size_t bytes = i < rubyTexts.size() ? rubyTexts[i].size() : 0;
    if (!epub::limits::countCanGrow(result, sizeof(uint32_t) + bytes, SIZE_MAX)) return SIZE_MAX;
    result += sizeof(uint32_t) + bytes;
  }
  return result;
}

size_t TextBlock::retainedSize() const {
  size_t result = sizeof(TextBlock) + arenaSize(numWords, focusPresent, textBytes) +
                  rubyTexts.capacity() * sizeof(std::string);
  for (const auto& ruby : rubyTexts) {
    if (!ruby.empty()) result += ruby.size() + 1;
  }
  return result;
}

std::unique_ptr<TextBlock> TextBlock::deserialize(
    HalFile& file, epub::limits::PageDecodeBudget* const budget,
    epub::limits::PageDecodeFailure* const failure) {
  uint16_t wc = 0;
  uint8_t hasFocus = 0;
  uint16_t textBytes = 0;
  if (!readPagePod(file, wc, budget) || !readPagePod(file, hasFocus, budget) ||
      !readPagePod(file, textBytes, budget) || hasFocus > 1) {
    LOG_ERR("TXB", "Deserialization failed: truncated header");
    return nullptr;
  }

  // Sanity checks: cap the arena allocation and reject impossible geometry
  // (every word carries at least its NUL terminator).
  if (wc > epub::limits::MAX_TEXT_BLOCK_WORDS) {
    LOG_ERR("TXB", "Deserialization failed: word count %u exceeds maximum", wc);
    return nullptr;
  }
  if ((wc == 0 && textBytes != 0) || (wc > 0 && textBytes < wc)) {
    LOG_ERR("TXB", "Deserialization failed: bad text size %u for %u words", textBytes, wc);
    return nullptr;
  }

  if (budget && !budget->tryRetain(epub::limits::RETAINED_TEXT_BLOCK_FIXED_BYTES,
                                    sizeof(TextBlock))) {
    if (budget->resourceRefused()) epub::limits::markPageDecodeResourceRefusal(failure);
    return nullptr;
  }
  std::unique_ptr<TextBlock> block(new (std::nothrow) TextBlock());
  if (!block) {
    epub::limits::markPageDecodeResourceRefusal(failure);
    LOG_ERR("TXB", "OOM: TextBlock");
    return nullptr;
  }
  block->numWords = wc;
  block->textBytes = textBytes;
  block->focusPresent = hasFocus != 0;

  if (wc > 0) {
    const size_t size = arenaSize(wc, block->focusPresent, textBytes);
    const size_t pos = file.position();
    const size_t fileSize = file.size();
    if (pos > fileSize || size > fileSize - pos ||
        (budget && size > budget->serializedRemaining())) {
      LOG_ERR("TXB", "Deserialization failed: arena exceeds remaining bytes");
      return nullptr;
    }
    if (budget && !budget->tryRetain(size, size)) {
      if (budget->resourceRefused()) epub::limits::markPageDecodeResourceRefusal(failure);
      return nullptr;
    }
    if (budget && !budget->tryConsumeSerialized(size)) return nullptr;
    block->arena = makeUniqueNoThrow<uint8_t[]>(size);
    if (!block->arena) {
      epub::limits::markPageDecodeResourceRefusal(failure);
      LOG_ERR("TXB", "OOM: arena %u bytes", static_cast<uint32_t>(size));
      return nullptr;
    }
    if (file.read(block->arena.get(), size) != size) {
      LOG_ERR("TXB", "Deserialization failed: arena read (%u bytes)", static_cast<uint32_t>(size));
      return nullptr;
    }
    block->bindArenaPointers();

    // Validate offsets before anything dereferences wordText(): offset 0 first,
    // strictly increasing, in bounds, and every word NUL-terminated (word i ends
    // at the byte before offset i+1; the last word at the last text byte).
    const uint16_t* textOff = block->textOffArr;
    const char* text = block->textArr;
    if (textOff[0] != 0 || text[textBytes - 1] != '\0') {
      LOG_ERR("TXB", "Deserialization failed: corrupt text layout");
      return nullptr;
    }
    for (uint16_t i = 1; i < wc; i++) {
      if (textOff[i] <= textOff[i - 1] || textOff[i] >= textBytes || text[textOff[i] - 1] != '\0') {
        LOG_ERR("TXB", "Deserialization failed: corrupt word offset %u", i);
        return nullptr;
      }
    }
  }

  // Ruby text data. Ruby is a CJK feature, so for nearly every book every entry here
  // is the empty string. Materializing the vector regardless costs wordCount * 24 bytes
  // (sizeof(std::string)) plus a heap block per line, held for as long as the page is
  // resident -- several KB of DRAM on a full page, none of it ever read. An empty
  // rubyTexts is already the "no ruby" representation: hasRuby() reports false and every
  // other reader is guarded by `i < rubyTexts.size()`, so allocate lazily and only once a
  // non-empty annotation actually shows up.
  //
  // `scratch` is reused across words: readString() resizes it to the incoming length and
  // overwrites every byte, so a moved-from value carries nothing into the next iteration.
  std::string scratch;
  size_t rubyBytes = 0;
  for (uint16_t i = 0; i < wc; i++) {
    if (!readPageString(file, scratch, epub::limits::MAX_RUBY_TEXT_BYTES, budget, failure) ||
        !epub::limits::rubyTextFits(rubyBytes, scratch.size())) {
      LOG_ERR("TXB", "Deserialization failed: invalid ruby text");
      return nullptr;
    }
    rubyBytes += scratch.size();
    if (scratch.empty()) continue;
    if (block->rubyTexts.empty()) {
      const size_t denseBytes = static_cast<size_t>(wc) * sizeof(std::string);
      if (budget && !budget->tryRetain(denseBytes, denseBytes)) {
        if (budget->resourceRefused()) epub::limits::markPageDecodeResourceRefusal(failure);
        return nullptr;
      }
      if (!epub::limits::checkedVectorResize(block->rubyTexts, wc,
                                              epub::limits::MAX_TEXT_BLOCK_WORDS)) {
        epub::limits::markPageDecodeResourceRefusal(failure);
        return nullptr;
      }
    }
    block->rubyTexts[i] = std::move(scratch);
  }

  // Style (alignment + margins/padding/indent)
  BlockStyle& blockStyle = block->blockStyle;
  if (!readPagePod(file, blockStyle.alignment, budget) ||
      !readPagePod(file, blockStyle.textAlignDefined, budget) ||
      !readPagePod(file, blockStyle.marginTop, budget) ||
      !readPagePod(file, blockStyle.marginBottom, budget) ||
      !readPagePod(file, blockStyle.marginLeft, budget) ||
      !readPagePod(file, blockStyle.marginRight, budget) ||
      !readPagePod(file, blockStyle.paddingTop, budget) ||
      !readPagePod(file, blockStyle.paddingBottom, budget) ||
      !readPagePod(file, blockStyle.paddingLeft, budget) ||
      !readPagePod(file, blockStyle.paddingRight, budget) ||
      !readPagePod(file, blockStyle.textIndent, budget) ||
      !readPagePod(file, blockStyle.textIndentDefined, budget) ||
      !readPagePod(file, blockStyle.isRtl, budget) ||
      !readPagePod(file, blockStyle.directionDefined, budget)) {
    LOG_ERR("TXB", "Deserialization failed: truncated style");
    return nullptr;
  }

  return block;
}
