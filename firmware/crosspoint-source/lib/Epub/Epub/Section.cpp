#include "Section.h"

#include <HalStorage.h>
#include <Logging.h>
#include <Memory.h>
#include <Serialization.h>

#include "Epub/css/CssParser.h"
#include "Page.h"
#include "SectionReadTransaction.h"
#include "hyphenation/Hyphenator.h"
#include "parsers/ChapterHtmlSlimParser.h"

namespace {
// v28: text decoration bits now include line-through in serialized wordStyles.
// v29: TextBlock word data stored as one flat arena (offset table + NUL-terminated
// text blob) instead of length-prefixed strings and per-field arrays.
// v30: Arabic shaping changed both drawing and measurement (getTextAdvanceX now
//      measures the shaped visual text); cached word positions from v29 no longer
//      match what drawText renders.
// v32: ImageBlock serializes the book-internal source href after the cache path
//      (lazy extraction: images are header-probed at build time and extracted on
//      first render).
// v33: Support <ruby> and <rt> tags. Skip <rp> tags
// v34: Word gaps are only suppressed for tokens glued in the source, so spaces between
//      Hangul words survive again; ruby element boundaries carry the continuation flag
//      instead. Invalidates v33 caches, whose word positions have the spaces collapsed.

// v34: <br> handling changed layout — a <br> after text is now a margin-stripped
//      line break (browser-like) and only a <br> whose block stays empty injects
//      the scene-break gap, so cached pages laid out by older versions no longer
//      match. Keeps <br>-per-paragraph books (common CJK formatting) from
//      re-adding container spacing at every paragraph.
// v35: Persist a uint32_t visible-text start offset for every page.
// v36: Rebuild pre-hardening caches so all retained files have bounded/exact
//      string, element, page-count, and LUT validation.
// v37: Per-page byte spans, aggregate page/anchor budgets and exact transactional
//      writes are mandatory; older caches cannot prove those invariants.
constexpr uint8_t SECTION_FILE_VERSION = 37;
// Written into the version field while a build is in progress; patched to
// SECTION_FILE_VERSION only when the build is finalized. An abandoned /
// crash-interrupted .bin therefore carries version 0, which loadSectionFile rejects
// as unknown and clears -- so an incomplete file is never mistaken for a valid one.
constexpr uint8_t SECTION_FILE_INCOMPLETE_VERSION = 0;
// Written when a build is suspended partway (reader exited or device slept mid-build).
// The file carries valid pages 0..pageCount-1, all LUTs, and a trailer with the parse
// watermark (bytesConsumed, totalBytes) appended after the li LUT. loadSectionFile
// accepts it so a resume shows those pages instantly; the reader extends it by
// rebuilding in the background. Uses the same header layout as SECTION_FILE_VERSION,
// so finalized files are untouched by this feature; older firmware treats the sentinel
// as an unknown version and rebuilds, which is a safe downgrade.
// MUST change in lockstep with SECTION_FILE_VERSION: the sentinel IS the partial's
// format version, so a stale-format partial otherwise passes the header check and
// only fails (noisily, via the block-decode error path) when a page is loaded.
// Derived so the pairing can't be forgotten: 0xFE for v28, 0xFD for v29, ...
constexpr uint8_t SECTION_FILE_PARTIAL_VERSION = 0xFE - (SECTION_FILE_VERSION - 28);
constexpr uint32_t HEADER_SIZE = sizeof(uint8_t) + sizeof(int) + sizeof(float) + sizeof(bool) + sizeof(uint8_t) +
                                 sizeof(uint16_t) + sizeof(uint16_t) + sizeof(uint16_t) + sizeof(bool) + sizeof(bool) +
                                 sizeof(uint8_t) + sizeof(bool) + sizeof(uint32_t) + sizeof(uint32_t) +
                                 sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint32_t);

Section::LoadFailure toSectionLoadFailure(const epub::limits::PageDecodeFailure failure) noexcept {
  return failure == epub::limits::PageDecodeFailure::ResourceRefused
             ? Section::LoadFailure::ResourceRefused
             : Section::LoadFailure::Corrupt;
}

}  // namespace

// Out-of-line so the unique_ptr<ChapterHtmlSlimParser> in BuildContext can be
// constructed/destroyed where the parser's full definition is visible.
Section::Section(const std::shared_ptr<Epub>& epub, const int spineIndex, GfxRenderer& renderer)
    : epub(epub),
      spineIndex(spineIndex),
      renderer(renderer),
      filePath(epub->getCachePath() + "/sections/" + std::to_string(spineIndex) + ".bin") {}

// Suspend any in-progress build so every section.reset() / navigation / sleep path
// persists the pages already laid out as a partial .bin instead of discarding them
// (no-op once a build has completed or never started).
Section::~Section() noexcept {
  if (!epub::limits::catchAllocationFailure([&]() { suspendBuild(); })) {
    LOG_ERR("SCT", "Allocation failed while suspending section; abandoning transaction");
    abandonBuildNoThrow();
  }
}

bool Section::loadSectionFile(const ReaderRenderSpec& spec) {
  bool result = false;
  if (!epub::limits::catchAllocationFailure([&]() { result = loadSectionFileImpl(spec); })) {
    LOG_ERR("SCT", "Allocation failed while loading section cache");
    abandonBuildNoThrow();
    return false;
  }
  return result;
}

bool Section::startBuild(const ReaderRenderSpec& spec, const std::function<void()>& popupFn) {
  bool result = false;
  if (!epub::limits::catchAllocationFailure([&]() { result = startBuildImpl(spec, popupFn); })) {
    LOG_ERR("SCT", "Allocation failed while starting section build");
    abandonBuildNoThrow();
    return false;
  }
  return result;
}

bool Section::buildSomeMore(const int maxPages) {
  bool result = false;
  if (!epub::limits::catchAllocationFailure([&]() { result = buildSomeMoreImpl(maxPages); })) {
    LOG_ERR("SCT", "Allocation failed while extending section build");
    abandonBuildNoThrow();
    return false;
  }
  return result;
}

std::unique_ptr<Page> Section::loadPage(const int page) {
  lastPageLoadFailure_ = LoadFailure::None;
  LoadFailure failure = LoadFailure::Corrupt;
  std::unique_ptr<Page> result;
  if (!epub::limits::catchAllocationFailure([&]() { result = loadPageImpl(page, failure); })) {
    LOG_ERR("SCT", "Allocation failed while loading page");
    if (!activeBuildCursorSafe_) {
      LOG_ERR("SCT", "Could not restore active-build write cursor; abandoning temp transaction");
      abandonBuildNoThrow();
      activeBuildCursorSafe_ = true;
      lastPageLoadFailure_ = LoadFailure::RestartRequired;
      return nullptr;
    }
    lastPageLoadFailure_ = LoadFailure::ResourceRefused;
    return nullptr;
  }
  if (!activeBuildCursorSafe_) {
    LOG_ERR("SCT", "Could not restore active-build write cursor; abandoning temp transaction");
    abandonBuildNoThrow();
    activeBuildCursorSafe_ = true;
    failure = LoadFailure::RestartRequired;
    result.reset();
  }
  if (!result) lastPageLoadFailure_ = failure;
  return result;
}

uint32_t Section::onPageComplete(std::unique_ptr<Page> page) {
  if (!file) {
    LOG_ERR("SCT", "File not open for writing page %d", builtPageCount_);
    return 0;
  }

  const uint32_t position = file.position();
  if (!page->serialize(file)) {
    LOG_ERR("SCT", "Failed to serialize page %d", builtPageCount_);
    return 0;
  }
  const uint32_t endPosition = file.position();
  if (position < HEADER_SIZE || endPosition <= position ||
      endPosition - position > epub::limits::MAX_SERIALIZED_PAGE_BYTES) {
    LOG_ERR("SCT", "Serialized page %d exceeded its byte budget", builtPageCount_);
    return 0;
  }
  LOG_DBG("SCT", "Page %d processed", builtPageCount_);

  builtPageCount_++;
  // pageCount is the pages available to read: a rebuild over a partial only raises it
  // once it has laid out more pages than the partial already covers.
  if (builtPageCount_ > pageCount) {
    pageCount = builtPageCount_;
  }
  return position;
}

bool Section::writeSectionFileHeader(const ReaderRenderSpec& spec) {
  if (!file) {
    LOG_DBG("SCT", "File not open for writing header");
    return false;
  }
  static_assert(HEADER_SIZE == sizeof(SECTION_FILE_VERSION) + sizeof(spec.fontId) + sizeof(spec.lineCompression) +
                                   sizeof(spec.extraParagraphSpacing) + sizeof(spec.paragraphAlignment) +
                                   sizeof(spec.viewportWidth) + sizeof(spec.viewportHeight) + sizeof(pageCount) +
                                   sizeof(spec.hyphenationEnabled) + sizeof(spec.embeddedStyle) +
                                   sizeof(spec.imageRendering) + sizeof(spec.focusReadingEnabled) + sizeof(uint32_t) +
                                   sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint32_t),
                "Header size mismatch");
  // Written as the incomplete sentinel; finalizeBuild() patches it to
  // SECTION_FILE_VERSION as the last step, committing the file.
  const uint32_t zero = 0;
  return serialization::writePod(file, SECTION_FILE_INCOMPLETE_VERSION) &&
         serialization::writePod(file, spec.fontId) && serialization::writePod(file, spec.lineCompression) &&
         serialization::writePod(file, spec.extraParagraphSpacing) &&
         serialization::writePod(file, spec.paragraphAlignment) &&
         serialization::writePod(file, spec.viewportWidth) && serialization::writePod(file, spec.viewportHeight) &&
         serialization::writePod(file, spec.hyphenationEnabled) &&
         serialization::writePod(file, spec.embeddedStyle) && serialization::writePod(file, spec.imageRendering) &&
         serialization::writePod(file, spec.focusReadingEnabled) &&
         serialization::writePod(file, pageCount) &&  // placeholder, patched later
         serialization::writePod(file, zero) && serialization::writePod(file, zero) &&
         serialization::writePod(file, zero) && serialization::writePod(file, zero) &&
         serialization::writePod(file, zero);
}

bool Section::loadSectionFileImpl(const ReaderRenderSpec& spec) {
  if (!Storage.openFileForRead("SCT", filePath, file)) {
    return false;
  }

  const auto rejectCache = [this](const char* reason) {
    file.close();
    LOG_ERR("SCT", "Deserialization failed: %s", reason);
    clearCache();
    pageCount = 0;
    partial_ = false;
    partialPageCount_ = 0;
    partialBytesConsumed_ = 0;
    partialTotalBytes_ = 0;
    return false;
  };
  const uint64_t fileSize = file.fileSize64();
  if (fileSize < HEADER_SIZE) return rejectCache("truncated section header");

  // Match parameters
  bool filePartial = false;
  {
    uint8_t version = 0;
    if (!serialization::readPod(file, version)) return rejectCache("truncated section version");
    if (version != SECTION_FILE_VERSION && version != SECTION_FILE_PARTIAL_VERSION) {
      return rejectCache("unknown section version");
    }
    filePartial = (version == SECTION_FILE_PARTIAL_VERSION);

    int fileFontId;
    uint16_t fileViewportWidth, fileViewportHeight;
    float fileLineCompression;
    bool fileExtraParagraphSpacing;
    uint8_t fileParagraphAlignment;
    bool fileHyphenationEnabled;
    bool fileEmbeddedStyle;
    uint8_t fileImageRendering;
    bool fileFocusReadingEnabled;
    if (!serialization::readPod(file, fileFontId) || !serialization::readPod(file, fileLineCompression) ||
        !serialization::readPod(file, fileExtraParagraphSpacing) ||
        !serialization::readPod(file, fileParagraphAlignment) ||
        !serialization::readPod(file, fileViewportWidth) ||
        !serialization::readPod(file, fileViewportHeight) ||
        !serialization::readPod(file, fileHyphenationEnabled) ||
        !serialization::readPod(file, fileEmbeddedStyle) ||
        !serialization::readPod(file, fileImageRendering) ||
        !serialization::readPod(file, fileFocusReadingEnabled)) {
      return rejectCache("truncated render parameters");
    }

    if (spec.fontId != fileFontId || spec.lineCompression != fileLineCompression ||
        spec.extraParagraphSpacing != fileExtraParagraphSpacing || spec.paragraphAlignment != fileParagraphAlignment ||
        spec.viewportWidth != fileViewportWidth || spec.viewportHeight != fileViewportHeight ||
        spec.hyphenationEnabled != fileHyphenationEnabled || spec.embeddedStyle != fileEmbeddedStyle ||
        spec.imageRendering != fileImageRendering || spec.focusReadingEnabled != fileFocusReadingEnabled) {
      return rejectCache("render parameters do not match");
    }
  }

  uint32_t lutOffset = 0;
  uint32_t anchorMapOffset = 0;
  uint32_t paragraphLutOffset = 0;
  uint32_t liLutOffset = 0;
  uint32_t visibleLutOffset = 0;
  if (!serialization::readPod(file, pageCount) || !serialization::readPod(file, lutOffset) ||
      !serialization::readPod(file, anchorMapOffset) || !serialization::readPod(file, paragraphLutOffset) ||
      !serialization::readPod(file, liLutOffset) || !serialization::readPod(file, visibleLutOffset)) {
    return rejectCache("truncated section offsets");
  }
  if (pageCount > epub::limits::MAX_PAGES_PER_SPINE ||
      static_cast<size_t>(pageCount) * epub::limits::SECTION_LUT_ENTRY_BYTES >
          epub::limits::MAX_SECTION_LUT_BYTES) {
    return rejectCache("page count exceeds safety limit");
  }

  const uint64_t pageLutEnd = static_cast<uint64_t>(lutOffset) + static_cast<uint64_t>(pageCount) * sizeof(uint32_t);
  const uint64_t paragraphLutEnd = static_cast<uint64_t>(paragraphLutOffset) + sizeof(uint16_t) +
                                   static_cast<uint64_t>(pageCount) * sizeof(uint16_t);
  const uint64_t liLutEnd =
      static_cast<uint64_t>(liLutOffset) + static_cast<uint64_t>(pageCount) * sizeof(uint16_t);
  const uint64_t visibleLutEnd =
      static_cast<uint64_t>(visibleLutOffset) + static_cast<uint64_t>(pageCount) * sizeof(uint32_t);
  if (lutOffset < HEADER_SIZE || pageLutEnd != anchorMapOffset ||
      static_cast<uint64_t>(anchorMapOffset) + sizeof(uint16_t) > paragraphLutOffset ||
      paragraphLutEnd != liLutOffset || liLutEnd != visibleLutOffset || visibleLutEnd > fileSize) {
    return rejectCache("invalid section LUT bounds");
  }

  // Validate every page span before accepting the cache. Page::deserialize is
  // then always called with an exact, bounded byte count rather than the rest of
  // the section file.
  uint32_t previousPageOffset = 0;
  if (!file.seek(lutOffset)) return rejectCache("invalid page LUT seek");
  for (uint16_t i = 0; i < pageCount; ++i) {
    uint32_t pageOffset = 0;
    if (!serialization::readPod(file, pageOffset) || pageOffset < HEADER_SIZE || pageOffset >= lutOffset ||
        (i == 0 && pageOffset != HEADER_SIZE) ||
        (i > 0 && (pageOffset <= previousPageOffset ||
                   pageOffset - previousPageOffset > epub::limits::MAX_SERIALIZED_PAGE_BYTES))) {
      return rejectCache("invalid serialized page span");
    }
    previousPageOffset = pageOffset;
  }
  if ((pageCount == 0 && lutOffset != HEADER_SIZE) ||
      (pageCount > 0 && (lutOffset <= previousPageOffset ||
                         lutOffset - previousPageOffset > epub::limits::MAX_SERIALIZED_PAGE_BYTES))) {
    return rejectCache("invalid trailing page span");
  }

  if (!file.seek(anchorMapOffset)) return rejectCache("invalid anchor map seek");
  uint16_t anchorCount = 0;
  if (!serialization::readPod(file, anchorCount) || anchorCount > epub::limits::MAX_ANCHORS_PER_SPINE) {
    return rejectCache("anchor count exceeds safety limit");
  }
  epub::limits::AnchorBudget cachedAnchorBudget(epub::limits::MAX_RETAINED_ANCHOR_BYTES);
  for (uint16_t i = 0; i < anchorCount; ++i) {
    std::string anchor;
    uint16_t page = 0;
    if (!serialization::readString(file, anchor, epub::limits::MAX_ANCHOR_BYTES) ||
        !cachedAnchorBudget.tryRetain(epub::limits::anchorRetainedBytes(anchor.size())) ||
        !serialization::readPod(file, page) || page >= pageCount) {
      return rejectCache("invalid anchor map entry");
    }
  }
  if (file.position() != paragraphLutOffset) return rejectCache("anchor map has trailing bytes");

  if (!file.seek(paragraphLutOffset)) return rejectCache("invalid paragraph LUT seek");
  uint16_t paragraphCount = 0;
  if (!serialization::readPod(file, paragraphCount) || paragraphCount != pageCount) {
    return rejectCache("paragraph LUT count mismatch");
  }

  if (filePartial) {
    // A partial's pageCount is the watermark of a suspended build. Read the watermark
    // trailer (appended after the visible-offset LUT) so estimatedTotalPages can extrapolate.
    const uint64_t trailerOffset = visibleLutEnd;
    const bool trailerValid = pageCount > 0 && trailerOffset + 2 * sizeof(uint32_t) == fileSize;
    if (!trailerValid) return rejectCache("malformed partial section");
    if (!file.seek(trailerOffset)) return rejectCache("invalid partial trailer seek");
    if (!serialization::readPod(file, partialBytesConsumed_) ||
        !serialization::readPod(file, partialTotalBytes_) || partialBytesConsumed_ == 0 ||
        partialBytesConsumed_ > partialTotalBytes_ ||
        !epub::limits::inflatedSpineFits(partialTotalBytes_)) {
      return rejectCache("invalid partial parse watermark");
    }
    partial_ = true;
    partialPageCount_ = pageCount;
  } else if (visibleLutEnd != fileSize) {
    return rejectCache("finalized section has trailing bytes");
  }

  // Explicit close() required: member variable persists beyond function scope
  file.close();
  LOG_DBG("SCT", "Deserialization succeeded: %d pages%s", pageCount, filePartial ? " (partial)" : "");
  return true;
}

// Your updated class method (assuming you are using the 'SD' object, which is a wrapper for a specific filesystem)
bool Section::clearCache() const {
  const std::string tmpBin = binTmpPath();
  if (Storage.exists(tmpBin.c_str())) {
    Storage.remove(tmpBin.c_str());
  }
  if (!Storage.exists(filePath.c_str())) {
    LOG_DBG("SCT", "Cache does not exist, no action needed");
    return true;
  }

  if (!Storage.remove(filePath.c_str())) {
    LOG_ERR("SCT", "Failed to clear cache");
    return false;
  }

  LOG_DBG("SCT", "Cache cleared successfully");
  return true;
}

bool Section::createSectionFile(const ReaderRenderSpec& spec, const std::function<void()>& popupFn) {
  // One-shot build: start, then lay out the whole section in a single pass.
  if (!startBuild(spec, popupFn)) {
    return false;
  }
  if (!buildSomeMore(0)) {  // 0 = build to completion
    return false;
  }
  return buildComplete_;
}

bool Section::startBuildImpl(const ReaderRenderSpec& spec, const std::function<void()>& popupFn) {
  if (build_) {
    LOG_ERR("SCT", "startBuild called while a build is already active");
    return false;
  }
  buildComplete_ = false;
  builtPageCount_ = 0;
  // Pages from a loaded partial stay readable (from filePath) while this build writes
  // to the tmp .bin, so availability never drops below the partial's watermark.
  pageCount = partial_ ? partialPageCount_ : 0;

  // Remove a stale tmp .bin from a crash-interrupted build; this build recreates it.
  {
    const std::string staleTmp = binTmpPath();
    if (Storage.exists(staleTmp.c_str())) {
      Storage.remove(staleTmp.c_str());
    }
  }

  const auto localPath = epub->getSpineItem(spineIndex).href;
  const auto htmlDir = epub->getCachePath() + "/html";
  const auto htmlPath = htmlDir + "/" + std::to_string(spineIndex) + ".html";
  const auto tmpHtmlPath = htmlDir + "/.tmp_" + std::to_string(spineIndex) + ".html";

  size_t declaredSpineBytes = 0;
  if (!epub->getItemSize(localPath, &declaredSpineBytes) || declaredSpineBytes == 0 ||
      !epub::limits::inflatedSpineFits(declaredSpineBytes)) {
    LOG_ERR("SCT", "Refusing spine with invalid inflated size: %u", static_cast<unsigned>(declaredSpineBytes));
    return false;
  }

  // Create cache directory if it doesn't exist
  {
    const auto sectionsDir = epub->getCachePath() + "/sections";
    Storage.mkdir(sectionsDir.c_str());
  }

  // Reuse the previously unzipped HTML if we already have it. The unzipped HTML is keyed only on the
  // book (it lives in the per-book cache dir), not on render settings, so it survives the invalidation
  // that wipes the layout (.bin) caches when font/margin/orientation change -- rebuilds then skip zip
  // inflation entirely. It's promoted by an atomic rename as soon as the inflate succeeds (below), so
  // even a window-only giant spine -- whose .bin never finalizes -- still caches its HTML, letting a
  // reopen skip the multi-second inflate. If htmlPath exists it is known-complete.
  bool reusedHtml = Storage.exists(htmlPath.c_str());
  if (reusedHtml) {
    HalFile cachedHtml;
    if (!Storage.openFileForRead("SCT", htmlPath, cachedHtml) || cachedHtml.size() != declaredSpineBytes ||
        !epub::limits::inflatedSpineFits(cachedHtml.size())) {
      if (cachedHtml) cachedHtml.close();
      Storage.remove(htmlPath.c_str());
      reusedHtml = false;
      LOG_ERR("SCT", "Removed malformed cached spine HTML");
    } else {
      cachedHtml.close();
    }
  }
  bool htmlCached = reusedHtml;
  if (reusedHtml) {
    LOG_DBG("SCT", "Reusing cached HTML %s", htmlPath.c_str());
  } else {
    Storage.mkdir(htmlDir.c_str());

    // Retry logic for SD card timing issues
    bool streamed = false;
    uint32_t fileSize = 0;
    for (int attempt = 0; attempt < 3 && !streamed; attempt++) {
      if (attempt > 0) {
        LOG_DBG("SCT", "Retrying stream (attempt %d)...", attempt + 1);
        delay(50);  // Brief delay before retry
      }

      // Remove any incomplete file from previous attempt before retrying
      if (Storage.exists(tmpHtmlPath.c_str())) {
        Storage.remove(tmpHtmlPath.c_str());
      }

      HalFile tmpHtml;
      if (!Storage.openFileForWrite("SCT", tmpHtmlPath, tmpHtml)) {
        continue;
      }
      // Larger chunks mean far fewer SD writes inflating the HTML; a 1KB chunk turned a 584KB
      // single-spine novel into ~570 tiny writes (multi-second). 8KB keeps the transient buffers
      // small while cutting the write count 8x.
      streamed = epub->readItemContentsToStream(localPath, tmpHtml, 8192);
      fileSize = tmpHtml.size();
      // Explicitly close() file before calling Storage.remove()
      tmpHtml.close();

      if (streamed && (fileSize != declaredSpineBytes || !epub::limits::inflatedSpineFits(fileSize))) {
        LOG_ERR("SCT", "Inflated spine size mismatch: declared=%u actual=%u",
                static_cast<unsigned>(declaredSpineBytes), static_cast<unsigned>(fileSize));
        streamed = false;
      }

      // If streaming failed, remove the incomplete file immediately
      if (!streamed && Storage.exists(tmpHtmlPath.c_str())) {
        Storage.remove(tmpHtmlPath.c_str());
        LOG_DBG("SCT", "Removed incomplete temp file after failed attempt");
      }
    }

    if (!streamed) {
      LOG_ERR("SCT", "Failed to stream item contents to temp file after retries");
      return false;
    }

    LOG_DBG("SCT", "Streamed temp HTML to %s (%d bytes)", tmpHtmlPath.c_str(), fileSize);

    // Promote to the persistent HTML cache immediately -- the inflate is complete and the bytes are
    // valid regardless of whether the layout build finishes, so reopening (even a window-only spine
    // that never finalizes its .bin) skips re-inflation. If the rename fails we just parse the temp.
    if (Storage.rename(tmpHtmlPath.c_str(), htmlPath.c_str())) {
      htmlCached = true;
    } else {
      LOG_DBG("SCT", "Failed to promote HTML cache; parsing from temp");
    }
  }

  if (!Storage.openFileForWrite("SCT", binTmpPath(), file)) {
    if (!reusedHtml) Storage.remove(tmpHtmlPath.c_str());
    return false;
  }
  // Header is written with the incomplete-version sentinel; finalizeBuild() commits it.
  if (!writeSectionFileHeader(spec)) {
    file.close();
    Storage.remove(binTmpPath().c_str());
    if (!reusedHtml) Storage.remove(tmpHtmlPath.c_str());
    return false;
  }

  auto ctx = makeUniqueNoThrow<BuildContext>();
  if (!ctx) {
    LOG_ERR("SCT", "OOM: BuildContext");
    file.close();
    Storage.remove(binTmpPath().c_str());
    if (!reusedHtml) Storage.remove(tmpHtmlPath.c_str());
    return false;
  }
  // htmlCached == "htmlPath is the live cache" (reused, or just promoted). finalizeBuild/abandonBuild
  // then leave the cached HTML alone; only an un-promoted temp (rename failed) is theirs to clean up.
  ctx->reusedHtml = htmlCached;
  ctx->htmlPath = htmlPath;
  ctx->tmpHtmlPath = tmpHtmlPath;
  ctx->parsePath = htmlCached ? htmlPath : tmpHtmlPath;

  // Derive the content base directory and image cache path prefix for the parser
  const size_t lastSlash = localPath.find_last_of('/');
  ctx->contentBase = (lastSlash != std::string::npos) ? localPath.substr(0, lastSlash + 1) : "";
  ctx->imageBasePath = epub->getCachePath() + "/img_" + std::to_string(spineIndex) + "_";

  if (spec.embeddedStyle) {
    ctx->cssParser = epub->getCssParser();
    if (ctx->cssParser && !ctx->cssParser->loadFromCache()) {
      LOG_ERR("SCT", "Failed to load CSS from cache");
    }
  }

  // Collect TOC anchors for this spine so the parser can insert page breaks at chapter boundaries
  std::vector<std::string> tocAnchors;
  epub::limits::AnchorBudget anchorBudget(epub::limits::MAX_RETAINED_ANCHOR_BYTES);
  const int startTocIndex = epub->getTocIndexForSpineIndex(spineIndex);
  if (startTocIndex >= 0) {
    for (int i = startTocIndex; i < epub->getTocItemsCount(); i++) {
      auto entry = epub->getTocItem(i);
      if (entry.spineIndex != spineIndex) break;
      if (!entry.anchor.empty()) {
        const size_t retained = epub::limits::anchorRetainedBytes(entry.anchor.size());
        if (entry.anchor.size() > epub::limits::MAX_ANCHOR_BYTES ||
            tocAnchors.size() >= epub::limits::MAX_ANCHORS_PER_SPINE ||
            !anchorBudget.tryRetain(retained) ||
            !epub::limits::allocationPreflight(retained, entry.anchor.size() + 1) ||
            !epub::limits::checkedVectorPushBack(tocAnchors, std::move(entry.anchor),
                                                  epub::limits::MAX_ANCHORS_PER_SPINE)) {
          LOG_ERR("SCT", "TOC anchor list exceeds safety limit");
          file.close();
          Storage.remove(binTmpPath().c_str());
          if (!reusedHtml) Storage.remove(tmpHtmlPath.c_str());
          return false;
        }
      }
    }
  }

  // The parser stores the path/contentBase/imageBasePath by reference, so they must
  // live in the BuildContext (which outlives the parser). The page-complete callback
  // captures the BuildContext pointer to append to its in-RAM LUT; build_ owns the
  // context for the parser's whole lifetime.
  BuildContext* ctxPtr = ctx.get();
  ctx->parser = makeUniqueNoThrow<ChapterHtmlSlimParser>(
      epub, ctxPtr->parsePath, renderer, spec.fontId, spec.lineCompression, spec.extraParagraphSpacing,
      spec.paragraphAlignment, spec.viewportWidth, spec.viewportHeight, spec.hyphenationEnabled,
      spec.focusReadingEnabled,
      [this, ctxPtr](std::unique_ptr<Page> page, const uint16_t paragraphIndex, const uint16_t listItemIndex,
                      const uint32_t visibleTextOffset) -> bool {
        constexpr size_t maxLutEntries =
            epub::limits::MAX_SECTION_LUT_BYTES / sizeof(PageLutEntry);
        if (ctxPtr->lut.size() >= epub::limits::MAX_PAGES_PER_SPINE ||
            ctxPtr->lut.size() >= maxLutEntries) {
          return false;
        }
        const uint32_t pageOffset = this->onPageComplete(std::move(page));
        if (pageOffset == 0) return false;
        return epub::limits::checkedVectorPushBack(
            ctxPtr->lut, PageLutEntry{pageOffset, paragraphIndex, listItemIndex, visibleTextOffset},
            std::min(epub::limits::MAX_PAGES_PER_SPINE, maxLutEntries));
      },
      spec.embeddedStyle, ctxPtr->contentBase, ctxPtr->imageBasePath, spec.imageRendering, std::move(tocAnchors),
      std::move(anchorBudget), popupFn, ctxPtr->cssParser);
  if (!ctx->parser) {
    LOG_ERR("SCT", "OOM: ChapterHtmlSlimParser");
    if (ctx->cssParser) ctx->cssParser->clear();
    file.close();
    Storage.remove(binTmpPath().c_str());
    if (!reusedHtml) Storage.remove(tmpHtmlPath.c_str());
    return false;
  }

  Hyphenator::setPreferredLanguage(epub->getLanguage());
  build_ = std::move(ctx);

  if (!build_->parser->beginParse()) {
    LOG_ERR("SCT", "Failed to begin parse");
    abandonBuild();
    return false;
  }
  build_->totalBytes = build_->parser->parseTotalBytes();
  return true;
}

bool Section::buildSomeMoreImpl(const int maxPages) {
  if (!build_ || !build_->parser) {
    LOG_ERR("SCT", "buildSomeMore with no active build");
    return false;
  }
  // Pace on pages laid out by THIS build, not pageCount: during a rebuild over a partial,
  // pageCount stays pinned at the partial's watermark until the build passes it, which
  // would otherwise turn one "small" chunk into a blocking rebuild of the whole watermark.
  const int startCount = builtPageCount_;
  for (;;) {
    const auto status = build_->parser->parseStep();
    if (status == ChapterHtmlSlimParser::ParseStatus::Error) {
      LOG_ERR("SCT", "Parse error during incremental build");
      abandonBuild();
      return false;
    }
    if (status == ChapterHtmlSlimParser::ParseStatus::Done) {
      return finalizeBuild();
    }
    // ParseStatus::More: yield once we've laid out the requested number of pages.
    if (maxPages > 0 && (builtPageCount_ - startCount) >= maxPages) {
      build_->bytesConsumed = build_->parser->parseBytesConsumed();
      return true;
    }
  }
}

bool Section::hasHtmlCache() const {
  const std::string htmlPath = epub->getCachePath() + "/html/" + std::to_string(spineIndex) + ".html";
  return Storage.exists(htmlPath.c_str());
}

std::optional<uint16_t> Section::findAnchorDuringBuild(const std::string& anchor) const {
  if (!build_ || !build_->parser) return std::nullopt;
  for (const auto& [key, page] : build_->parser->getAnchors()) {
    if (key == anchor) return page;
  }
  return std::nullopt;
}

std::optional<uint16_t> Section::findAnchor(const std::string& anchor) const {
  if (const auto page = findAnchorDuringBuild(anchor)) {
    return page;
  }
  // Fall back to the on-disk anchor map: a finalized section, or a partial whose map
  // covers everything up to its watermark (nullopt past it -- build further and retry).
  return getPageForAnchor(anchor);
}

uint16_t Section::estimatedTotalPages() const {
  // Extrapolation from a suspended session's watermark trailer. A static snapshot, so no EMA
  // damping is needed. Also the best guess while a rebuild is running but hasn't laid out
  // enough pages yet to extrapolate from its own progress.
  const auto partialEstimate = [this]() -> uint16_t {
    if (!partial_ || partialBytesConsumed_ == 0 || partialTotalBytes_ <= partialBytesConsumed_) {
      return pageCount;
    }
    const uint64_t est = static_cast<uint64_t>(partialPageCount_) * partialTotalBytes_ / partialBytesConsumed_;
    if (est <= pageCount) return pageCount;
    return est > 60000 ? 60000 : static_cast<uint16_t>(est);
  };

  if (!build_) {
    return partial_ ? partialEstimate() : pageCount;  // partial -> extrapolate, finalized -> exact
  }
  const uint32_t consumed = build_->bytesConsumed;
  const uint32_t total = build_->totalBytes;
  if (builtPageCount_ == 0 || consumed == 0 || total <= consumed) return partialEstimate();

  // Raw extrapolation: scale the pages built so far by the fraction of HTML still unparsed. This
  // re-derives from a growing, non-uniform sample, so it jitters up and down as the build crosses
  // dense vs sparse regions of the chapter.
  const uint64_t raw = static_cast<uint64_t>(builtPageCount_) * total / consumed;

  // Damp that jitter with an exponential moving average. Step it once per build advance (keyed on
  // bytesConsumed) rather than per status-bar redraw, so the smoothing rate doesn't depend on how
  // often we repaint. As the build nears the end, consumed -> total and raw -> the built count, so
  // the average settles onto the true count (and finalizeBuild then returns the exact pageCount).
  constexpr float ALPHA = 0.25f;  // weight of each new sample; lower = steadier but slower to settle
  if (build_->smoothedEstimate <= 0) {
    build_->smoothedEstimate = static_cast<float>(raw);  // seed on the first estimate
  } else if (consumed != build_->smoothedAtConsumed) {
    build_->smoothedEstimate += ALPHA * (static_cast<float>(raw) - build_->smoothedEstimate);
  }
  build_->smoothedAtConsumed = consumed;

  const uint64_t est = static_cast<uint64_t>(build_->smoothedEstimate + 0.5f);
  if (est <= pageCount) return pageCount;  // never fewer than the pages already available
  return est > 60000 ? 60000 : static_cast<uint16_t>(est);
}

// Write the LUTs and anchor map into the open tmp .bin, patch the header with the built
// page count and table offsets, stamp `version` as the commit point, then swap the tmp
// file over filePath. For SECTION_FILE_PARTIAL_VERSION a watermark trailer
// (bytesConsumed, totalBytes) is appended after the li LUT so a later open can estimate
// the total page count. The parser must still be alive (anchors are read from it).
// On failure the tmp is removed and any pre-existing file at filePath is left intact.
bool Section::commitBuildFile(const uint8_t version, const uint32_t bytesConsumed, const uint32_t totalBytes) {
  const bool asPartial = (version == SECTION_FILE_PARTIAL_VERSION);

  const auto failCommit = [this]() {
    // Explicit close() required before remove (member variable, O_RDWR handle).
    file.close();
    Storage.remove(binTmpPath().c_str());
    return false;
  };

  if (!build_ || !build_->parser || build_->lut.size() != builtPageCount_ ||
      build_->lut.size() > epub::limits::MAX_PAGES_PER_SPINE ||
      build_->lut.size() * sizeof(PageLutEntry) > epub::limits::MAX_SECTION_LUT_BYTES) {
    LOG_ERR("SCT", "Refusing inconsistent section build state");
    return failCommit();
  }

  const uint32_t lutOffset = file.position();
  for (const auto& entry : build_->lut) {
    if (entry.fileOffset == 0) {
      LOG_ERR("SCT", "Failed to write LUT due to invalid page positions");
      return failCommit();
    }
    if (!serialization::writePod(file, entry.fileOffset)) return failCommit();
  }

  // Write anchor-to-page map for fragment navigation (e.g. footnote targets). For a
  // partial, skip anchors that landed on the incomplete trailing page the suspend drops.
  const uint32_t anchorMapOffset = file.position();
  const auto& anchors = build_->parser->getAnchors();
  uint16_t anchorCount = 0;
  epub::limits::AnchorBudget persistedAnchorBudget(epub::limits::MAX_RETAINED_ANCHOR_BYTES);
  for (const auto& [anchor, page] : anchors) {
    if (asPartial && page >= builtPageCount_) continue;
    if (anchorCount >= epub::limits::MAX_ANCHORS_PER_SPINE ||
        anchor.size() > epub::limits::MAX_ANCHOR_BYTES || page >= builtPageCount_ ||
        !persistedAnchorBudget.tryRetain(epub::limits::anchorRetainedBytes(anchor.size()))) {
      LOG_ERR("SCT", "Refusing oversized anchor map");
      return failCommit();
    }
    anchorCount++;
  }
  if (!serialization::writePod(file, anchorCount)) return failCommit();
  for (const auto& [anchor, page] : anchors) {
    if (asPartial && page >= builtPageCount_) continue;
    if (!serialization::writeString(file, anchor) || !serialization::writePod(file, page)) return failCommit();
  }

  const uint32_t paragraphLutOffset = file.position();
  if (!serialization::writePod(file, static_cast<uint16_t>(build_->lut.size()))) return failCommit();
  for (const auto& entry : build_->lut) {
    if (!serialization::writePod(file, entry.paragraphIndex)) return failCommit();
  }

  const uint32_t liLutFileOffset = static_cast<uint32_t>(file.position());
  for (const auto& entry : build_->lut) {
    if (!serialization::writePod(file, entry.listItemIndex)) return failCommit();
  }

  const uint32_t visibleLutFileOffset = static_cast<uint32_t>(file.position());
  for (const auto& entry : build_->lut) {
    if (!serialization::writePod(file, entry.visibleTextOffset)) return failCommit();
  }

  if (asPartial) {
    // Watermark trailer, located on load immediately after the visible-offset LUT.
    if (!serialization::writePod(file, bytesConsumed) || !serialization::writePod(file, totalBytes)) {
      return failCommit();
    }
  }

  // Patch header with the built page count and section offsets...
  if (!file.seek(HEADER_SIZE - sizeof(uint32_t) * 5 - sizeof(builtPageCount_)) ||
      !serialization::writePod(file, builtPageCount_) || !serialization::writePod(file, lutOffset) ||
      !serialization::writePod(file, anchorMapOffset) || !serialization::writePod(file, paragraphLutOffset) ||
      !serialization::writePod(file, liLutFileOffset) || !serialization::writePod(file, visibleLutFileOffset)) {
    return failCommit();
  }
  // ...then commit by overwriting the sentinel version with the real one. Writing the
  // version last makes it the commit point: a crash before here leaves version 0.
  if (!file.seek(0) || !serialization::writePod(file, version)) return failCommit();
  // Explicit close() required: member variable persists beyond function scope
  file.close();

  // Swap into place. A crash between remove and rename loses the old file but keeps a
  // fully-committed tmp; the next build just removes it and rebuilds.
  if (Storage.exists(filePath.c_str())) {
    Storage.remove(filePath.c_str());
  }
  if (!Storage.rename(binTmpPath().c_str(), filePath.c_str())) {
    LOG_ERR("SCT", "Failed to move built section into place");
    Storage.remove(binTmpPath().c_str());
    return false;
  }
  return true;
}

bool Section::finalizeBuild() {
  // Flush the trailing page (emits the last page via the completePageFn into the LUT).
  if (!build_->parser->finishParse()) {
    LOG_ERR("SCT", "Failed to finish spine parse");
    abandonBuild();
    return false;
  }

  if (!build_->reusedHtml) {
    // Parse succeeded: promote the freshly unzipped HTML to the persistent cache so future
    // rebuilds skip zip inflation. If promotion fails, drop the temp -- the build still succeeded.
    if (!Storage.rename(build_->tmpHtmlPath.c_str(), build_->htmlPath.c_str())) {
      LOG_DBG("SCT", "Failed to promote HTML cache, removing temp");
      Storage.remove(build_->tmpHtmlPath.c_str());
    }
  }

  const bool committed = commitBuildFile(SECTION_FILE_VERSION, 0, 0);
  if (build_->cssParser) build_->cssParser->clear();
  build_.reset();
  if (!committed) {
    // commitBuildFile removed filePath before the failed swap, so nothing valid remains.
    partial_ = false;
    partialPageCount_ = 0;
    pageCount = 0;
    builtPageCount_ = 0;
    return false;
  }
  buildComplete_ = true;
  partial_ = false;
  partialPageCount_ = 0;
  pageCount = builtPageCount_;
  return true;
}

void Section::suspendBuild() {
  if (!build_) return;

  // Only worth persisting if this build produced pages a pre-existing partial doesn't
  // already cover; otherwise keep the older (bigger) partial and just drop the tmp.
  const bool worthKeeping = builtPageCount_ > 0 && (!partial_ || builtPageCount_ > partialPageCount_);

  bool committed = false;
  if (worthKeeping) {
    // Capture the parse watermark and commit before tearing the parser down (the anchor
    // map is read from it). The incomplete trailing page is intentionally not flushed:
    // only fully laid-out pages are persisted, and the rebuild re-derives the rest.
    const uint32_t consumed = static_cast<uint32_t>(build_->parser->parseBytesConsumed());
    committed = commitBuildFile(SECTION_FILE_PARTIAL_VERSION, consumed, build_->totalBytes);
    if (committed) {
      partial_ = true;
      partialPageCount_ = builtPageCount_;
      partialBytesConsumed_ = consumed;
      partialTotalBytes_ = build_->totalBytes;
      LOG_INF("SCT", "Suspended build: %u pages persisted", builtPageCount_);
    }
  }

  if (build_->parser) build_->parser->abortParse();
  if (build_->cssParser) build_->cssParser->clear();
  if (!committed && file) {
    // Explicit close() required before remove (member variable, O_RDWR handle).
    file.close();
    Storage.remove(binTmpPath().c_str());
  }
  if (!build_->reusedHtml && Storage.exists(build_->tmpHtmlPath.c_str())) {
    Storage.remove(build_->tmpHtmlPath.c_str());
  }
  build_.reset();
  buildComplete_ = false;
  pageCount = partial_ ? partialPageCount_ : 0;
  builtPageCount_ = 0;
}

void Section::abandonBuild() {
  if (!build_) return;
  if (build_->parser) build_->parser->abortParse();
  if (build_->cssParser) build_->cssParser->clear();
  if (file) {
    // Explicit close() required before remove (member variable, O_RDWR handle).
    file.close();
    Storage.remove(binTmpPath().c_str());
  }
  // A parse error would recur against the same HTML, so drop any partial too -- resuming
  // from it would just re-enter the failing build every open.
  if (Storage.exists(filePath.c_str())) {
    Storage.remove(filePath.c_str());
  }
  if (!build_->reusedHtml && Storage.exists(build_->tmpHtmlPath.c_str())) {
    Storage.remove(build_->tmpHtmlPath.c_str());
  }
  build_.reset();
  buildComplete_ = false;
  partial_ = false;
  partialPageCount_ = 0;
  pageCount = 0;
  builtPageCount_ = 0;
}

void Section::abandonBuildNoThrow() noexcept {
  // Allocation-failure cleanup deliberately avoids path concatenation and SD
  // promotion/removal.  An in-progress section is stamped with version 0, so a
  // leftover .part can never be accepted as a committed cache and the next
  // normal build safely overwrites or removes it.
  if (build_) {
    if (build_->parser) build_->parser->abortParse();
    if (build_->cssParser) build_->cssParser->clear();
  }
  if (file) file.close();
  build_.reset();
  buildComplete_ = false;
  partial_ = false;
  partialPageCount_ = 0;
  partialBytesConsumed_ = 0;
  partialTotalBytes_ = 0;
  pageCount = 0;
  builtPageCount_ = 0;
}

std::unique_ptr<Page> Section::loadPageDuringBuild(const int page, LoadFailure& failure) {
  if (!build_ || page < 0 || page >= static_cast<int>(build_->lut.size()) || !file) {
    return nullptr;
  }
  const uint32_t pos = build_->lut[page].fileOffset;
  const uint32_t writePos = file.position();
  const uint32_t pageEnd = page + 1 < static_cast<int>(build_->lut.size())
                               ? build_->lut[page + 1].fileOffset
                               : writePos;
  if (pos < HEADER_SIZE || pageEnd <= pos ||
      pageEnd - pos > epub::limits::MAX_SERIALIZED_PAGE_BYTES) {
    return nullptr;
  }
  // The .bin is open O_RDWR for the build. Read the already-written page, then restore
  // the write cursor so the next onPageComplete keeps appending where it left off.
  // The guard also restores during exception unwinding, before loadPage's outer
  // allocation catch keeps the active transaction alive.
  activeBuildCursorSafe_ = false;
  if (!file.seek(pos)) return nullptr;
  epub::detail::FileCursorRestoreGuard<HalFile> restore(file, writePos, activeBuildCursorSafe_);
  epub::limits::PageDecodeFailure decodeFailure = epub::limits::PageDecodeFailure::InvalidData;
  auto p = Page::deserialize(file, pageEnd - pos, &decodeFailure);
  if (!restore.restore()) return nullptr;
  if (!p) failure = toSectionLoadFailure(decodeFailure);
  if (p) {
    p->visibleTextOffset = build_->lut[page].visibleTextOffset;
  }
  return p;
}

// Read a page from the committed file at filePath (finalized section or partial from a
// previous session). Uses a local handle so it is safe while a build holds the member
// `file` open on the tmp .bin.
std::unique_ptr<Page> Section::loadPageAt(const int page, LoadFailure& failure) const {
  HalFile f;
  if (page < 0 || page >= pageCount || !Storage.openFileForRead("SCT", filePath, f)) {
    return nullptr;
  }

  const uint64_t fileSize = f.fileSize64();
  uint32_t lutOffset = 0;
  if (fileSize < HEADER_SIZE || !f.seek(HEADER_SIZE - sizeof(uint32_t) * 5) ||
      !serialization::readPod(f, lutOffset)) {
    f.close();
    return nullptr;
  }
  const uint64_t pageLutEntry = static_cast<uint64_t>(lutOffset) + sizeof(uint32_t) * static_cast<uint64_t>(page);
  uint32_t pagePos = 0;
  if (lutOffset < HEADER_SIZE || pageLutEntry + sizeof(uint32_t) > fileSize || !f.seek(pageLutEntry) ||
      !serialization::readPod(f, pagePos) || pagePos < HEADER_SIZE || pagePos >= fileSize) {
    f.close();
    return nullptr;
  }
  uint32_t pageEnd = lutOffset;
  if (page + 1 < pageCount) {
    if (!serialization::readPod(f, pageEnd)) {
      f.close();
      return nullptr;
    }
  }
  if (pageEnd <= pagePos || pageEnd > lutOffset ||
      pageEnd - pagePos > epub::limits::MAX_SERIALIZED_PAGE_BYTES) {
    f.close();
    return nullptr;
  }

  // Read this page's visible-codepoint start offset from the visible-offset LUT (last header slot)
  // in the same open handle, so the reader can persist progress without reopening the section file
  // on every page turn (see Page::visibleTextOffset). A malformed/old file leaves it at 0.
  f.seek(HEADER_SIZE - sizeof(uint32_t));
  uint32_t visibleLutOffset = 0;
  if (!serialization::readPod(f, visibleLutOffset)) {
    f.close();
    return nullptr;
  }
  uint32_t visibleTextOffset = 0;
  const uint64_t visibleEntry = static_cast<uint64_t>(visibleLutOffset) + sizeof(uint32_t) * page;
  if (visibleLutOffset >= HEADER_SIZE && visibleEntry + sizeof(uint32_t) <= fileSize) {
    if (!f.seek(visibleEntry)) {
      f.close();
      return nullptr;
    }
    if (!serialization::readPod(f, visibleTextOffset)) {
      f.close();
      return nullptr;
    }
  }

  if (!f.seek(pagePos)) {
    f.close();
    return nullptr;
  }
  epub::limits::PageDecodeFailure decodeFailure = epub::limits::PageDecodeFailure::InvalidData;
  auto p = Page::deserialize(f, pageEnd - pagePos, &decodeFailure);
  if (!p) {
    f.close();
    failure = toSectionLoadFailure(decodeFailure);
    return nullptr;
  }
  if (p) {
    p->visibleTextOffset = visibleTextOffset;
  }
  return p;
  // No f.close() needed -- DESTRUCTOR_CLOSES_FILE=1 handles it at scope exit
}

std::unique_ptr<Page> Section::loadPageImpl(const int page, LoadFailure& failure) {
  if (page < 0) {
    return nullptr;
  }
  if (build_ && page < static_cast<int>(build_->lut.size())) {
    return loadPageDuringBuild(page, failure);
  }
  // Not (yet) in the active build: serve from the file on disk -- a finalized section,
  // or a partial from a previous session whose pages the rebuild hasn't reached again.
  const int onDisk = partial_ ? partialPageCount_ : (build_ ? 0 : pageCount);
  if (page >= onDisk) {
    return nullptr;
  }
  return loadPageAt(page, failure);
}

std::string Section::getTextFromSectionFile() {
  std::string fullText;
  auto p = loadPage(currentPage);
  if (p) {
    for (const auto& el : p->elements) {
      if (el->getTag() == TAG_PageLine) {
        const auto& line = static_cast<const PageLine&>(*el);
        if (line.getBlock()) {
          const auto& block = *line.getBlock();
          for (uint16_t i = 0; i < block.wordCount(); i++) {
            if (!fullText.empty()) fullText += " ";
            fullText += block.wordText(i);
          }
        }
      }
    }
  }
  return fullText;
}

std::optional<uint16_t> Section::getCachedPageCount() const {
  HalFile f;
  if (!Storage.openFileForRead("SCT", filePath, f)) {
    return std::nullopt;
  }

  const uint32_t fileSize = f.size();
  if (fileSize < HEADER_SIZE) {
    return std::nullopt;
  }

  // Only a finalized section's count is the chapter total; a partial's count is just the
  // suspended build's watermark, which would skew progress mapping. Callers fall back to
  // their own estimates.
  uint8_t version = 0;
  if (!serialization::readPod(f, version)) return std::nullopt;
  if (version != SECTION_FILE_VERSION) {
    return std::nullopt;
  }

  f.seek(HEADER_SIZE - sizeof(uint32_t) * 5 - sizeof(uint16_t));
  uint16_t count = 0;
  if (!serialization::readPod(f, count) || count > epub::limits::MAX_PAGES_PER_SPINE) {
    f.close();
    clearCache();
    return std::nullopt;
  }
  return count;
}

std::optional<uint16_t> Section::getPageForAnchor(const std::string& anchor) const {
  HalFile f;
  if (!Storage.openFileForRead("SCT", filePath, f)) {
    return std::nullopt;
  }

  const uint64_t fileSize = f.fileSize64();
  if (fileSize < HEADER_SIZE || !f.seek(HEADER_SIZE - sizeof(uint32_t) * 4)) return std::nullopt;
  uint32_t anchorMapOffset = 0;
  uint32_t paragraphLutOffset = 0;
  if (!serialization::readPod(f, anchorMapOffset) || !serialization::readPod(f, paragraphLutOffset) ||
      anchorMapOffset < HEADER_SIZE || paragraphLutOffset <= anchorMapOffset || paragraphLutOffset > fileSize) {
    return std::nullopt;
  }

  if (!f.seek(anchorMapOffset)) return std::nullopt;
  uint16_t count = 0;
  if (!serialization::readPod(f, count) || count > epub::limits::MAX_ANCHORS_PER_SPINE) {
    f.close();
    clearCache();
    return std::nullopt;
  }
  epub::limits::AnchorBudget budget(epub::limits::MAX_RETAINED_ANCHOR_BYTES);
  std::optional<uint16_t> result;
  for (uint16_t i = 0; i < count; i++) {
    std::string key;
    uint16_t page = 0;
    if (!serialization::readString(f, key, epub::limits::MAX_ANCHOR_BYTES) ||
        !budget.tryRetain(epub::limits::anchorRetainedBytes(key.size())) ||
        !serialization::readPod(f, page) || page >= pageCount || f.position() > paragraphLutOffset) {
      f.close();
      clearCache();
      return std::nullopt;
    }
    if (!result && key == anchor) result = page;
  }
  if (f.position() != paragraphLutOffset) {
    f.close();
    clearCache();
    return std::nullopt;
  }
  return result;
}

std::optional<uint16_t> Section::getPageForParagraphIndex(const uint16_t pIndex) const {
  HalFile f;
  if (!Storage.openFileForRead("SCT", filePath, f)) {
    return std::nullopt;
  }

  const uint32_t fileSize = f.size();
  f.seek(HEADER_SIZE - sizeof(uint32_t) * 3);
  uint32_t paragraphLutOffset;
  serialization::readPod(f, paragraphLutOffset);
  if (paragraphLutOffset == 0 || paragraphLutOffset >= fileSize) {
    return std::nullopt;
  }

  f.seek(paragraphLutOffset);
  uint16_t count;
  serialization::readPod(f, count);
  if (count == 0) {
    return std::nullopt;
  }

  const uint32_t lutEnd = paragraphLutOffset + sizeof(uint16_t) + count * sizeof(uint16_t);
  if (lutEnd > fileSize) {
    return std::nullopt;
  }

  uint16_t resultPage = count - 1;
  for (uint16_t i = 0; i < count; i++) {
    uint16_t pagePIdx;
    serialization::readPod(f, pagePIdx);
    if (pagePIdx >= pIndex) {
      resultPage = i;
      break;
    }
  }

  return resultPage;
}

std::optional<uint16_t> Section::getParagraphIndexForPage(const uint16_t page) const {
  HalFile f;
  if (!Storage.openFileForRead("SCT", filePath, f)) {
    return std::nullopt;
  }

  const uint32_t fileSize = f.size();
  f.seek(HEADER_SIZE - sizeof(uint32_t) * 3);
  uint32_t paragraphLutOffset;
  serialization::readPod(f, paragraphLutOffset);
  if (paragraphLutOffset == 0 || paragraphLutOffset >= fileSize) {
    return std::nullopt;
  }

  f.seek(paragraphLutOffset);
  uint16_t count;
  serialization::readPod(f, count);
  if (count == 0 || page >= count) {
    return std::nullopt;
  }

  const uint32_t entryEnd = paragraphLutOffset + sizeof(uint16_t) + (page + 1) * sizeof(uint16_t);
  if (entryEnd > fileSize) {
    return std::nullopt;
  }

  f.seek(paragraphLutOffset + sizeof(uint16_t) + page * sizeof(uint16_t));
  uint16_t pIdx;
  serialization::readPod(f, pIdx);
  return pIdx;
}

std::optional<uint16_t> Section::getPageForListItemIndex(const uint16_t liIndex) const {
  HalFile f;
  if (!Storage.openFileForRead("SCT", filePath, f)) {
    return std::nullopt;
  }

  const uint32_t fileSize = f.size();
  f.seek(HEADER_SIZE - sizeof(uint32_t) * 2);
  uint32_t liLutOffset;
  serialization::readPod(f, liLutOffset);
  if (liLutOffset == 0 || liLutOffset >= fileSize) {
    return std::nullopt;
  }

  // The li LUT shares count with the paragraph LUT; read count from paragraphLutOffset
  f.seek(HEADER_SIZE - sizeof(uint32_t) * 3);
  uint32_t paragraphLutOffset;
  serialization::readPod(f, paragraphLutOffset);
  if (paragraphLutOffset == 0 || paragraphLutOffset >= fileSize) {
    return std::nullopt;
  }

  f.seek(paragraphLutOffset);
  uint16_t count;
  serialization::readPod(f, count);
  if (count == 0) {
    return std::nullopt;
  }

  const uint32_t lutEnd = liLutOffset + count * sizeof(uint16_t);
  if (lutEnd > fileSize) {
    return std::nullopt;
  }

  f.seek(liLutOffset);
  uint16_t resultPage = count - 1;
  for (uint16_t i = 0; i < count; i++) {
    uint16_t pageLiIdx;
    serialization::readPod(f, pageLiIdx);
    if (pageLiIdx >= liIndex) {
      resultPage = i;
      break;
    }
  }

  return resultPage;
}

std::optional<uint32_t> Section::getVisibleTextOffsetForPage(const uint16_t page) const {
  if (build_ && page < build_->lut.size()) {
    return build_->lut[page].visibleTextOffset;
  }

  HalFile f;
  if (!Storage.openFileForRead("SCT", filePath, f) || f.size() < HEADER_SIZE) {
    return std::nullopt;
  }

  uint8_t version;
  serialization::readPod(f, version);
  if (version != SECTION_FILE_VERSION && version != SECTION_FILE_PARTIAL_VERSION) {
    return std::nullopt;
  }

  f.seek(HEADER_SIZE - sizeof(uint32_t) * 5 - sizeof(uint16_t));
  uint16_t count;
  serialization::readPod(f, count);
  if (page >= count) {
    return std::nullopt;
  }

  f.seek(HEADER_SIZE - sizeof(uint32_t));
  uint32_t visibleLutOffset;
  serialization::readPod(f, visibleLutOffset);
  const uint32_t entryOffset = visibleLutOffset + static_cast<uint32_t>(page) * sizeof(uint32_t);
  if (visibleLutOffset < HEADER_SIZE || entryOffset + sizeof(uint32_t) > f.size()) {
    return std::nullopt;
  }

  f.seek(entryOffset);
  uint32_t result;
  serialization::readPod(f, result);
  return result;
}

std::optional<uint16_t> Section::getPageForVisibleTextOffset(const uint32_t offset,
                                                             const bool preferFirstAtOffset) const {
  const auto findInEntries = [offset, preferFirstAtOffset](const auto& entries) -> std::optional<uint16_t> {
    if (entries.empty()) return std::nullopt;
    uint16_t result = 0;
    for (size_t i = 0; i < entries.size(); i++) {
      const uint32_t pageStart = entries[i].visibleTextOffset;
      if (preferFirstAtOffset && pageStart == offset) {
        return static_cast<uint16_t>(i);
      }
      if (pageStart > offset) break;
      result = static_cast<uint16_t>(i);
    }
    return result;
  };

  if (build_ && !build_->lut.empty()) {
    // Resolve within the active build's known range. Later offsets may still be
    // covered by an on-disk partial that the resumed build has not reached yet.
    if (offset <= build_->lut.back().visibleTextOffset) {
      return findInEntries(build_->lut);
    }
  }

  HalFile f;
  if (!Storage.openFileForRead("SCT", filePath, f) || f.size() < HEADER_SIZE) {
    return std::nullopt;
  }

  uint8_t version;
  serialization::readPod(f, version);
  if (version != SECTION_FILE_VERSION && version != SECTION_FILE_PARTIAL_VERSION) {
    return std::nullopt;
  }
  const bool partial = version == SECTION_FILE_PARTIAL_VERSION;

  f.seek(HEADER_SIZE - sizeof(uint32_t) * 5 - sizeof(uint16_t));
  uint16_t count;
  serialization::readPod(f, count);
  if (count == 0) {
    return std::nullopt;
  }

  f.seek(HEADER_SIZE - sizeof(uint32_t));
  uint32_t visibleLutOffset;
  serialization::readPod(f, visibleLutOffset);
  if (visibleLutOffset < HEADER_SIZE || visibleLutOffset + static_cast<uint32_t>(count) * sizeof(uint32_t) > f.size()) {
    return std::nullopt;
  }

  f.seek(visibleLutOffset);
  uint16_t result = 0;
  uint32_t lastPageStart = 0;
  for (uint16_t page = 0; page < count; page++) {
    uint32_t pageStart;
    serialization::readPod(f, pageStart);
    lastPageStart = pageStart;
    if (preferFirstAtOffset && pageStart == offset) {
      return page;
    }
    if (pageStart > offset) break;
    result = page;
  }
  if (partial && offset > lastPageStart) {
    return std::nullopt;
  }
  return result;
}
