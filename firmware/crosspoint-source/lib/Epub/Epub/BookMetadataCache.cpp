#include "BookMetadataCache.h"

#include <BufferedFile.h>
#include <Logging.h>
#include <Serialization.h>
#include <Utf8.h>
#include <ZipFile.h>

#include <deque>

#include "FsHelpers.h"

namespace {
constexpr uint8_t BOOK_CACHE_VERSION = 11;  // v11: bounded, exact cache deserialization
constexpr char bookBinFile[] = "/book.bin";
constexpr char tmpSpineBinFile[] = "/spine.bin.tmp";
constexpr char tmpTocBinFile[] = "/toc.bin.tmp";
// Buffer size for the buildBookBin streams. 3 buffers x 4KB, transient (freed on
// return); 4KB = 8 SD sectors per transfer, enough to stop the sector-cache thrash.
constexpr size_t BUILD_IO_BUFFER_SIZE = 4096;

// Entry (de)serializers, templated so they run over HalFile and the Buffered*
// wrappers alike (two instantiations each -- a few hundred bytes of flash, in
// exchange for the build path streaming at SD speed instead of per-pod).
template <typename F>
uint32_t writeSpineEntryTo(F& file, const BookMetadataCache::SpineEntry& entry) {
  const uint32_t pos = file.position();
  return serialization::writeString(file, entry.href) &&
                 serialization::writePod(file, entry.cumulativeSize) &&
                 serialization::writePod(file, entry.tocIndex)
             ? pos
             : UINT32_MAX;
}

template <typename F>
uint32_t writeTocEntryTo(F& file, const BookMetadataCache::TocEntry& entry) {
  const uint32_t pos = file.position();
  return serialization::writeString(file, entry.title) && serialization::writeString(file, entry.href) &&
                 serialization::writeString(file, entry.anchor) && serialization::writePod(file, entry.level) &&
                 serialization::writePod(file, entry.spineIndex)
             ? pos
             : UINT32_MAX;
}

template <typename F>
bool readSpineEntryFrom(F& file, BookMetadataCache::SpineEntry& entry) {
  return serialization::readString(file, entry.href, epub::limits::MAX_HREF_BYTES) &&
         serialization::readPod(file, entry.cumulativeSize) && serialization::readPod(file, entry.tocIndex);
}

template <typename F>
bool readTocEntryFrom(F& file, BookMetadataCache::TocEntry& entry) {
  return serialization::readString(file, entry.title, epub::limits::MAX_TITLE_BYTES) &&
         serialization::readString(file, entry.href, epub::limits::MAX_HREF_BYTES) &&
         serialization::readString(file, entry.anchor, epub::limits::MAX_ANCHOR_BYTES) &&
         serialization::readPod(file, entry.level) && serialization::readPod(file, entry.spineIndex);
}
}  // namespace

/* ============= WRITING / BUILDING FUNCTIONS ================ */

bool BookMetadataCache::beginWrite() {
  buildMode = true;
  spineCount = 0;
  tocCount = 0;
  LOG_DBG("BMC", "Entering write mode");
  return true;
}

bool BookMetadataCache::beginContentOpfPass() {
  LOG_DBG("BMC", "Beginning content opf pass");

  // Open spine file for writing
  if (!Storage.openFileForWrite("BMC", cachePath + tmpSpineBinFile, spineFile)) {
    return false;
  }
  // Wrapper OOM is fine: createSpineEntry falls back to unbuffered writes.
  passOut = makeUniqueNoThrow<serialization::BufferedFileWriter>(spineFile, BUILD_IO_BUFFER_SIZE);
  return true;
}

bool BookMetadataCache::endContentOpfPass() {
  const bool flushed = !passOut || passOut->flush();
  passOut.reset();
  // Explicit close() required: member variable persists beyond function scope
  spineFile.close();
  if (!flushed) {
    LOG_ERR("BMC", "Failed writing spine tmp file");
  }
  return flushed;
}

bool BookMetadataCache::beginTocPass() {
  LOG_DBG("BMC", "Beginning toc pass");

  if (spineCount > epub::limits::MAX_SPINE_ITEMS) {
    LOG_ERR("BMC", "Spine count %u exceeds safety limit", spineCount);
    return false;
  }

  if (!Storage.openFileForRead("BMC", cachePath + tmpSpineBinFile, spineFile)) {
    return false;
  }
  if (!Storage.openFileForWrite("BMC", cachePath + tmpTocBinFile, tocFile)) {
    // Explicit close() required: member variable persists beyond function scope
    spineFile.close();
    return false;
  }

  if (spineCount >= LARGE_SPINE_THRESHOLD) {
    spineHrefIndex.clear();
    const size_t retained = static_cast<size_t>(spineCount) * sizeof(SpineHrefIndexEntry);
    if (retained > epub::limits::MAX_METADATA_BATCH_BYTES ||
        !epub::limits::checkedDequeResize(spineHrefIndex, spineCount,
                                          epub::limits::MAX_SPINE_ITEMS)) {
      LOG_ERR("BMC", "Spine href index allocation refused");
      spineFile.close();
      tocFile.close();
      return false;
    }
    spineFile.seek(0);
    for (int i = 0; i < spineCount; i++) {
      SpineEntry entry;
      if (!readSpineEntry(spineFile, entry)) {
        LOG_ERR("BMC", "Malformed spine tmp entry %d", i);
        spineFile.close();
        tocFile.close();
        return false;
      }
      SpineHrefIndexEntry idx;
      idx.hrefHash = fnvHash64(entry.href);
      idx.hrefLen = static_cast<uint16_t>(entry.href.size());
      idx.spineIndex = static_cast<int16_t>(i);
      spineHrefIndex[i] = idx;
    }
    std::sort(spineHrefIndex.begin(), spineHrefIndex.end(),
              [](const SpineHrefIndexEntry& a, const SpineHrefIndexEntry& b) {
                return a.hrefHash < b.hrefHash || (a.hrefHash == b.hrefHash && a.hrefLen < b.hrefLen);
              });
    spineFile.seek(0);
    useSpineHrefIndex = true;
    LOG_DBG("BMC", "Using fast index for %d spine items", spineCount);
  } else {
    useSpineHrefIndex = false;
  }

  // Wrapper OOM is fine: createTocEntry falls back to unbuffered writes.
  passOut = makeUniqueNoThrow<serialization::BufferedFileWriter>(tocFile, BUILD_IO_BUFFER_SIZE);
  return true;
}

bool BookMetadataCache::endTocPass() {
  const bool flushed = !passOut || passOut->flush();
  passOut.reset();
  if (!flushed) {
    LOG_ERR("BMC", "Failed writing toc tmp file");
  }
  // Explicit close() required: member variables persist beyond function scope
  tocFile.close();
  spineFile.close();

  spineHrefIndex.clear();
  spineHrefIndex.shrink_to_fit();
  useSpineHrefIndex = false;

  return flushed;
}

bool BookMetadataCache::endWrite() {
  if (!buildMode) {
    LOG_DBG("BMC", "endWrite called but not in build mode");
    return false;
  }

  buildMode = false;
  LOG_DBG("BMC", "Wrote %d spine, %d TOC entries", spineCount, tocCount);
  return true;
}

bool BookMetadataCache::buildBookBin(const std::string& epubPath, const BookMetadata& metadata) {
  if (spineCount > epub::limits::MAX_SPINE_ITEMS || tocCount > epub::limits::MAX_TOC_ITEMS ||
      metadata.title.size() > epub::limits::MAX_TITLE_BYTES ||
      metadata.author.size() > epub::limits::MAX_AUTHOR_BYTES ||
      metadata.language.size() > epub::limits::MAX_LANGUAGE_BYTES ||
      metadata.coverItemHref.size() > epub::limits::MAX_HREF_BYTES ||
      metadata.textReferenceHref.size() > epub::limits::MAX_HREF_BYTES) {
    LOG_ERR("BMC", "Refusing oversized book metadata cache");
    return false;
  }

  // Open all three files, writing to meta, reading from spine and toc
  if (!Storage.openFileForWrite("BMC", cachePath + bookBinFile, bookFile)) {
    return false;
  }

  if (!Storage.openFileForRead("BMC", cachePath + tmpSpineBinFile, spineFile)) {
    // Explicit close() required: member variable persists beyond function scope
    bookFile.close();
    return false;
  }

  if (!Storage.openFileForRead("BMC", cachePath + tmpTocBinFile, tocFile)) {
    // Explicit close() required: member variables persist beyond function scope
    bookFile.close();
    spineFile.close();
    return false;
  }

  // Buffered streams for the whole build: every access below is sequential per
  // file, but interleaved ACROSS files, which thrashes SdFat's single shared
  // sector cache when unbuffered (one 512B SD transaction per 4-byte pod --
  // measured 31s for a 1,732-spine omnibus). Three 4KB buffers, freed on return.
  serialization::BufferedFileWriter bookOut(bookFile, BUILD_IO_BUFFER_SIZE);
  serialization::BufferedFileReader spineIn(spineFile, BUILD_IO_BUFFER_SIZE);
  serialization::BufferedFileReader tocIn(tocFile, BUILD_IO_BUFFER_SIZE);

  const auto failBuild = [&](const char* reason) {
    LOG_ERR("BMC", "%s", reason);
    // Drain the wrapper while the underlying handle is still valid. Its
    // destructor also flushes, so closing first would make the destructor write
    // buffered bytes through a closed HalFile on every early-return path.
    bookOut.flush();
    bookFile.close();
    spineFile.close();
    tocFile.close();
    Storage.remove((cachePath + bookBinFile).c_str());
    return false;
  };

  constexpr uint32_t headerASize =
      sizeof(BOOK_CACHE_VERSION) + /* LUT Offset */ sizeof(uint32_t) + sizeof(spineCount) + sizeof(tocCount);
  const uint64_t metadataSize64 = metadata.title.size() + metadata.author.size() + metadata.language.size() +
                                  metadata.coverItemHref.size() + metadata.textReferenceHref.size() +
                                  sizeof(uint32_t) * 5ULL;
  const uint64_t lutSize64 = sizeof(uint32_t) * (static_cast<uint64_t>(spineCount) + tocCount);
  if (metadataSize64 > UINT32_MAX || lutSize64 > UINT32_MAX || headerASize + metadataSize64 > UINT32_MAX) {
    return failBuild("Book metadata offsets overflow");
  }
  const auto metadataSize = static_cast<uint32_t>(metadataSize64);
  const auto lutSize = static_cast<uint32_t>(lutSize64);
  const uint32_t lutOffset = headerASize + metadataSize;

  // Header A
  if (!serialization::writePod(bookOut, BOOK_CACHE_VERSION) || !serialization::writePod(bookOut, lutOffset) ||
      !serialization::writePod(bookOut, spineCount) || !serialization::writePod(bookOut, tocCount)) {
    return failBuild("Failed writing book cache header");
  }
  // Metadata
  if (!serialization::writeString(bookOut, metadata.title) ||
      !serialization::writeString(bookOut, metadata.author) ||
      !serialization::writeString(bookOut, metadata.language) ||
      !serialization::writeString(bookOut, metadata.coverItemHref) ||
      !serialization::writeString(bookOut, metadata.textReferenceHref)) {
    return failBuild("Failed writing book cache metadata");
  }

  // Loop through spine entries, writing LUT positions
  spineIn.seek(0);
  for (int i = 0; i < spineCount; i++) {
    const uint32_t pos = spineIn.position();
    SpineEntry entry;
    if (!readSpineEntryFrom(spineIn, entry)) return failBuild("Malformed spine tmp data");
    const uint64_t outputPos = static_cast<uint64_t>(pos) + lutOffset + lutSize;
    if (outputPos > UINT32_MAX || !serialization::writePod(bookOut, static_cast<uint32_t>(outputPos))) {
      return failBuild("Failed writing spine LUT");
    }
  }
  // Total size of the spine tmp file: entries land in book.bin after the toc LUT
  // and the full spine block, so toc LUT positions are offset by it.
  const auto spineBytes = static_cast<uint32_t>(spineIn.position());

  // Loop through toc entries, writing LUT positions
  tocIn.seek(0);
  for (int i = 0; i < tocCount; i++) {
    const uint32_t pos = tocIn.position();
    TocEntry entry;
    if (!readTocEntryFrom(tocIn, entry)) return failBuild("Malformed TOC tmp data");
    const uint64_t outputPos = static_cast<uint64_t>(pos) + lutOffset + lutSize + spineBytes;
    if (outputPos > UINT32_MAX || !serialization::writePod(bookOut, static_cast<uint32_t>(outputPos))) {
      return failBuild("Failed writing TOC LUT");
    }
  }

  // LUTs complete
  // Loop through spines from spine file matching up TOC indexes, calculating cumulative size and writing to book.bin

  // Build spineIndex->tocIndex mapping in one pass (O(n) instead of O(n*m))
  const size_t spineMapBytes = static_cast<size_t>(spineCount) * sizeof(int16_t);
  if (spineMapBytes > epub::limits::MAX_METADATA_BATCH_BYTES ||
      !epub::limits::allocationPreflight(spineMapBytes, std::min<size_t>(spineMapBytes, 4096))) {
    return failBuild("Spine mapping allocation refused");
  }
  std::deque<int16_t> spineToTocIndex;
  if (!epub::limits::checkedDequeResize(spineToTocIndex, spineCount,
                                        epub::limits::MAX_SPINE_ITEMS)) {
    return failBuild("Spine mapping allocation refused");
  }
  std::fill(spineToTocIndex.begin(), spineToTocIndex.end(), static_cast<int16_t>(-1));
  tocIn.seek(0);
  for (int j = 0; j < tocCount; j++) {
    TocEntry tocEntry;
    if (!readTocEntryFrom(tocIn, tocEntry)) return failBuild("Malformed TOC mapping entry");
    if (tocEntry.spineIndex >= 0 && tocEntry.spineIndex < spineCount) {
      if (spineToTocIndex[tocEntry.spineIndex] == -1) {
        spineToTocIndex[tocEntry.spineIndex] = static_cast<int16_t>(j);
      }
    }
  }

  ZipFile zip(epubPath);
  // Pre-open zip file to speed up size calculations
  if (!zip.open()) {
    LOG_ERR("BMC", "Could not open EPUB zip for size calculations");
    return failBuild("Could not open EPUB zip for size calculations");
  }
  // NOTE: We intentionally skip calling loadAllFileStatSlims() here.
  // For large EPUBs (2000+ chapters), pre-loading all ZIP central directory entries
  // into memory causes OOM crashes on ESP32-C3's limited ~380KB RAM.
  // Instead, for large books we use a one-pass batch lookup that scans the ZIP
  // central directory once and matches against spine targets using hash comparison.
  // This is O(n*log(m)) instead of O(n*m) while avoiding memory exhaustion.
  // See: https://github.com/crosspoint-reader/crosspoint-reader/issues/134

  std::deque<uint32_t> spineSizes;
  bool useBatchSizes = false;

  if (spineCount >= LARGE_SPINE_THRESHOLD) {
    LOG_DBG("BMC", "Using batch size lookup for %d spine items", spineCount);

    std::deque<ZipFile::SizeTarget> targets;
    const size_t batchBytes = spineMapBytes +
                              static_cast<size_t>(spineCount) *
                                  (sizeof(ZipFile::SizeTarget) + sizeof(uint32_t));
    if (batchBytes > epub::limits::MAX_METADATA_BATCH_BYTES ||
        !epub::limits::allocationPreflight(batchBytes, 4096) ||
        !epub::limits::checkedDequeResize(targets, spineCount,
                                           epub::limits::MAX_SPINE_ITEMS)) {
      zip.close();
      return failBuild("Spine size batch allocation refused");
    }

    spineIn.seek(0);
    for (int i = 0; i < spineCount; i++) {
      SpineEntry entry;
      if (!readSpineEntryFrom(spineIn, entry)) {
        zip.close();
        return failBuild("Malformed spine size entry");
      }
      std::string path = FsHelpers::normalisePath(entry.href);

      ZipFile::SizeTarget t;
      t.hash = ZipFile::fnvHash64(path.c_str(), path.size());
      t.len = static_cast<uint16_t>(path.size());
      t.index = static_cast<uint16_t>(i);
      targets[i] = t;
    }

    std::sort(targets.begin(), targets.end(), [](const ZipFile::SizeTarget& a, const ZipFile::SizeTarget& b) {
      return a.hash < b.hash || (a.hash == b.hash && a.len < b.len);
    });

    if (!epub::limits::checkedDequeResize(spineSizes, spineCount,
                                          epub::limits::MAX_SPINE_ITEMS)) {
      zip.close();
      return failBuild("Spine size result allocation refused");
    }
    std::fill(spineSizes.begin(), spineSizes.end(), 0U);
    int matched = zip.fillUncompressedSizes(targets, spineSizes);
    LOG_DBG("BMC", "Batch lookup matched %d/%d spine items", matched, spineCount);

    targets.clear();
    targets.shrink_to_fit();

    useBatchSizes = true;
  }

  uint32_t cumSize = 0;
  spineIn.seek(0);
  int lastSpineTocIndex = -1;
  for (int i = 0; i < spineCount; i++) {
    SpineEntry spineEntry;
    if (!readSpineEntryFrom(spineIn, spineEntry)) {
      zip.close();
      return failBuild("Malformed spine entry during final write");
    }

    spineEntry.tocIndex = spineToTocIndex[i];

    // Not a huge deal if we don't fine a TOC entry for the spine entry, this is expected behaviour for EPUBs
    // Logging here is for debugging
    if (spineEntry.tocIndex == -1) {
      LOG_DBG("BMC", "Warning: Could not find TOC entry for spine item %d: %s, using title from last section", i,
              spineEntry.href.c_str());
      spineEntry.tocIndex = lastSpineTocIndex;
    }
    lastSpineTocIndex = spineEntry.tocIndex;

    size_t itemSize = 0;
    if (useBatchSizes) {
      itemSize = spineSizes[i];
      if (itemSize == 0) {
        const std::string path = FsHelpers::normalisePath(spineEntry.href);
        if (!zip.getInflatedFileSize(path.c_str(), &itemSize)) {
          LOG_ERR("BMC", "Warning: Could not get size for spine item: %s", path.c_str());
        }
      }
    } else {
      const std::string path = FsHelpers::normalisePath(spineEntry.href);
      if (!zip.getInflatedFileSize(path.c_str(), &itemSize)) {
        LOG_ERR("BMC", "Warning: Could not get size for spine item: %s", path.c_str());
      }
    }

    if (!epub::limits::inflatedSpineFits(itemSize) || itemSize > UINT32_MAX - cumSize) {
      zip.close();
      return failBuild("Spine inflated size exceeds safety limit");
    }
    cumSize += static_cast<uint32_t>(itemSize);
    spineEntry.cumulativeSize = cumSize;

    // Write out spine data to book.bin
    if (writeSpineEntryTo(bookOut, spineEntry) == UINT32_MAX) {
      zip.close();
      return failBuild("Failed writing final spine entry");
    }
  }
  // Close opened zip file
  zip.close();

  // Loop through toc entries from toc file writing to book.bin
  tocIn.seek(0);
  for (int i = 0; i < tocCount; i++) {
    TocEntry tocEntry;
    if (!readTocEntryFrom(tocIn, tocEntry)) return failBuild("Malformed TOC entry during final write");
    if (writeTocEntryTo(bookOut, tocEntry) == UINT32_MAX) {
      return failBuild("Failed writing final TOC entry");
    }
  }

  const bool written = bookOut.flush();

  // Explicit close() required: member variables persist beyond function scope
  bookFile.close();
  spineFile.close();
  tocFile.close();

  if (!written) {
    // A short write (card full/removed) would leave a truncated book.bin that
    // still passes the version check on load; remove it so the next open rebuilds.
    LOG_ERR("BMC", "Failed writing book.bin, removing truncated file");
    Storage.remove((cachePath + bookBinFile).c_str());
    return false;
  }

  LOG_DBG("BMC", "Successfully built book.bin");
  return true;
}

bool BookMetadataCache::cleanupTmpFiles() const {
  const auto spineBinFile = cachePath + tmpSpineBinFile;
  if (Storage.exists(spineBinFile.c_str())) {
    Storage.remove(spineBinFile.c_str());
  }
  const auto tocBinFile = cachePath + tmpTocBinFile;
  if (Storage.exists(tocBinFile.c_str())) {
    Storage.remove(tocBinFile.c_str());
  }
  return true;
}

uint32_t BookMetadataCache::writeSpineEntry(HalFile& file, const SpineEntry& entry) const {
  return writeSpineEntryTo(file, entry);
}

uint32_t BookMetadataCache::writeTocEntry(HalFile& file, const TocEntry& entry) const {
  return writeTocEntryTo(file, entry);
}

// Note: for the LUT to be accurate, this **MUST** be called for all spine items before `addTocEntry` is ever called
// this is because in this function we're marking positions of the items
bool BookMetadataCache::createSpineEntry(const std::string& href) {
  if (!buildMode || !spineFile) {
    LOG_DBG("BMC", "createSpineEntry called but not in build mode");
    return false;
  }
  if (spineCount >= epub::limits::MAX_SPINE_ITEMS || href.empty() || href.size() > epub::limits::MAX_HREF_BYTES) {
    LOG_ERR("BMC", "Rejected spine entry %u (href bytes=%u)", spineCount,
            static_cast<unsigned>(href.size()));
    return false;
  }

  const SpineEntry entry(href, 0, -1);
  const uint32_t position = passOut ? writeSpineEntryTo(*passOut, entry) : writeSpineEntry(spineFile, entry);
  if (position == UINT32_MAX) return false;
  spineCount++;
  return true;
}

bool BookMetadataCache::createTocEntry(const std::string& title, const std::string& href, const std::string& anchor,
                                       const uint8_t level) {
  if (!buildMode || !tocFile || !spineFile) {
    LOG_DBG("BMC", "createTocEntry called but not in build mode");
    return false;
  }
  if (tocCount >= epub::limits::MAX_TOC_ITEMS || title.size() > epub::limits::MAX_TITLE_BYTES ||
      href.size() > epub::limits::MAX_HREF_BYTES || anchor.size() > epub::limits::MAX_ANCHOR_BYTES) {
    LOG_ERR("BMC", "Rejected oversized TOC entry %u", tocCount);
    return false;
  }

  int16_t spineIndex = -1;

  if (useSpineHrefIndex) {
    uint64_t targetHash = fnvHash64(href);
    uint16_t targetLen = static_cast<uint16_t>(href.size());

    auto it =
        std::lower_bound(spineHrefIndex.begin(), spineHrefIndex.end(), SpineHrefIndexEntry{targetHash, targetLen, 0},
                         [](const SpineHrefIndexEntry& a, const SpineHrefIndexEntry& b) {
                           return a.hrefHash < b.hrefHash || (a.hrefHash == b.hrefHash && a.hrefLen < b.hrefLen);
                         });

    while (it != spineHrefIndex.end() && it->hrefHash == targetHash && it->hrefLen == targetLen) {
      spineIndex = it->spineIndex;
      break;
    }

    if (spineIndex == -1) {
      LOG_DBG("BMC", "createTocEntry: Could not find spine item for TOC href %s", href.c_str());
    }
  } else {
    spineFile.seek(0);
    for (int i = 0; i < spineCount; i++) {
      SpineEntry spineEntry;
      if (!readSpineEntry(spineFile, spineEntry)) {
        LOG_ERR("BMC", "Malformed spine entry during TOC lookup");
        return false;
      }
      if (spineEntry.href == href) {
        spineIndex = static_cast<int16_t>(i);
        break;
      }
    }
    if (spineIndex == -1) {
      LOG_DBG("BMC", "createTocEntry: Could not find spine item for TOC href %s", href.c_str());
    }
  }

  // Compose the title to NFC at index time so the cache stores precomposed glyphs;
  // device fonts have no combining-mark positioning, so NFD titles render broken.
  if (!epub::limits::allocationPreflight(title.size() + 1, title.size() + 1)) return false;
  std::string normalizedTitle = utf8ComposeNfc(title);
  if (normalizedTitle.size() > epub::limits::MAX_TITLE_BYTES) return false;
  const TocEntry entry(std::move(normalizedTitle), href, anchor, level, spineIndex);
  const uint32_t position = passOut ? writeTocEntryTo(*passOut, entry) : writeTocEntry(tocFile, entry);
  if (position == UINT32_MAX) return false;
  tocCount++;
  return true;
}

/* ============= READING / LOADING FUNCTIONS ================ */

bool BookMetadataCache::load() {
  loaded = false;
  spineCount = 0;
  tocCount = 0;
  lutOffset = 0;
  if (!Storage.openFileForRead("BMC", cachePath + bookBinFile, bookFile)) {
    return false;
  }

  uint8_t version = 0;
  if (!serialization::readPod(bookFile, version)) return invalidateCache("truncated version");
  if (version != BOOK_CACHE_VERSION) {
    LOG_DBG("BMC", "Cache version mismatch: expected %d, got %d", BOOK_CACHE_VERSION, version);
    return invalidateCache("version mismatch");
  }

  if (!serialization::readPod(bookFile, lutOffset) || !serialization::readPod(bookFile, spineCount) ||
      !serialization::readPod(bookFile, tocCount)) {
    return invalidateCache("truncated cache header");
  }
  if (spineCount == 0 || spineCount > epub::limits::MAX_SPINE_ITEMS || tocCount > epub::limits::MAX_TOC_ITEMS) {
    return invalidateCache("cache count exceeds safety limit");
  }

  if (!serialization::readString(bookFile, coreMetadata.title, epub::limits::MAX_TITLE_BYTES) ||
      !serialization::readString(bookFile, coreMetadata.author, epub::limits::MAX_AUTHOR_BYTES) ||
      !serialization::readString(bookFile, coreMetadata.language, epub::limits::MAX_LANGUAGE_BYTES) ||
      !serialization::readString(bookFile, coreMetadata.coverItemHref, epub::limits::MAX_HREF_BYTES) ||
      !serialization::readString(bookFile, coreMetadata.textReferenceHref, epub::limits::MAX_HREF_BYTES)) {
    return invalidateCache("malformed metadata string");
  }

  const size_t fileSize = bookFile.size();
  const size_t lutBytes = sizeof(uint32_t) * (static_cast<size_t>(spineCount) + tocCount);
  if (lutOffset != bookFile.position() || lutOffset > fileSize || lutBytes > fileSize - lutOffset) {
    return invalidateCache("invalid cache LUT bounds");
  }

  loaded = true;
  LOG_DBG("BMC", "Loaded cache data: %d spine, %d TOC entries", spineCount, tocCount);
  return true;
}

BookMetadataCache::SpineEntry BookMetadataCache::getSpineEntry(const int index) {
  if (!loaded) {
    LOG_ERR("BMC", "getSpineEntry called but cache not loaded");
    return {};
  }

  if (index < 0 || index >= static_cast<int>(spineCount)) {
    LOG_ERR("BMC", "getSpineEntry index %d out of range", index);
    return {};
  }

  // Seek to spine LUT item, read from LUT and get out data
  const size_t lutEntry = lutOffset + sizeof(uint32_t) * static_cast<size_t>(index);
  uint32_t spineEntryPos = 0;
  SpineEntry entry;
  const size_t dataStart = lutOffset + sizeof(uint32_t) * (static_cast<size_t>(spineCount) + tocCount);
  if (!bookFile.seek(lutEntry) || !serialization::readPod(bookFile, spineEntryPos) || spineEntryPos < dataStart ||
      spineEntryPos >= bookFile.size() || !bookFile.seek(spineEntryPos) || !readSpineEntry(bookFile, entry)) {
    invalidateCache("malformed spine cache entry");
    return {};
  }
  return entry;
}

BookMetadataCache::TocEntry BookMetadataCache::getTocEntry(const int index) {
  if (!loaded) {
    LOG_ERR("BMC", "getTocEntry called but cache not loaded");
    return {};
  }

  if (index < 0 || index >= static_cast<int>(tocCount)) {
    LOG_ERR("BMC", "getTocEntry index %d out of range", index);
    return {};
  }

  // Seek to TOC LUT item, read from LUT and get out data
  const size_t lutEntry = lutOffset + sizeof(uint32_t) * static_cast<size_t>(spineCount) +
                          sizeof(uint32_t) * static_cast<size_t>(index);
  uint32_t tocEntryPos = 0;
  TocEntry entry;
  const size_t dataStart = lutOffset + sizeof(uint32_t) * (static_cast<size_t>(spineCount) + tocCount);
  if (!bookFile.seek(lutEntry) || !serialization::readPod(bookFile, tocEntryPos) || tocEntryPos < dataStart ||
      tocEntryPos >= bookFile.size() || !bookFile.seek(tocEntryPos) || !readTocEntry(bookFile, entry) ||
      entry.spineIndex >= static_cast<int16_t>(spineCount)) {
    invalidateCache("malformed TOC cache entry");
    return {};
  }
  return entry;
}

bool BookMetadataCache::readSpineEntry(HalFile& file, SpineEntry& entry) const {
  return readSpineEntryFrom(file, entry);
}

bool BookMetadataCache::readTocEntry(HalFile& file, TocEntry& entry) const { return readTocEntryFrom(file, entry); }

bool BookMetadataCache::invalidateCache(const char* const reason) {
  LOG_ERR("BMC", "Invalidating book cache: %s", reason ? reason : "malformed data");
  loaded = false;
  bookFile.close();
  Storage.remove((cachePath + bookBinFile).c_str());
  return false;
}
