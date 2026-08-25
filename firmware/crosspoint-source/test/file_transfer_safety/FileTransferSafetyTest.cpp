#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <map>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "src/network/FileTransferSafety.h"

namespace safety = xtinct::file_transfer;

namespace {

bool equalsIgnoreCase(std::string_view left, std::string_view right) {
  return safety::asciiEqualsIgnoreCase(left, right);
}

uint8_t shortNameChecksum(const char name[11]) {
  uint8_t sum = 0;
  for (size_t index = 0; index < 11; ++index) {
    sum = static_cast<uint8_t>(((sum & 1U) ? 0x80U : 0U) + (sum >> 1U) + static_cast<uint8_t>(name[index]));
  }
  return sum;
}

// A standard 1.44 MiB FAT12 image with real VFAT LFN + SFN directory entries.
// The resolver parses the on-image root directory exactly as an alias-capable
// FAT implementation does, so policy tests exercise collision aliases rather
// than a hard-coded CROSSP~1 string.
class Fat12RootResolver {
 public:
  Fat12RootResolver() : image(1440U * 1024U, 0) {
    put16(11, 512);
    image[13] = 1;     // sectors per cluster
    put16(14, 1);      // reserved sectors
    image[16] = 2;     // FAT copies
    put16(17, 224);    // root entries
    put16(19, 2880);   // total sectors
    image[21] = 0xf0;  // media
    put16(22, 9);      // sectors per FAT
    put16(24, 18);
    put16(26, 2);
    image[510] = 0x55;
    image[511] = 0xaa;
    image[512] = 0xf0;
    image[513] = 0xff;
    image[514] = 0xff;
    image[10U * 512U] = 0xf0;
    image[10U * 512U + 1] = 0xff;
    image[10U * 512U + 2] = 0xff;

    addDirectory(".crosspoint", "CROSSP~7");
    addDirectory("System Volume Information", "SYSTEM~4");
    addDirectory("XTCache", "XTCACH~9");
    addDirectory("Books", "BOOKS");
  }

  safety::ResolveStatus resolve(const std::string_view path, char* actual, const size_t capacity,
                                size_t& actualLength) const {
    actualLength = 0;
    if (path.size() < 2 || path.front() != '/' || path.find('/', 1) != std::string_view::npos) {
      return safety::ResolveStatus::Missing;
    }
    const std::string_view requested = path.substr(1);
    constexpr size_t rootOffset = 19U * 512U;
    std::array<char16_t, 260> longChars{};
    bool haveLfn = false;
    uint8_t expectedChecksum = 0;
    for (size_t entryOffset = rootOffset; entryOffset < rootOffset + 224U * 32U; entryOffset += 32) {
      const uint8_t* entry = image.data() + entryOffset;
      if (entry[0] == 0) break;
      if (entry[11] == 0x0f) {
        haveLfn = true;
        expectedChecksum = entry[13];
        const uint8_t ordinal = static_cast<uint8_t>(entry[0] & 0x1fU);
        static constexpr uint8_t positions[13] = {1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30};
        for (size_t index = 0; index < 13; ++index) {
          const size_t target = (ordinal - 1U) * 13U + index;
          longChars[target] = static_cast<char16_t>(entry[positions[index]] | (entry[positions[index] + 1] << 8U));
        }
        continue;
      }

      char rawShort[11];
      std::memcpy(rawShort, entry, sizeof(rawShort));
      std::string shortName;
      for (size_t index = 0; index < 8 && rawShort[index] != ' '; ++index) shortName.push_back(rawShort[index]);
      std::string extension;
      for (size_t index = 8; index < 11 && rawShort[index] != ' '; ++index) extension.push_back(rawShort[index]);
      if (!extension.empty()) shortName += "." + extension;

      std::string longName;
      if (haveLfn && shortNameChecksum(rawShort) == expectedChecksum) {
        for (const char16_t value : longChars) {
          if (value == 0 || value == 0xffff) break;
          if (value > 0x7f) return safety::ResolveStatus::Error;
          longName.push_back(static_cast<char>(value));
        }
      }
      const std::string& resolved = longName.empty() ? shortName : longName;
      if (equalsIgnoreCase(requested, shortName) || equalsIgnoreCase(requested, resolved)) {
        if (resolved.size() + 1 > capacity) return safety::ResolveStatus::Error;
        std::memcpy(actual, resolved.data(), resolved.size());
        actual[resolved.size()] = '\0';
        actualLength = resolved.size();
        return safety::ResolveStatus::Found;
      }
      haveLfn = false;
      expectedChecksum = 0;
      longChars.fill(0);
    }
    return safety::ResolveStatus::Missing;
  }

 private:
  std::vector<uint8_t> image;
  size_t nextRootEntry = 0;
  uint16_t nextCluster = 2;

  void put16(const size_t offset, const uint16_t value) {
    image[offset] = static_cast<uint8_t>(value);
    image[offset + 1] = static_cast<uint8_t>(value >> 8U);
  }

  void addDirectory(const std::string& longName, const std::string& shortBase) {
    char shortName[11];
    std::memset(shortName, ' ', sizeof(shortName));
    std::memcpy(shortName, shortBase.data(), std::min<size_t>(8, shortBase.size()));
    const uint8_t checksum = shortNameChecksum(shortName);
    const size_t lfnCount = (longName.size() + 12U) / 13U;
    constexpr size_t rootOffset = 19U * 512U;
    static constexpr uint8_t positions[13] = {1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30};
    for (size_t ordinal = lfnCount; ordinal > 0; --ordinal) {
      uint8_t* entry = image.data() + rootOffset + nextRootEntry++ * 32U;
      std::memset(entry, 0xff, 32);
      entry[0] = static_cast<uint8_t>(ordinal | (ordinal == lfnCount ? 0x40U : 0U));
      entry[11] = 0x0f;
      entry[12] = 0;
      entry[13] = checksum;
      entry[26] = 0;
      entry[27] = 0;
      for (size_t index = 0; index < 13; ++index) {
        const size_t source = (ordinal - 1U) * 13U + index;
        const uint16_t value = source < longName.size() ? static_cast<uint8_t>(longName[source])
                               : source == longName.size() ? 0
                                                          : 0xffff;
        entry[positions[index]] = static_cast<uint8_t>(value);
        entry[positions[index] + 1] = static_cast<uint8_t>(value >> 8U);
      }
    }
    uint8_t* entry = image.data() + rootOffset + nextRootEntry++ * 32U;
    std::memset(entry, 0, 32);
    std::memcpy(entry, shortName, sizeof(shortName));
    entry[11] = 0x10;
    entry[26] = static_cast<uint8_t>(nextCluster);
    entry[27] = static_cast<uint8_t>(nextCluster >> 8U);
    ++nextCluster;
  }
};

struct FakeOps {
  std::map<std::string, std::string> files;
  std::set<size_t> failRenameCalls;
  std::set<size_t> failRemoveCalls;
  size_t renameCalls = 0;
  size_t removeCalls = 0;

  bool exists(const char* path) const { return files.contains(path); }
  bool rename(const char* from, const char* to) {
    ++renameCalls;
    if (failRenameCalls.contains(renameCalls) || !files.contains(from) || files.contains(to)) return false;
    files[to] = files[from];
    files.erase(from);
    return true;
  }
  bool remove(const char* path) {
    ++removeCalls;
    if (failRemoveCalls.contains(removeCalls)) return false;
    return files.erase(path) == 1;
  }
};

struct FakeReader {
  std::vector<uint8_t> bytes;
  size_t position = 0;
  size_t reads = 0;
  size_t failRead = 0;
  int read(void* output, const size_t count) {
    if (++reads == failRead) return -1;
    if (position >= bytes.size()) return 0;
    const size_t copied = std::min(count, bytes.size() - position);
    std::memcpy(output, bytes.data() + position, copied);
    position += copied;
    return static_cast<int>(copied);
  }
};

struct FakeWriter {
  std::vector<uint8_t> bytes;
  size_t writes = 0;
  size_t failWrite = 0;
  bool failSync = false;
  bool failClose = false;
  bool writeError = false;
  size_t write(const void* input, const size_t count) {
    if (++writes == failWrite) {
      writeError = true;
      return count == 0 ? 0 : count - 1;
    }
    const auto* first = static_cast<const uint8_t*>(input);
    bytes.insert(bytes.end(), first, first + count);
    return count;
  }
  bool sync() { return !failSync; }
  bool getWriteError() const { return writeError; }
  bool close() { return !failClose; }
};

}  // namespace

TEST(FileTransferPathPolicy, ResolvesRealFatCollisionAliasesToProtectedLfns) {
  Fat12RootResolver fat;
  EXPECT_EQ(safety::checkNormalizedPath("/CROSSP~7", safety::PathIntent::Existing, fat),
            safety::PathDecision::Protected);
  EXPECT_EQ(safety::checkNormalizedPath("/SYSTEM~4", safety::PathIntent::Existing, fat),
            safety::PathDecision::Protected);
  EXPECT_EQ(safety::checkNormalizedPath("/XTCACH~9", safety::PathIntent::Existing, fat),
            safety::PathDecision::Protected);
  EXPECT_EQ(safety::checkNormalizedPath("/CROSSP~7/new.bin", safety::PathIntent::CreateLeaf, fat),
            safety::PathDecision::Protected);
}

TEST(FileTransferPathPolicy, AllowsSafeExistingParentAndLexicalCreateLeaf) {
  Fat12RootResolver fat;
  EXPECT_EQ(safety::checkNormalizedPath("/BOOKS", safety::PathIntent::Existing, fat),
            safety::PathDecision::Allowed);
  EXPECT_EQ(safety::checkNormalizedPath("/BOOKS/new.epub", safety::PathIntent::CreateLeaf, fat),
            safety::PathDecision::Allowed);
  EXPECT_EQ(safety::checkNormalizedPath("/MISSING/new.epub", safety::PathIntent::CreateLeaf, fat),
            safety::PathDecision::Invalid);
}

TEST(FileTransferPathPolicy, RejectsRawEncodedSeparatorsNulAndMalformedEscapes) {
  EXPECT_FALSE(safety::isBoundedRawPath("/safe%2fhidden"));
  EXPECT_FALSE(safety::isBoundedRawPath("/safe%2Fhidden"));
  EXPECT_FALSE(safety::isBoundedRawPath("/safe%5cchild"));
  EXPECT_FALSE(safety::isBoundedRawPath("/safe%00child"));
  EXPECT_FALSE(safety::isBoundedRawPath("/safe%0Achild"));
  EXPECT_FALSE(safety::isBoundedRawPath("/safe%2"));
  const char literalNul[] = {'/', 's', 'a', 'f', 'e', '\0', 'x'};
  EXPECT_FALSE(safety::isBoundedRawPath(std::string_view(literalNul, sizeof(literalNul))));
  EXPECT_TRUE(safety::isBoundedRawPath("/safe%20name"));
}

TEST(FileTransferPathPolicy, RejectsLongAndManyComponentPaths) {
  Fat12RootResolver fat;
  const std::string longPath(safety::MAX_PATH_BYTES + 1, 'a');
  EXPECT_EQ(safety::checkNormalizedPath("/" + longPath, safety::PathIntent::CreateLeaf, fat),
            safety::PathDecision::Invalid);
  std::string many;
  for (size_t index = 0; index < safety::MAX_PATH_COMPONENTS + 1; ++index) many += "/a";
  EXPECT_EQ(safety::checkNormalizedPath(many, safety::PathIntent::CreateLeaf, fat),
            safety::PathDecision::Invalid);
}

TEST(FileTransferWebSocket, ParsesOnlyBoundedExactLengthStartFrames) {
  safety::WsStartControl parsed;
  EXPECT_TRUE(safety::parseWsStartControl("START:book.epub:4294967295:/Books", parsed));
  EXPECT_STREQ(parsed.filename, "book.epub");
  EXPECT_STREQ(parsed.path, "/Books");
  EXPECT_EQ(parsed.bytes, safety::MAX_TRANSFER_FILE_BYTES);

  EXPECT_FALSE(safety::parseWsStartControl("START:book.epub:4294967296:/Books", parsed));
  EXPECT_FALSE(safety::parseWsStartControl("START:book.epub:+1:/Books", parsed));
  EXPECT_FALSE(safety::parseWsStartControl("START:book.epub:1x:/Books", parsed));
  EXPECT_FALSE(safety::parseWsStartControl(std::string(safety::MAX_WS_CONTROL_BYTES + 1, 'x'), parsed));

  const char embeddedNul[] = {'S', 'T', 'A', 'R', 'T', ':', 'a', ':', '1', ':', '/', '\0', 'x'};
  EXPECT_FALSE(safety::parseWsStartControl(std::string_view(embeddedNul, sizeof(embeddedNul)), parsed));
  const char nonTerminated[] = {'S', 'T', 'A', 'R', 'T', ':', 'a', ':', '1', ':', '/'};
  EXPECT_TRUE(safety::parseWsStartControl(std::string_view(nonTerminated, sizeof(nonTerminated)), parsed));
}

TEST(FileTransferUploadBounds, RejectsCumulativeOverflowBeforeBufferingOrWriting) {
  EXPECT_TRUE(safety::canAppendTransferBytes(0, safety::MAX_TRANSFER_FILE_BYTES));
  EXPECT_TRUE(safety::canAppendTransferBytes(safety::MAX_TRANSFER_FILE_BYTES, 0));
  EXPECT_FALSE(safety::canAppendTransferBytes(safety::MAX_TRANSFER_FILE_BYTES, 1));
  EXPECT_FALSE(safety::canAppendTransferBytes(safety::MAX_TRANSFER_FILE_BYTES + 1, 0));
}

TEST(FileTransferFontUpload, AcceptsFragmentedMagicAndRejectsShortOrBadPrefixes) {
  safety::CpfontMagicAccumulator fragmented;
  const uint8_t first[] = {'C', 'P', 'F'};
  const uint8_t second[] = {'O', 'N', 'T', 0, 0, 42};
  EXPECT_TRUE(fragmented.feed(first, sizeof(first)));
  EXPECT_FALSE(fragmented.complete());
  EXPECT_TRUE(fragmented.feed(second, sizeof(second)));
  EXPECT_TRUE(fragmented.complete());

  safety::CpfontMagicAccumulator shortFile;
  const uint8_t seven[] = {'C', 'P', 'F', 'O', 'N', 'T', 0};
  EXPECT_TRUE(shortFile.feed(seven, sizeof(seven)));
  EXPECT_FALSE(shortFile.complete());

  safety::CpfontMagicAccumulator badSplit;
  const uint8_t badTail[] = {'X', 'N', 'T', 0, 0};
  EXPECT_TRUE(badSplit.feed(first, sizeof(first)));
  EXPECT_FALSE(badSplit.feed(badTail, sizeof(badTail)));
  EXPECT_FALSE(badSplit.complete());
}

TEST(FileTransferFontUpload, NeverReportsSuccessBeforePromotionConsumesOwnedTemp) {
  EXPECT_TRUE(safety::mayReportCommittedUploadSuccess(true, true, false));
  EXPECT_FALSE(safety::mayReportCommittedUploadSuccess(true, false, false));
  EXPECT_FALSE(safety::mayReportCommittedUploadSuccess(true, true, true));
  EXPECT_FALSE(safety::mayReportCommittedUploadSuccess(false, true, false));
}

TEST(FileTransferFontUpload, RequiresFullMagicAndExactReceivedWrittenCounts) {
  EXPECT_TRUE(safety::isCompleteFontPayload(true, 8, 8));
  EXPECT_TRUE(safety::isCompleteFontPayload(true, 4097, 4097));
  EXPECT_FALSE(safety::isCompleteFontPayload(false, 8, 8));
  EXPECT_FALSE(safety::isCompleteFontPayload(true, 7, 7));
  EXPECT_FALSE(safety::isCompleteFontPayload(true, 4097, 4096));
}

TEST(FileTransferTransaction, ReplaceNeverDeletesOldDestinationBeforePromote) {
  FakeOps ops;
  ops.files = {{"/temp", "new"}, {"/dest", "old"}};
  EXPECT_EQ(safety::promotePrepared(ops, "/temp", "/dest", "/backup", true), safety::ReplaceResult::Committed);
  EXPECT_EQ(ops.files.at("/dest"), "new");
  EXPECT_FALSE(ops.files.contains("/backup"));
}

TEST(FileTransferTransaction, FailedPromoteRestoresOldDestination) {
  FakeOps ops;
  ops.files = {{"/temp", "new"}, {"/dest", "old"}};
  ops.failRenameCalls.insert(2);
  EXPECT_EQ(safety::promotePrepared(ops, "/temp", "/dest", "/backup", true), safety::ReplaceResult::Failed);
  EXPECT_EQ(ops.files.at("/dest"), "old");
  EXPECT_EQ(ops.files.at("/temp"), "new");
}

TEST(FileTransferTransaction, RestoreFailureStillPreservesOldBytesInOwnedBackup) {
  FakeOps ops;
  ops.files = {{"/temp", "new"}, {"/dest", "old"}};
  ops.failRenameCalls = {2, 3};
  EXPECT_EQ(safety::promotePrepared(ops, "/temp", "/dest", "/backup", true),
            safety::ReplaceResult::RestoreFailed);
  EXPECT_EQ(ops.files.at("/backup"), "old");
  EXPECT_EQ(ops.files.at("/temp"), "new");
}

TEST(FileTransferTransaction, CleanupFailureReportsCommittedBackupRetained) {
  FakeOps ops;
  ops.files = {{"/temp", "new"}, {"/dest", "old"}};
  ops.failRemoveCalls.insert(1);
  EXPECT_EQ(safety::promotePrepared(ops, "/temp", "/dest", "/backup", true),
            safety::ReplaceResult::CommittedBackupRetained);
  EXPECT_EQ(ops.files.at("/dest"), "new");
  EXPECT_EQ(ops.files.at("/backup"), "old");
}

TEST(FileTransferTransaction, PutNeverReportsSuccessWithoutConsumedCommittedTemp) {
  EXPECT_TRUE(safety::mayReportPutSuccess(true, true, true, true, false));
  EXPECT_FALSE(safety::mayReportPutSuccess(true, true, true, false, false));
  EXPECT_FALSE(safety::mayReportPutSuccess(true, true, true, true, true));
  EXPECT_FALSE(safety::mayReportPutSuccess(false, true, true, true, false));
  // Models openFileForWrite=true while the ownership/existence verification
  // failed: the stream must not be considered healthy or committed.
  EXPECT_FALSE(safety::mayReportPutSuccess(true, true, false, false, false));
}

TEST(FileTransferTransaction, ExactCopyRejectsReadWriteAndFlushFaults) {
  uint8_t buffer[4];
  FakeReader reader{{1, 2, 3, 4, 5}};
  FakeWriter writer;
  EXPECT_TRUE(safety::copyExactly(reader, writer, 5, buffer, sizeof(buffer)));
  EXPECT_EQ(writer.bytes, reader.bytes);

  FakeReader readFault{{1, 2, 3, 4, 5}};
  readFault.failRead = 2;
  FakeWriter readFaultWriter;
  EXPECT_FALSE(safety::copyExactly(readFault, readFaultWriter, 5, buffer, sizeof(buffer)));

  FakeReader writeReader{{1, 2, 3, 4, 5}};
  FakeWriter writeFault;
  writeFault.failWrite = 1;
  EXPECT_FALSE(safety::copyExactly(writeReader, writeFault, 5, buffer, sizeof(buffer)));

  FakeReader syncReader{{1, 2, 3, 4, 5}};
  FakeWriter syncFault;
  syncFault.failSync = true;
  EXPECT_FALSE(safety::copyExactly(syncReader, syncFault, 5, buffer, sizeof(buffer)));

  FakeReader truncated{{1, 2, 3}};
  FakeWriter truncatedWriter;
  EXPECT_FALSE(safety::copyExactly(truncated, truncatedWriter, 5, buffer, sizeof(buffer)));
}

TEST(FileTransferTransaction, DurableFinishRejectsWriteSyncStickyAndCloseFaults) {
  FakeWriter healthy;
  EXPECT_TRUE(safety::finishDurableWrite(healthy));

  FakeWriter priorWriteFault;
  EXPECT_FALSE(safety::finishDurableWrite(priorWriteFault, false));
  FakeWriter syncFault;
  syncFault.failSync = true;
  EXPECT_FALSE(safety::finishDurableWrite(syncFault));
  FakeWriter stickyFault;
  stickyFault.writeError = true;
  EXPECT_FALSE(safety::finishDurableWrite(stickyFault));
  FakeWriter closeFault;
  closeFault.failClose = true;
  EXPECT_FALSE(safety::finishDurableWrite(closeFault));
}
