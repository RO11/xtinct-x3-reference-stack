#include <cstdint>
#include <string>

#include "Epub/Epub/EpubSafetyLimits.h"
#include "Epub/Epub/PageLoadRecovery.h"
#include "Epub/Epub/SectionReadTransaction.h"
#include "Serialization/BufferedFile.h"
#include "Serialization/Serialization.h"

static_assert(epub::limits::MAX_MANIFEST_ITEMS >= 1732,
              "verified large omnibus must remain supported");
static_assert(epub::limits::MAX_SPINE_ITEMS >= 1732,
              "verified large omnibus must remain supported");
static_assert(!epub::limits::paragraphTokensFit(epub::limits::MAX_PARAGRAPH_TOKENS, 1));
static_assert(epub::limits::retainedTokenBytes(epub::limits::MAX_INPUT_WORD_BYTES, false) >
              epub::limits::MAX_INPUT_WORD_BYTES);
static_assert(epub::limits::MAX_RETAINED_PARAGRAPH_BYTES < 128U * 1024U);
static_assert(epub::limits::MAX_PAGES_PER_SPINE * epub::limits::SECTION_LUT_ENTRY_BYTES ==
              epub::limits::MAX_SECTION_LUT_BYTES);
static_assert(epub::limits::MAX_RUBY_RENDER_SCRATCH_BYTES <= 32U * 1024U);
static_assert(epub::limits::RETAINED_ANCHOR_FIXED_BYTES >= 64);
static_assert(!serialization::sizedFieldFits(UINT32_MAX, 2048, 2048));
static_assert(epub::pageLoadRecovery(epub::PageLoadFailure::ResourceRefused) ==
              epub::PageLoadRecovery::PreserveCacheAndShowError);
static_assert(epub::pageLoadRecovery(epub::PageLoadFailure::RestartRequired) ==
              epub::PageLoadRecovery::ReloadPreservedCache);

struct CursorSyntaxFile {
  bool seek(unsigned long) { return true; }
};

bool cursorGuardSyntaxProbe(CursorSyntaxFile& file) {
  bool restored = false;
  epub::detail::FileCursorRestoreGuard<CursorSyntaxFile> guard(file, 0, restored);
  return guard.restore() && restored;
}

bool serializationSyntaxProbe(HalFile& file) {
  std::string value;
  serialization::BufferedFileReader buffered(file, 64);
  return buffered.good() &&
         serialization::readString(buffered, value, epub::limits::MAX_HREF_BYTES);
}
