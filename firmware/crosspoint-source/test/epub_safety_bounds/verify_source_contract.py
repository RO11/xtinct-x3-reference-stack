"""Source-level release gate for cache fail-closed wiring.

The pure limit predicates have runtime tests. These assertions pin the other
half of the contract: malformed cache reads must remove the cache and force a
rebuild, and parser failures must propagate to Epub/Section callers.
"""

from pathlib import Path
import re
import os


ROOT = Path(os.environ.get("EPUB_CONTRACT_ROOT", Path(__file__).resolve().parents[2])).resolve()


def require(path: str, needles: tuple[str, ...]) -> None:
    text = (ROOT / path).read_text(encoding="utf-8")
    for needle in needles:
        if needle not in text:
            raise SystemExit(f"missing safety contract in {path}: {needle}")


def require_before(path: str, first: str, second: str) -> None:
    text = (ROOT / path).read_text(encoding="utf-8")
    first_pos = text.find(first)
    second_pos = text.find(second)
    if first_pos < 0 or second_pos < 0 or first_pos >= second_pos:
        raise SystemExit(f"safety ordering missing in {path}: {first} before {second}")


def function_body(path: str, signature: str) -> str:
    text = (ROOT / path).read_text(encoding="utf-8")
    start = text.find(signature)
    if start < 0:
        raise SystemExit(f"missing safety function in {path}: {signature}")
    opening = text.find("{", start + len(signature))
    if opening < 0:
        raise SystemExit(f"missing function body in {path}: {signature}")
    depth = 0
    closing = -1
    for index in range(opening, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                closing = index
                break
    if closing < 0:
        raise SystemExit(f"unterminated function body in {path}: {signature}")

    # C++ function-try-block handlers follow the primary body. Include every
    # adjacent catch clause so an uncaught body cannot pass merely because a
    # catch exists somewhere else in the file.
    cursor = closing + 1
    final = closing
    while True:
        while cursor < len(text) and text[cursor].isspace():
            cursor += 1
        if not text.startswith("catch", cursor):
            break
        catch_open = text.find("{", cursor)
        if catch_open < 0:
            break
        depth = 0
        catch_close = -1
        for index in range(catch_open, len(text)):
            if text[index] == "{":
                depth += 1
            elif text[index] == "}":
                depth -= 1
                if depth == 0:
                    catch_close = index
                    break
        if catch_close < 0:
            raise SystemExit(f"unterminated catch block in {path}: {signature}")
        final = catch_close
        cursor = catch_close + 1
    return text[opening + 1:final + 1]


def require_function(path: str, signature: str, needles: tuple[str, ...],
                     forbidden: tuple[str, ...] = ()) -> str:
    body = function_body(path, signature)
    for needle in needles:
        if needle not in body:
            raise SystemExit(f"missing function-scoped safety contract in {path}::{signature}: {needle}")
    for needle in forbidden:
        if needle in body:
            raise SystemExit(f"forbidden function-scoped safety contract in {path}::{signature}: {needle}")
    return body


def braced_blocks(text: str, marker: str) -> list[str]:
    blocks: list[str] = []
    cursor = 0
    while True:
        start = text.find(marker, cursor)
        if start < 0:
            return blocks
        opening = text.find("{", start + len(marker))
        if opening < 0:
            return blocks
        depth = 0
        for index in range(opening, len(text)):
            if text[index] == "{":
                depth += 1
            elif text[index] == "}":
                depth -= 1
                if depth == 0:
                    blocks.append(text[opening + 1:index])
                    cursor = index + 1
                    break
        else:
            raise SystemExit(f"unterminated scoped block after marker: {marker}")


def ini_section(text: str, name: str) -> str:
    match = re.search(rf"(?ms)^\[{re.escape(name)}\]\s*$\n(.*?)(?=^\[|\Z)", text)
    if not match:
        raise SystemExit(f"missing platformio section [{name}]")
    return match.group(1)


def multiline_setting(section: str, key: str) -> list[str]:
    lines = section.splitlines()
    starts = [i for i, line in enumerate(lines) if re.match(rf"^{re.escape(key)}\s*=", line)]
    if len(starts) != 1:
        raise SystemExit(f"[{key}] must occur exactly once in [base]")
    result: list[str] = []
    for line in lines[starts[0] + 1:]:
        if re.match(r"^[^\s#;][^=]*=", line):
            break
        stripped = line.strip()
        if stripped and not stripped.startswith(("#", ";")):
            result.append(stripped)
    return result


platformio = (ROOT / "platformio.ini").read_text(encoding="utf-8")
base = ini_section(platformio, "base")
base_flags = "\n".join(multiline_setting(base, "build_flags"))
base_unflags = "\n".join(multiline_setting(base, "build_unflags"))
if "-fexceptions" not in base_flags or "-fno-exceptions" in base_flags:
    raise SystemExit("production build_flags must globally enable -fexceptions")
if "-fno-exceptions" not in base_unflags or "-fexceptions" in base_unflags:
    raise SystemExit("production build_unflags must remove -fno-exceptions")
sdk_lines = multiline_setting(base, "custom_sdkconfig")
sdk_values: dict[str, list[str]] = {}
for line in sdk_lines:
    if not line.startswith("CONFIG_") or "=" not in line:
        continue
    key, value = line.split("=", 1)
    sdk_values.setdefault(key, []).append(value)
expected_sdk = {
    "CONFIG_COMPILER_CXX_EXCEPTIONS": "y",
    "CONFIG_COMPILER_CXX_EXCEPTIONS_EMG_POOL_SIZE": "1024",
    "CONFIG_COMPILER_CXX_RTTI": "n",
}
for key, expected in expected_sdk.items():
    values = sdk_values.get(key, [])
    if values != [expected]:
        raise SystemExit(f"[base] custom_sdkconfig must pin {key}={expected} exactly once; got {values}")
    active_occurrences = re.findall(rf"(?m)^\s*{re.escape(key)}=([^\s#;]+)\s*$", platformio)
    if active_occurrences != [expected]:
        raise SystemExit(f"contradictory or duplicate {key} outside [base] custom_sdkconfig: {active_occurrences}")

for stale_path in (
    "lib/Epub/Epub/ParsedText.h",
    "lib/Epub/Epub/blocks/TextBlock.h",
    "src/activities/reader/EpubReaderActivity.h",
    "src/activities/reader/EpubReaderActivity.cpp",
):
    stale = (ROOT / stale_path).read_text(encoding="utf-8")
    if "-fno-exceptions" in stale or "abort under" in stale:
        raise SystemExit(f"stale no-exception allocation comment in {stale_path}")

require(
    "lib/Epub/Epub/BookMetadataCache.cpp",
    (
        "BOOK_CACHE_VERSION = 11",
        'return invalidateCache("malformed metadata string")',
        'Storage.remove((cachePath + bookBinFile).c_str())',
    ),
)

# ReaderActivity can only know whether book.bin exists before Epub::load().
# The loader may reject that file (notably after BOOK_CACHE_VERSION changes) and
# rebuild in the same call, so the scratch loan must not be conditional on the
# pre-load existence check. Popup behavior intentionally remains conditional.
reader_load = function_body("src/activities/reader/ReaderActivity.cpp",
                            "std::unique_ptr<Epub> ReaderActivity::loadEpub(")
popup_pos = reader_load.find("if (uncached)")
loan_pos = reader_load.find("GfxRenderer::FrameBufferLoan loan(renderer);")
load_pos = reader_load.find("loaded = epub->load(true, SETTINGS.embeddedStyle == 0);")
if popup_pos < 0 or loan_pos < 0 or load_pos < 0 or not popup_pos < loan_pos < load_pos:
    raise SystemExit("ReaderActivity must preserve popup gating, then lend scratch before EPUB load")
if "if (uncached) loan" in reader_load or "std::optional<GfxRenderer::FrameBufferLoan>" in reader_load:
    raise SystemExit("ReaderActivity must lend build scratch even when an existing book cache is rejected")
require(
    "lib/Epub/Epub/ParsedText.cpp",
    (
        "minimumRetained > retainedBudget_.remaining()",
        "!retainedBudget_.tryRetain(retained)",
        "releaseRetainedPrefix(consumed);",
        "retainedBudget_.tryRetain(retainedDelta)",
        "retainedBudget_.release(rubyTexts.size() * epub::limits::RETAINED_RUBY_SLOT_FIXED_BYTES)",
    ),
)
require_before(
    "lib/Epub/Epub/ParsedText.cpp",
    "minimumRetained > retainedBudget_.remaining()",
    "std::string normalizedWord(inputWord);",
)
require(
    "lib/Epub/Epub/parsers/ChapterHtmlSlimParser.cpp",
    ("!self->currentTextBlock->ensureRubyCapacity()",),
)
require(
    "lib/Epub/Epub/Section.cpp",
    (
        "SECTION_FILE_VERSION = 37",
        'return rejectCache("invalid section LUT bounds")',
        'return rejectCache("invalid serialized page span")',
        "MAX_SECTION_LUT_BYTES / sizeof(PageLutEntry)",
        "AnchorBudget anchorBudget",
        "clearCache();",
        "if (!build_->parser->finishParse())",
    ),
)
require(
    "lib/Epub/Epub.cpp",
    (
        "!opfParser.isValid()",
        "!ncxParser.isValid()",
        "!navParser.isValid()",
        "!containerParser.isValid()",
        "class CoverImageReferenceScanner final : public Print",
        "parsed.cssFiles = std::move(opfParser.cssFiles)",
        "std::vector<std::string>{}.swap(cssFiles)",
    ),
)
require_before(
    "lib/Epub/Epub.cpp",
    "ContentOpfParser opfParser",
    "bookMetadata.title = utf8ComposeNfc(parsed.title)",
)
require(
    "lib/Epub/Epub/css/CssParser.cpp",
    (
        "MAX_RETAINED_CSS_RULE_BYTES",
        "RuleMap staged",
        'Storage.remove((cachePath + rulesCache).c_str())',
        'return rejectCache("trailing or inconsistent cache bytes")',
    ),
)
require(
    "lib/Epub/Epub/Page.cpp",
    (
        "PageDecodeBudget budget(serializedBytes)",
        "budget.tryNoteElement(kind)",
        "budget.serializedRemaining() != 0",
        "MAX_PAGE_IMAGE_PATH_BYTES",
    ),
)
require(
    "lib/Epub/Epub/blocks/TextBlock.cpp",
    (
        "MAX_RUBY_RENDER_SCRATCH_BYTES",
        "Ruby render scratch allocation refused",
    ),
)
require(
    "lib/Epub/Epub/EpubSafetyLimits.h",
    (
        "MAX_RETAINED_CSS_RULE_BYTES = 80U * 1024U",
        "MAX_RETAINED_ANCHOR_BYTES = 48U * 1024U",
        "MAX_SERIALIZED_PAGE_BYTES = 160U * 1024U",
        "MAX_METADATA_BATCH_BYTES = 96U * 1024U",
        "allocationProbeForTests",
        "catchAllocationFailure",
        "checkedStringResize",
        "#if !defined(__cpp_exceptions)",
        "PageDecodeFailure",
    ),
)
require(
    "lib/Serialization/Serialization.h",
    ("sizedFieldFits(len, typeMaximum, remaining)", "resizeStringChecked(s, len)"),
)

# Every Expat C callback must catch before returning through the C ABI. The
# failure handler must mark the parser failed and synchronously stop Expat.
callback_contracts = {
    "lib/Epub/Epub/parsers/ContainerParser.cpp": (
        ("void XMLCALL ContainerParser::startElement(", "startElementImpl", "self->failed = true", "XML_StopParser"),
        ("void XMLCALL ContainerParser::endElement(", "endElementImpl", "self->failed = true", "XML_StopParser"),
    ),
    "lib/Epub/Epub/parsers/ContentOpfParser.cpp": (
        ("void XMLCALL ContentOpfParser::startElement(", "startElementImpl", "self->failParsing"),
        ("void XMLCALL ContentOpfParser::characterData(", "characterDataImpl", "self->failParsing"),
        ("void XMLCALL ContentOpfParser::endElement(", "endElementImpl", "self->failParsing"),
    ),
    "lib/Epub/Epub/parsers/TocNavParser.cpp": (
        ("void XMLCALL TocNavParser::startElement(", "startElementImpl", "self->failParsing"),
        ("void XMLCALL TocNavParser::characterData(", "characterDataImpl", "self->failParsing"),
        ("void XMLCALL TocNavParser::endElement(", "endElementImpl", "self->failParsing"),
    ),
    "lib/Epub/Epub/parsers/TocNcxParser.cpp": (
        ("void XMLCALL TocNcxParser::startElement(", "startElementImpl", "self->failParsing"),
        ("void XMLCALL TocNcxParser::characterData(", "characterDataImpl", "self->failParsing"),
        ("void XMLCALL TocNcxParser::endElement(", "endElementImpl", "self->failParsing"),
    ),
    "lib/Epub/Epub/parsers/ChapterHtmlSlimParser.cpp": (
        ("void XMLCALL ChapterHtmlSlimParser::startElement(", "startElementImpl", "self->failParsing"),
        ("void XMLCALL ChapterHtmlSlimParser::characterData(", "characterDataImpl", "self->failParsing"),
        ("void XMLCALL ChapterHtmlSlimParser::defaultHandlerExpand(", "defaultHandlerExpandImpl", "self->failParsing"),
        ("void XMLCALL ChapterHtmlSlimParser::endElement(", "endElementImpl", "self->failParsing"),
    ),
}
for path, callbacks in callback_contracts.items():
    for signature, impl, *failure_needles in callbacks:
        body = require_function(path, signature, ("catchAllocationFailure", impl, *failure_needles))
        if body.find("catchAllocationFailure") > body.find(impl):
            raise SystemExit(f"callback implementation escapes catch boundary in {path}::{signature}")

for path, signature, marker in (
    ("lib/Epub/Epub/parsers/ContentOpfParser.cpp", "void ContentOpfParser::failParsing(", "failed = true"),
    ("lib/Epub/Epub/parsers/TocNavParser.cpp", "void TocNavParser::failParsing(", "failed = true"),
    ("lib/Epub/Epub/parsers/TocNcxParser.cpp", "void TocNcxParser::failParsing(", "failed = true"),
    ("lib/Epub/Epub/parsers/ChapterHtmlSlimParser.cpp", "void ChapterHtmlSlimParser::failParsing(", "parseFailed_ = true"),
):
    require_function(path, signature, (marker, "XML_StopParser"))

# Section catches are pinned per entry point. Page load is intentionally
# different: resource refusal preserves cache; an unprovable active-build
# cursor produces RestartRequired and abandons only the temp transaction.
for signature in (
    "Section::~Section()",
    "bool Section::loadSectionFile(",
    "bool Section::startBuild(",
    "bool Section::buildSomeMore(",
):
    require_function("lib/Epub/Epub/Section.cpp", signature,
                     ("catchAllocationFailure", "abandonBuildNoThrow"))
load_page = require_function(
    "lib/Epub/Epub/Section.cpp",
    "std::unique_ptr<Page> Section::loadPage(",
    ("catchAllocationFailure", "activeBuildCursorSafe_", "RestartRequired",
     "ResourceRefused", "abandonBuildNoThrow"),
)
unsafe_cursor_blocks = braced_blocks(load_page, "if (!activeBuildCursorSafe_)")
if len(unsafe_cursor_blocks) != 2:
    raise SystemExit("Section::loadPage must handle unsafe cursor after both unwind and explicit failure")
for index, block in enumerate(unsafe_cursor_blocks):
    if "abandonBuildNoThrow" not in block or "RestartRequired" not in block:
        raise SystemExit(f"unsafe cursor branch {index} must abandon temp build and request preserved-cache restart")
    if block.find("abandonBuildNoThrow") > block.find("RestartRequired"):
        raise SystemExit(f"unsafe cursor branch {index} must abandon before publishing RestartRequired")
if "return nullptr" not in unsafe_cursor_blocks[0] or "result.reset()" not in unsafe_cursor_blocks[1]:
    raise SystemExit("unsafe cursor branches must stop the current page-load transaction")
load_page_at = require_function(
    "lib/Epub/Epub/Section.cpp",
    "std::unique_ptr<Page> Section::loadPageAt(",
    ("PageDecodeFailure", "Page::deserialize", "toSectionLoadFailure"),
    ("clearCache()",),
)

# Bind every direct nothrow page-decode allocation to explicit status
# propagation. A nullptr without this marker would be misclassified as corrupt
# and could send valid cache bytes down the deletion path.
for signature in (
    "std::unique_ptr<PageLine> PageLine::deserialize(",
    "std::unique_ptr<PageImage> PageImage::deserialize(",
    "std::unique_ptr<PageHorizontalRule> PageHorizontalRule::deserialize(",
):
    require_function("lib/Epub/Epub/Page.cpp", signature,
                     ("new (std::nothrow)", "markPageDecodeResourceRefusal"))
for path in (
    "lib/Epub/Epub/blocks/TextBlock.cpp",
    "lib/Epub/Epub/blocks/ImageBlock.cpp",
):
    read_string = require_function(
        path,
        "bool readPageString(",
        ("checkedStringResize", "budget->resourceRefused()", "markPageDecodeResourceRefusal"),
    )
    if read_string.find("checkedStringResize") > read_string.rfind("markPageDecodeResourceRefusal"):
        raise SystemExit(f"{path} must mark checked string resize refusal before returning")
page_decode = require_function(
    "lib/Epub/Epub/Page.cpp",
    "std::unique_ptr<Page> Page::deserialize(",
    ("PageDecodeFailure::InvalidData", "new (std::nothrow) Page()",
     "markPageDecodeResourceRefusal", "PageDecodeFailure::None"),
)
if page_decode.count("markPageDecodeResourceRefusal") < 4:
    raise SystemExit("Page::deserialize must promote every direct container/object allocation refusal")
text_decode = require_function(
    "lib/Epub/Epub/blocks/TextBlock.cpp",
    "std::unique_ptr<TextBlock> TextBlock::deserialize(",
    ("new (std::nothrow) TextBlock()", "makeUniqueNoThrow<uint8_t[]>",
     "markPageDecodeResourceRefusal", "checkedVectorResize"),
)
if text_decode.count("markPageDecodeResourceRefusal") < 4:
    raise SystemExit("TextBlock decode allocation refusals must all set explicit status")
require_function(
    "lib/Epub/Epub/blocks/ImageBlock.cpp",
    "std::unique_ptr<ImageBlock> ImageBlock::deserialize(",
    ("new (std::nothrow) ImageBlock", "markPageDecodeResourceRefusal",
     "budget->resourceRefused()"),
)
require_function(
    "lib/Epub/Epub/Section.cpp",
    "std::unique_ptr<Page> Section::loadPageDuringBuild(",
    ("FileCursorRestoreGuard", "activeBuildCursorSafe_", "Page::deserialize", "restore.restore()"),
)

# Reader transition and lifecycle containment are outside the normal EPUB
# render/loop catches, so bind them independently and in commit order.
transition = require_function(
    "src/activities/reader/ReaderActivity.cpp",
    "void ReaderActivity::onGoToEpubReader(",
    ("std::make_unique<EpubReaderActivity>", "hasBookOwner", "replaceActivity",
     "catch (const std::bad_alloc&)", "catch (const std::length_error&)"),
)
if not (transition.find("std::make_unique<EpubReaderActivity>") < transition.find("replaceActivity") <
        transition.find("currentBookPath.swap")):
    raise SystemExit("EPUB transition must stage activity before replacing and commit path by no-throw swap")
require_function(
    "src/activities/reader/ReaderActivity.cpp",
    "void ReaderActivity::onEnter() try",
    ("loadEpub", "onGoToEpubReader", "catch (const std::bad_alloc&)",
     "catch (const std::length_error&)"),
)
reader_enter = require_function(
    "src/activities/reader/EpubReaderActivity.cpp",
    "void EpubReaderActivity::onEnter() try",
    ("if (xtinct::reader_open_policy::savedSpineNeedsReset(currentSpineIndex, spineCount)) {",
     "normalizeSavedSpine", "nextPageNumber = 0",
     "cachedChapterTotalPageCount = 0", "cachedVisibleTextOffset.reset()"),
)
if not (reader_enter.find("savedSpineNeedsReset") < reader_enter.find("currentSpineIndex == 0")):
    raise SystemExit("stale end-of-book progress must reset before first-text-reference routing")
require_function(
    "src/util/NextBookFinder.cpp",
    "std::vector<std::string> NextBookFinder::findNextBooks(",
    ("allowSiblingBookSuggestions(currentBookPath)", "return result;"),
)
exit_body = require_function(
    "src/activities/reader/EpubReaderActivity.cpp",
    "void EpubReaderActivity::onExit() noexcept",
    ("onExitImpl", "catch (const std::bad_alloc&)", "catch (const std::length_error&)",
     "ImageBlock::setExtractor(nullptr, nullptr)",
     "abandonBuildNoThrow", "section.reset()", "epub.reset()", "setOrientation", "readerActivityLoadCount = 0"),
)
if exit_body.find("catch (const std::bad_alloc&)") > exit_body.find("ImageBlock::setExtractor(nullptr, nullptr)"):
    raise SystemExit("reader exit cleanup must be an unconditional tail after allocation catch")
activity_loop = require_function(
    "src/activities/ActivityManager.cpp",
    "void ActivityManager::loop()",
    ("handler(pendingResult)", "catch (const std::bad_alloc&)", "catch (const std::length_error&)",
     "onDeferredAllocationFailure"),
)
for catch_type in ("catch (const std::bad_alloc&)", "catch (const std::length_error&)"):
    catch_blocks = braced_blocks(activity_loop, catch_type)
    if len(catch_blocks) != 1 or "onDeferredAllocationFailure" not in catch_blocks[0]:
        raise SystemExit(f"ActivityManager deferred {catch_type} must invoke allocation-failure hook")
for signature in (
    "void EpubReaderActivity::onEnter() try",
    "void EpubReaderActivity::loop() try",
    "void EpubReaderActivity::render(RenderLock&& lock) try",
):
    reader_boundary = require_function(
        "src/activities/reader/EpubReaderActivity.cpp",
        signature,
        ("catch (const std::bad_alloc&)", "catch (const std::length_error&)",
         "handleAllocationFailure"),
    )
    for catch_type in ("catch (const std::bad_alloc&)", "catch (const std::length_error&)"):
        catch_blocks = braced_blocks(reader_boundary, catch_type)
        if len(catch_blocks) != 1 or "handleAllocationFailure" not in catch_blocks[0]:
            raise SystemExit(f"{signature} {catch_type} must invoke EPUB allocation cleanup")
require_function(
    "src/activities/reader/EpubReaderActivity.h",
    "void onDeferredAllocationFailure(",
    ("handleAllocationFailure(phase)",),
)
render_body = require_function(
    "src/activities/reader/EpubReaderActivity.cpp",
    "void EpubReaderActivity::render(RenderLock&& lock) try",
    ("PageLoadRecovery::ReloadPreservedCache", "PageLoadRecovery::PreserveCacheAndShowError",
     "preserving section cache", "section->clearCache()"),
)
if not (render_body.find("PageLoadRecovery::ReloadPreservedCache") <
        render_body.find("PageLoadRecovery::PreserveCacheAndShowError") <
        render_body.find("section->clearCache()")):
    raise SystemExit("reader must handle restart/resource refusal before the corrupt-cache clear path")
restart_blocks = braced_blocks(render_body, "::epub::PageLoadRecovery::ReloadPreservedCache)")
resource_blocks = braced_blocks(render_body, "::epub::PageLoadRecovery::PreserveCacheAndShowError)")
if len(restart_blocks) != 1 or len(resource_blocks) != 1:
    raise SystemExit("reader must have one explicit restart and one resource-refusal branch")
restart_branch = restart_blocks[0]
resource_branch = resource_blocks[0]
for token in ("section.reset()", "requestUpdate()", "return;"):
    if token not in restart_branch:
        raise SystemExit(f"RestartRequired branch must reload preserved cache via {token}")
if "clearCache" in restart_branch:
    raise SystemExit("RestartRequired branch must never clear preserved cache")
for token in ("preserving section cache", "return;"):
    if token not in resource_branch:
        raise SystemExit(f"ResourceRefused branch must stop before corruption cleanup via {token}")
for forbidden in ("clearCache", "section.reset()", "requestUpdate()", "abandonBuild"):
    if forbidden in resource_branch:
        raise SystemExit(f"ResourceRefused branch must preserve state; found {forbidden}")

require(
    "test/epub_safety_bounds/EpubSafetyBoundsTest.cpp",
    (
        "RealAllocatorFailureAfterSuccessfulPreflightIsTransactional",
        "FullPageDeserializeClassifiesPostPreflightFailureWithoutMutatingCache",
        "ActiveBuildCursorRestoreFailureRequestsPreservedCacheReload",
        "FileCursorRestoreGuard<FakeSectionFile>",
        "PageLoadRecovery::ReloadPreservedCache",
        "ExpatCallbackContainsAllocatorFailureBeforeReturningThroughC",
        "XML_StopParser",
        "checkedVectorPushBack",
        "checkedVectorResize",
        "checkedDequePushBack",
        "checkedDequeResize",
        "checkedStringAssign",
        "checkedStringResize",
        "checkedStringAppend",
    ),
)
require(
    "test/epub_safety_bounds/CMakeLists.txt",
    ("PageDecodeDependencyStubs.cpp", "${REPO_ROOT}/lib/Epub/Epub/Page.cpp",
     "${REPO_ROOT}/lib/expat/xmlparse.c", "${REPO_ROOT}/lib/expat/xmlrole.c",
     "${REPO_ROOT}/lib/expat/xmltok.c", "XML_GE=0", "stubs"),
)
require(
    "test/epub_safety_bounds/stubs/HalStorage.h",
    ("HalFile(const uint8_t* data", "std::memcpy", "int available() const"),
)

print("EPUB cache/parser source contract: PASS")
