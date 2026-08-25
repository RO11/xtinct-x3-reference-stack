"""Prove the EPUB source gate rejects representative safety regressions."""

from pathlib import Path
import os
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[2]
VERIFY = Path(__file__).with_name("verify_source_contract.py")


def copy_contract_tree(destination: Path) -> None:
    shutil.copy2(ROOT / "platformio.ini", destination / "platformio.ini")
    for directory in ("lib/Epub", "lib/Serialization", "src/activities", "src/util", "test/epub_safety_bounds"):
        source = ROOT / directory
        target = destination / directory
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(source, target)


def mutate_and_expect_rejection(root: Path, relative: str, old: str, new: str, label: str) -> None:
    path = root / relative
    original = path.read_text(encoding="utf-8")
    if old not in original:
        raise SystemExit(f"mutation fixture drift ({label}): {old}")
    path.write_text(original.replace(old, new, 1), encoding="utf-8")
    environment = os.environ.copy()
    environment["EPUB_CONTRACT_ROOT"] = str(root)
    result = subprocess.run(
        [sys.executable, str(VERIFY)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=environment,
        check=False,
    )
    path.write_text(original, encoding="utf-8")
    if result.returncode == 0:
        raise SystemExit(f"source contract accepted forbidden mutation: {label}")
    print(f"mutation rejected: {label}")


with tempfile.TemporaryDirectory(prefix="epub-contract-mutations-") as temp:
    staged = Path(temp)
    copy_contract_tree(staged)
    mutations = (
        ("platformio.ini", "CONFIG_COMPILER_CXX_EXCEPTIONS=y", "CONFIG_COMPILER_CXX_EXCEPTIONS=n",
         "disable ESP-IDF exception runtime"),
        ("lib/Epub/Epub/parsers/ChapterHtmlSlimParser.cpp", "catchAllocationFailure([&]() { startElementImpl",
         "removedAllocationBoundary([&]() { startElementImpl", "remove Expat callback catch"),
        ("lib/Epub/Epub/Page.cpp",
         "if (!line) {\n    epub::limits::markPageDecodeResourceRefusal(failure);",
         "if (!line) {\n    /* missing decode refusal promotion */",
         "drop direct nothrow decode status"),
        ("lib/Epub/Epub/blocks/TextBlock.cpp",
         "if (!epub::limits::checkedStringResize(staged, length, maximum)) {\n    epub::limits::markPageDecodeResourceRefusal(failure);",
         "if (!epub::limits::checkedStringResize(staged, length, maximum)) {\n    /* missing string refusal status */",
         "drop page-string refusal status"),
        ("src/activities/reader/EpubReaderActivity.cpp", "PageLoadRecovery::PreserveCacheAndShowError",
         "PageLoadRecovery::ClearAndRebuild", "route resource refusal to corruption"),
        ("src/activities/reader/EpubReaderActivity.cpp",
         "renderer.displayBuffer();\n        return;\n      }\n      LOG_ERR(\"ERS\", \"Failed to load page from SD",
         "renderer.displayBuffer();\n        /* missing branch-local return */\n      }\n      LOG_ERR(\"ERS\", \"Failed to load page from SD",
         "allow resource refusal to fall into cache deletion"),
        ("src/activities/reader/EpubReaderActivity.cpp",
         "pageLoadRetryCount = 0;\n        section.reset();\n        requestUpdate();",
         "pageLoadRetryCount = 0;\n        section->clearCache();  // forbidden preserved-cache deletion\n        section.reset();\n        requestUpdate();",
         "delete cache in RestartRequired reload branch"),
        ("src/activities/reader/ReaderActivity.cpp",
         "GfxRenderer::FrameBufferLoan loan(renderer);",
         "std::optional<GfxRenderer::FrameBufferLoan> loan;\n    if (uncached) loan.emplace(renderer);",
         "withhold scratch from rejected existing book cache"),
        ("src/activities/reader/EpubReaderActivity.cpp",
         "if (xtinct::reader_open_policy::savedSpineNeedsReset(currentSpineIndex, spineCount))",
         "if (false && xtinct::reader_open_policy::savedSpineNeedsReset(currentSpineIndex, spineCount))",
         "trust stale persisted end-of-book progress"),
        ("src/util/NextBookFinder.cpp",
         "!xtinct::reader_open_policy::allowSiblingBookSuggestions(currentBookPath)",
         "false /* expose managed artifact hashes */",
         "expose content-addressed Inbox sibling suggestions"),
        ("src/activities/ActivityManager.cpp", "currentActivity->onDeferredAllocationFailure",
         "/* missing deferred allocation failure hook */", "remove deferred result containment"),
        ("test/epub_safety_bounds/CMakeLists.txt", "${REPO_ROOT}/lib/Epub/Epub/Page.cpp",
         "# production Page.cpp omitted", "remove full production Page test target"),
    )
    for mutation in mutations:
        mutate_and_expect_rejection(staged, *mutation)

print("EPUB source-contract mutation checks: PASS")
