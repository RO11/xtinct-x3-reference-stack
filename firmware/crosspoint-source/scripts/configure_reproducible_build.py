"""Fail-closed reproducible-path flags for the authoritative XTINCT build.

The firmware's logging macros retain ``__FILE__`` strings. Without compiler
prefix maps, Arduino/ESP-IDF paths expose the Windows user profile in update.bin
and make otherwise identical builds host-specific. The verified wrapper owns
every input below and pins the build directory and SOURCE_DATE_EPOCH.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path


Import("env")  # type: ignore[name-defined]  # noqa: F821

EXPECTED_SOURCE_DATE_EPOCH = "1786182071"
EXPECTED_PRIVATE_BUILD_NAME = ".xtinct-build-authoritative"
EXPECTED_PRIVATE_BUILD_CACHE_NAME = ".cache"
EXPECTED_PACKAGE_DIRECTORY_NAME = "packages"
EXPECTED_ESP_IDF_PACKAGE_NAME = "framework-espidf"
VIRTUAL_ESP_IDF_ROOT = "//IDF"
EXPECTED_CORE_PREFIX = ".xtinct-ready27-core-R27-EXCEPTIONS-20260810-"
EXPECTED_CORE_LANES = ("A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K")
WARMED_COMPILE_ONLY_ENV = "XTINCT_WARMED_COMPILE_ONLY"
WARMED_BUILD_NAME = ".xtinct-ready27-warmed-compile"
EXCEPTION_GUARD_RELATIVE = Path("scripts/xtinct_exception_build_guard.h")
EXCEPTION_CONSTRUCTION_EVIDENCE_NAME = "xtinct-exception-construction.json"
EXCEPTION_POLICY = "effective-fexceptions-forced-guard-all-project-cxx-v1"
ESP_DSP_INCLUDE_RELATIVE = Path(
    "framework-arduinoespressif32-libs/esp32c3/include/"
    "espressif__esp-dsp/modules/fft/include"
)
ESP_DSP_PLATFORM_HEADER_SHA256 = (
    "f8c8ec359abe829ca12e047ce3e5ba449957b1c612c0876555251d6858e47262"
)
MDNS_INCLUDE_RELATIVE = Path(
    "framework-arduinoespressif32-libs/esp32c3/include/"
    "espressif__mdns/include"
)
MDNS_HEADER_SHA256 = (
    "883cae69f6edc3b5743ec83fa698e416be3a69a719ad66245728837d334f1ae6"
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def owned_directory(name: str) -> Path:
    value = os.environ.get(name, "").strip()
    require(bool(value), f"Reproducible build environment is missing {name}")
    path = Path(value).resolve()
    require(path.is_dir() and not path.is_symlink(), f"{name} is not a plain directory")
    return path


require(os.environ.get("SOURCE_DATE_EPOCH") == EXPECTED_SOURCE_DATE_EPOCH,
        "SOURCE_DATE_EPOCH is not the reviewed deterministic value")
require(os.environ.get("TZ") == "UTC", "Authoritative build timezone is not UTC")
require(env.subst("$PIOENV") == "default", "Reproducible flags are reviewed only for the default environment")  # type: ignore[name-defined]  # noqa: F821
warmed_compile_only = os.environ.get(WARMED_COMPILE_ONLY_ENV) == "1"

physical_project = owned_directory("XTINCT_REPRO_PROJECT_ROOT")
core_root = owned_directory("XTINCT_REPRO_CORE_ROOT")
user_root = owned_directory("XTINCT_REPRO_USER_ROOT")
packages_root = owned_directory("XTINCT_PINNED_PACKAGES_DIR")
private_build = owned_directory("PLATFORMIO_BUILD_DIR")
private_build_cache = owned_directory("XTINCT_REPRO_BUILD_CACHE_ROOT")

if warmed_compile_only:
    require(core_root == user_root / ".platformio",
            "Warmed compile-only core is not the local PlatformIO root")
    require(packages_root == core_root / EXPECTED_PACKAGE_DIRECTORY_NAME,
            "Warmed compile-only package directory escaped the local PlatformIO root")
    require(private_build.parent == core_root and private_build.name == WARMED_BUILD_NAME,
            "Warmed compile-only build directory is not the one-off owned path")
else:
    require(core_root.name in {EXPECTED_CORE_PREFIX + lane for lane in EXPECTED_CORE_LANES},
            "Private READY27 PlatformIO core name changed")
    require(os.path.samefile(packages_root.parent, core_root) and
            packages_root.name == EXPECTED_PACKAGE_DIRECTORY_NAME,
            "Pinned package directory escaped the private READY27 PlatformIO core")
    require(os.path.samefile(private_build.parent, core_root) and
            private_build.name == EXPECTED_PRIVATE_BUILD_NAME,
            "Private build directory is not the deterministic wrapper-owned path")
require(os.path.samefile(private_build_cache.parent, private_build) and
        private_build_cache.name == EXPECTED_PRIVATE_BUILD_CACHE_NAME,
        "Build cache is not the wrapper-owned fresh per-run directory")
require(Path(os.environ.get("PLATFORMIO_BUILD_CACHE_DIR", "")).resolve() == private_build_cache,
        "PlatformIO and reproducible build-cache roots disagree")
require(core_root.is_relative_to(user_root), "PlatformIO core escaped the reviewed user root")
canonical_packages_root = core_root / EXPECTED_PACKAGE_DIRECTORY_NAME
canonical_esp_idf = canonical_packages_root / EXPECTED_ESP_IDF_PACKAGE_NAME
supplied_esp_idf = packages_root / EXPECTED_ESP_IDF_PACKAGE_NAME
require(canonical_packages_root.is_dir() and not canonical_packages_root.is_symlink() and
        canonical_esp_idf.is_dir() and not canonical_esp_idf.is_symlink() and
        supplied_esp_idf.is_dir() and not supplied_esp_idf.is_symlink() and
        os.path.samefile(canonical_packages_root, packages_root) and
        os.path.samefile(canonical_esp_idf, supplied_esp_idf),
        "Canonical and supplied ESP-IDF package identities disagree")

# PNGdec 1.1.6 ships an ESP32-S3 assembly source in every architecture.  Its
# first preprocessor include is the pinned esp-dsp platform header; on C3 that
# header disables the S3 SIMD body.  Add only that reviewed package directory
# so the assembler can evaluate the target guard without enabling or fetching
# any managed ESP-IDF component.
esp_dsp_include = (packages_root / ESP_DSP_INCLUDE_RELATIVE).resolve()
require(esp_dsp_include.is_dir() and not esp_dsp_include.is_symlink() and
        esp_dsp_include.is_relative_to(packages_root),
        "Pinned ESP32-C3 esp-dsp include directory is invalid")
esp_dsp_platform_header = esp_dsp_include / "dsps_fft2r_platform.h"
require(esp_dsp_platform_header.is_file() and not esp_dsp_platform_header.is_symlink() and
        hashlib.sha256(esp_dsp_platform_header.read_bytes()).hexdigest() ==
        ESP_DSP_PLATFORM_HEADER_SHA256,
        "Pinned ESP32-C3 esp-dsp platform header changed")
env.AppendUnique(CPPPATH=[str(esp_dsp_include)])  # type: ignore[name-defined]  # noqa: F821

# The isolated Arduino SDK rebuild keeps libespressif__mdns, while its
# generated Arduino include list omits the managed component's public header
# directory. Pin and expose only that reviewed directory so ESPmDNS and
# ArduinoOTA compile against the exact SDK that supplies the linked archive.
mdns_include = (packages_root / MDNS_INCLUDE_RELATIVE).resolve()
require(mdns_include.is_dir() and not mdns_include.is_symlink() and
        mdns_include.is_relative_to(packages_root),
        "Pinned ESP32-C3 mDNS include directory is invalid")
mdns_header = mdns_include / "mdns.h"
require(mdns_header.is_file() and not mdns_header.is_symlink() and
        hashlib.sha256(mdns_header.read_bytes()).hexdigest() == MDNS_HEADER_SHA256,
        "Pinned ESP32-C3 mDNS header changed")
env.AppendUnique(CPPPATH=[str(mdns_include)])  # type: ignore[name-defined]  # noqa: F821

project_alias_text = env.subst("$PROJECT_DIR")  # type: ignore[name-defined]  # noqa: F821
project_alias = Path(project_alias_text)
require(project_alias.drive.upper() == "X:" and not any(ch.isspace() for ch in project_alias_text),
        "Authoritative project alias must be the deterministic X: drive")
require(os.path.samefile(project_alias, physical_project),
        "Authoritative project alias no longer points at the physical source")

exception_guard = physical_project / EXCEPTION_GUARD_RELATIVE
require(exception_guard.is_file() and not exception_guard.is_symlink(),
        "C++ exception build guard is missing or linked")
exception_guard_bytes = exception_guard.read_bytes()
require(b"__cpp_exceptions" in exception_guard_bytes and
        b"#error" in exception_guard_bytes,
        "C++ exception build guard lost its fail-closed feature check")
guard_alias = project_alias / EXCEPTION_GUARD_RELATIVE
require(os.path.samefile(guard_alias, exception_guard),
        "Aliased C++ exception build guard is not the reviewed source")

# CXXFLAGS is inherited by application and library C++ builders.  Force the
# guard into every C++ translation unit, then inspect the fully expanded SCons
# command template after PlatformIO has applied build_flags/build_unflags.
# At this early PlatformIO pre-script point, configured build_flags have not
# yet been folded into $CXXCOM (the observed expansion was only
# ``CC -o -c -include ...``). Put the release requirement directly in CXXFLAGS
# beside the guard. GCC resolves repeated exception switches left-to-right, so
# the invariant is that the final effective switch is -fexceptions; duplicates
# before it are harmless. The forced header remains the per-TU backstop: any
# later -fno-exceptions makes __cpp_exceptions disappear and compilation fails.
env.Append(CXXFLAGS=["-include", str(guard_alias), "-fexceptions"])  # type: ignore[name-defined]  # noqa: F821
expanded_cxx_command = env.subst("$CXXCOM")  # type: ignore[name-defined]  # noqa: F821
exception_switches = re.findall(r"(?<!\S)-f(?:no-)?exceptions(?!\S)", expanded_cxx_command)
require(bool(exception_switches) and exception_switches[-1] == "-fexceptions",
        "Effective C++ command must end its exception-switch sequence with -fexceptions; "
        f"found {exception_switches!r} in {expanded_cxx_command!r}")
normalized_command = expanded_cxx_command.replace("\\", "/")
normalized_guard = str(guard_alias).replace("\\", "/")
require(re.search(r"(?:^|\s)-include(?:\s+|=)" + re.escape(normalized_guard) +
                   r"(?:\s|$)", normalized_command) is not None,
        "Effective C++ command does not force-include the exception guard")

environment_build = Path(env.subst("$BUILD_DIR")).resolve()  # type: ignore[name-defined]  # noqa: F821
require(environment_build.parent == private_build and environment_build.name == "default",
        "Exception construction evidence escaped the reviewed default build directory")
environment_build.mkdir(parents=True, exist_ok=True)
construction_evidence = environment_build / EXCEPTION_CONSTRUCTION_EVIDENCE_NAME
require(not construction_evidence.exists() and not construction_evidence.is_symlink(),
        "Exception construction evidence was not created in a clean build tree")
evidence = {
    "effective_exception_switches": exception_switches,
    "guard": {
        "bytes": len(exception_guard_bytes),
        "path": EXCEPTION_GUARD_RELATIVE.as_posix(),
        "sha256": hashlib.sha256(exception_guard_bytes).hexdigest(),
    },
    "policy": EXCEPTION_POLICY,
    "schema": 1,
}
with construction_evidence.open("x", encoding="utf-8", newline="\n") as handle:
    json.dump(evidence, handle, indent=2, sort_keys=True)
    handle.write("\n")

path_maps = {
    str(canonical_esp_idf).replace("\\", "/").rstrip("/"): VIRTUAL_ESP_IDF_ROOT,
    str(supplied_esp_idf).replace("\\", "/").rstrip("/"): VIRTUAL_ESP_IDF_ROOT,
    str(physical_project).replace("\\", "/").rstrip("/"): "/xtinct/source",
    project_alias_text.replace("\\", "/").rstrip("/"): "/xtinct/source",
    str(private_build).replace("\\", "/").rstrip("/"): "/xtinct/build",
    str(packages_root).replace("\\", "/").rstrip("/"): "/xtinct/packages",
    str(canonical_packages_root).replace("\\", "/").rstrip("/"): "/xtinct/packages",
    str(core_root).replace("\\", "/").rstrip("/"): "/xtinct/core",
    str(user_root).replace("\\", "/").rstrip("/"): "/xtinct/user",
}
for environment_name, replacement, physical in (
    ("XTINCT_REPRO_BUILD_ALIAS", "/xtinct/build", private_build),
    ("XTINCT_REPRO_PACKAGES_ALIAS", "/xtinct/packages", packages_root),
    ("XTINCT_REPRO_CORE_ALIAS", "/xtinct/core", core_root),
):
    raw_alias = os.environ.get(environment_name, "").replace("\\", "/").rstrip("/")
    require(raw_alias and os.path.samefile(Path(raw_alias), physical),
            f"{environment_name} immutable short path changed identity")
    path_maps[raw_alias] = replacement
flags = ["-fno-record-gcc-switches"]
# GCC resolves overlapping prefix-map options using the last matching rule.
# Emit broad roots first so the longest, most specific package roots win last.
for source, replacement in sorted(path_maps.items(), key=lambda item: len(item[0])):
    require(source and "=" not in source and "\0" not in source,
            "Reproducible path-map source is unsafe")
    for option in ("-ffile-prefix-map", "-fmacro-prefix-map", "-fdebug-prefix-map"):
        flags.append(f"{option}={source}={replacement}")

env.AppendUnique(CCFLAGS=flags)  # type: ignore[name-defined]  # noqa: F821
env.AppendUnique(LINKFLAGS=[  # type: ignore[name-defined]  # noqa: F821
    "-Wl,--strip-debug",
    "-Wl,--eh-frame-hdr",
])
print("XTINCT deterministic compiler time/path mapping verified")
print("XTINCT effective C++ exception construction verified")
if warmed_compile_only:
    print("XTINCT NON-AUTHORITATIVE warmed compile-only mode")
