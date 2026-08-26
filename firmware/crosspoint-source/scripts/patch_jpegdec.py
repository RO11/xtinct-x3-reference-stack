"""Verify the prepatched JPEGDEC dependency in the private READY27 seed.

READY27 constructs its metadata-free dependency tree before PlatformIO starts.
The two reviewed JPEGDEC fixes are therefore already present.  This hook never
falls back to ``PROJECT_DIR/.pio`` and never mutates a dependency during the
authoritative build: it accepts only the exact prepatched file and exact patch
documents from the frozen project source.
"""

from __future__ import annotations

import hashlib
import os
import re
import sys
from pathlib import Path

try:
    Import("env")  # type: ignore[name-defined]  # noqa: F821
except NameError:
    env = None


# Pin the LF-normalized payload stored in the portable public dependency tree.
PATCHED_JPEG_INL_BYTES = 247_258
PATCHED_JPEG_INL_SHA256 = "98668ee2df0b8da33fe37ddd9715e42ddd40972626b477539d1ce6253f43de33"
PATCH_SPECS = {
    "0001-redirect-pmcu-on-mcu-skip.patch": (
        1_134,
        "59e69d602446976d36bd5505258353ce1e8dc96e9d2626d25d321817d8418ae2",
    ),
    "0002-guard-dc-writes-on-mcu-skip.patch": (
        1_707,
        "1473c0b769c8f0c3e70b3e385670225b38b0e3f292e5ca3e4c38290363dccadb",
    ),
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def require_exact_file(path: Path, expected_bytes: int, expected_sha256: str,
                       label: str) -> None:
    require(path.is_file() and not path.is_symlink(), f"{label} is missing or linked")
    payload = path.read_bytes()
    require(len(payload) == expected_bytes and sha256_bytes(payload) == expected_sha256,
            f"{label} bytes changed")


def is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def verify_private_jpegdec(project_dir: Path, libdeps_root: Path,
                           environment: str) -> None:
    project_dir = project_dir.resolve()
    libdeps_root = libdeps_root.resolve()
    require(re.fullmatch(r"[A-Za-z0-9_.-]+", environment) is not None,
            "PlatformIO environment name is unsafe")
    require(libdeps_root.is_dir() and not libdeps_root.is_symlink(),
            "READY27 private libdeps root is missing or linked")
    require(libdeps_root.name == "libdeps" and not is_within(libdeps_root, project_dir),
            "JPEGDEC hook refuses the shared project .pio/libdeps cache")

    patch_dir = project_dir / "scripts" / "jpegdec_patches"
    require(patch_dir.is_dir() and not patch_dir.is_symlink(),
            "Reviewed JPEGDEC patch directory is missing or linked")
    actual_patch_names = {path.name for path in patch_dir.iterdir() if path.is_file()}
    require(actual_patch_names == set(PATCH_SPECS),
            "Reviewed JPEGDEC patch allowlist changed")
    for name, (size, digest) in PATCH_SPECS.items():
        require_exact_file(patch_dir / name, size, digest, f"JPEGDEC patch {name}")

    library = libdeps_root / environment / "JPEGDEC"
    require(library.is_dir() and not library.is_symlink(),
            "Pinned private JPEGDEC source is missing or linked")
    require(not os.path.lexists(library / ".git"),
            "Private JPEGDEC unexpectedly retained mutable Git metadata")
    require_exact_file(
        library / "src" / "jpeg.inl",
        PATCHED_JPEG_INL_BYTES,
        PATCHED_JPEG_INL_SHA256,
        "Prepatched private JPEGDEC source",
    )
    print("Verified exact prepatched JPEGDEC private dependency")


def self_test() -> None:
    payload = b"jpegdec-self-test"
    expected = sha256_bytes(payload)
    require(sha256_bytes(payload) == expected, "JPEGDEC digest self-test failed")
    require(sha256_bytes(payload + b"!") != expected,
            "JPEGDEC mutation self-test was accepted")
    source = Path(__file__).resolve().parent
    for name, (size, digest) in PATCH_SPECS.items():
        require_exact_file(source / "jpegdec_patches" / name, size, digest,
                           f"JPEGDEC patch self-test {name}")
    print("PATCH_JPEGDEC_SELF_TEST_OK")


if env is None:
    if sys.argv[1:] != ["--self-test"]:
        raise SystemExit("Run this PlatformIO extra script directly only with --self-test")
    self_test()
    raise SystemExit(0)


verify_private_jpegdec(
    Path(env.subst("$PROJECT_DIR")),  # type: ignore[union-attr]
    Path(env.subst("$PROJECT_LIBDEPS_DIR")),  # type: ignore[union-attr]
    env.subst("$PIOENV"),  # type: ignore[union-attr]
)
