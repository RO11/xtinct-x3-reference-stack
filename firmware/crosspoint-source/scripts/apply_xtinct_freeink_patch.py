"""Verify the vendored, patched FreeInk source used by public XTINCT builds.

The upstream project normally uses FreeInk as a Git submodule. Public release
archives intentionally contain ordinary files so they remain source-complete
outside GitHub. This gate binds that vendored tree to the reviewed upstream
revision plus the exact XTINCT verified-TLS patch without requiring nested Git
metadata.
"""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path


if "Import" in globals():
    Import("env")  # noqa: F821
    ROOT = Path(env.subst("$PROJECT_DIR")).resolve()  # noqa: F821
else:
    ROOT = Path(__file__).resolve().parents[1]

SDK = ROOT / "freeink-sdk"
PATCH = ROOT / "patches" / "freeink-secureclient-verified-tls.patch"
PATCHED_CLIENT = SDK / "libs/network/SecureNet/src/SecureClient.cpp"
UPSTREAM_REVISION = "a485dc46ef5fb2283e4bdb674002ddbef97a9268"
EXPECTED_TREE_FILES = 385
EXPECTED_TREE_SHA256 = "6e807c9c99460c9802f6fac75f049b18cf815b8876910c6b87cb044be9e412c8"
EXPECTED_PATCH_BYTES = 6569
EXPECTED_PATCH_SHA256 = "1e276da71b7569ded966d010b9e0f1e35b95d282b8faf45b436767f218f0bfac"
EXPECTED_CLIENT_BYTES = 11152
EXPECTED_CLIENT_SHA256 = "a807e6f8325ed08cd0cb086a0d719ee7799707567894df17e64b440bb2e7df4f"
FILE_ATTRIBUTE_REPARSE_POINT = 0x400


def fail(message: str) -> None:
    raise SystemExit(f"XTINCT vendored FreeInk error: {message}")


def is_reparse(path: Path) -> bool:
    info = os.lstat(path)
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT
    )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def tree_snapshot() -> tuple[int, str]:
    if not SDK.is_dir() or is_reparse(SDK):
        fail(f"source root is missing or linked: {SDK}")
    records: list[tuple[str, int, str]] = []
    pending = [SDK]
    while pending:
        directory = pending.pop()
        if not directory.is_dir() or is_reparse(directory):
            fail(f"directory is missing or linked: {directory}")
        for child in directory.iterdir():
            if child.name == ".git" or child.name == "__pycache__":
                continue
            if is_reparse(child):
                fail(f"source contains a link/reparse entry: {child}")
            if child.is_dir():
                pending.append(child)
                continue
            if not child.is_file() or child.suffix in {".pyc", ".pyo"}:
                continue
            relative = child.relative_to(SDK).as_posix()
            records.append((relative, child.stat().st_size, sha256_file(child)))
    digest = hashlib.sha256()
    for relative, length, file_digest in sorted(records):
        digest.update(f"{relative}\0{length}\0{file_digest}\n".encode("utf-8"))
    return len(records), digest.hexdigest()


def require_file(path: Path, expected_bytes: int, expected_sha256: str, label: str) -> None:
    if not path.is_file() or is_reparse(path):
        fail(f"{label} is missing or linked: {path}")
    if path.stat().st_size != expected_bytes or sha256_file(path) != expected_sha256:
        fail(f"{label} bytes changed")


def main() -> None:
    require_file(PATCH, EXPECTED_PATCH_BYTES, EXPECTED_PATCH_SHA256, "TLS patch")
    require_file(
        PATCHED_CLIENT,
        EXPECTED_CLIENT_BYTES,
        EXPECTED_CLIENT_SHA256,
        "patched SecureClient.cpp",
    )
    files, digest = tree_snapshot()
    if files != EXPECTED_TREE_FILES or digest != EXPECTED_TREE_SHA256:
        fail(
            "source snapshot changed: "
            f"expected {EXPECTED_TREE_FILES}/{EXPECTED_TREE_SHA256}, found {files}/{digest}"
        )
    print(
        "XTINCT vendored FreeInk source verified: "
        f"upstream={UPSTREAM_REVISION} files={files} sha256={digest}"
    )


main()
