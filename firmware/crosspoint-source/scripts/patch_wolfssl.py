import hashlib
import os
import re
import sys
import tempfile
from pathlib import Path

try:
    Import("env")
except NameError:
    env = None


MARKER = "/* CrossPoint wolfSSL compatibility overrides */"
PATCHED_SETTINGS_BYTES = 20_014
PATCHED_SETTINGS_SHA256 = "311eb5652e2f487f56d45fdbdb6be9d61334a18a1bc2a2e2f962dac749ece5cc"
REQUIRED_TLS_FLAGS = (
    "-DFREEINK_NET_WOLFSSL=1",
    "-DWOLFSSL_USER_SETTINGS",
    "-DWOLFSSL_TLS13",
    "-DWOLFSSL_SHA384",
    "-DWOLFSSL_SP_384",
    "-DHAVE_FFDHE_2048",
    "-DHAVE_CURVE25519",
    "-DHAVE_SNI",
    "-DHAVE_MAX_FRAGMENT",
)
OVERRIDES = f"""

{MARKER}
#undef DEBUG_WOLFSSL /* Production: omit unused TLS trace code/strings on the RAM-limited X3. */
#undef NO_DH
#ifndef HAVE_FFDHE_2048
#define HAVE_FFDHE_2048
#endif
#ifndef HAVE_MAX_FRAGMENT
#define HAVE_MAX_FRAGMENT
#endif
/* MEMFIX-PORT: 8192 handles up to RSA-4096 keys (the public-CA maximum,
   ISRG Root X1 included) with half the per-bignum heap of 16384: with
   WOLFSSL_SMALL_STACK each fast-math temp is FP_MAX_BITS/8 * 2 bytes on the
   heap, and TLS cert verification allocates dozens at once. */
#undef FP_MAX_BITS
#define FP_MAX_BITS 8192
"""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def without_c_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", lambda match: "\n" * match.group(0).count("\n"), text, flags=re.DOTALL)
    return re.sub(r"//[^\r\n]*", "", text)


def debug_wolfssl_is_defined(text: str) -> bool:
    directives = re.findall(
        r"(?m)^[ \t]*#[ \t]*(define|undef)[ \t]+DEBUG_WOLFSSL(?:[ \t]|$)",
        without_c_comments(text),
    )
    require(bool(directives), "wolfSSL DEBUG_WOLFSSL directive is missing")
    return directives[-1] == "define"


def render_patched_settings(text: str) -> str:
    require(text.count(MARKER) <= 1, "wolfSSL settings contain duplicate CrossPoint markers")
    base = text.split(MARKER, 1)[0].rstrip() if MARKER in text else text.rstrip()
    require(debug_wolfssl_is_defined(base), "Pinned wolfSSL settings no longer enable the reviewed debug default")
    patched = base + OVERRIDES + "\n"
    require(patched.count(MARKER) == 1, "wolfSSL patch marker is not unique")
    require(not debug_wolfssl_is_defined(patched), "wolfSSL internal debug remained enabled after the patch")
    for required in (
        "#undef NO_DH",
        "#define HAVE_FFDHE_2048",
        "#define HAVE_MAX_FRAGMENT",
        "#define FP_MAX_BITS 8192",
    ):
        require(required in patched, f"Required wolfSSL TLS setting is missing: {required}")
    return patched


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def find_settings_files(libdeps_root: Path, environment: str) -> list[Path]:
    require(re.fullmatch(r"[A-Za-z0-9_.-]+", environment) is not None,
            "PlatformIO environment name is unsafe")
    settings_files: list[Path] = []
    environment_root = libdeps_root / environment
    for library_dir_name in ("Arduino-wolfSSL", "wolfssl"):
        candidate = environment_root / library_dir_name / "src" / "user_settings.h"
        if os.path.lexists(candidate):
            settings_files.append(candidate)
    require(
        len(settings_files) == 1,
        "Exactly one private wolfSSL user_settings.h is required",
    )
    return settings_files


def verify_private_settings(project_dir: Path, libdeps_root: Path,
                            environment: str) -> None:
    project_dir = project_dir.resolve()
    libdeps_root = libdeps_root.resolve()
    require(libdeps_root.is_dir() and not libdeps_root.is_symlink(),
            "READY27 private libdeps root is missing or linked")
    require(libdeps_root.name == "libdeps" and not is_within(libdeps_root, project_dir),
            "wolfSSL hook refuses the shared project .pio/libdeps cache")
    settings_files = find_settings_files(libdeps_root, environment)
    for settings in settings_files:
        library = settings.parents[1]
        require(library.is_dir() and not library.is_symlink(),
                "Pinned private wolfSSL source is missing or linked")
        require(not os.path.lexists(library / ".git"),
                "Private wolfSSL unexpectedly retained mutable Git metadata")
        require(settings.is_file() and not settings.is_symlink(),
                "Private wolfSSL settings are missing or linked")
        payload = settings.read_bytes()
        require(len(payload) == PATCHED_SETTINGS_BYTES and
                sha256_bytes(payload) == PATCHED_SETTINGS_SHA256,
                "Prepatched private wolfSSL settings bytes changed")
        text = payload.decode("utf-8", errors="strict")
        require(text.count(MARKER) == 1 and not debug_wolfssl_is_defined(text),
                "Private wolfSSL compatibility settings are not effective")


def validate_project_configuration(project_dir: Path) -> None:
    platformio_path = project_dir / "platformio.ini"
    platformio_text = platformio_path.read_text(encoding="utf-8")
    for flag in REQUIRED_TLS_FLAGS:
        pattern = rf"(?m)^[ \t]*{re.escape(flag)}(?:[ \t]*(?:[;#].*)?)?$"
        require(re.search(pattern, platformio_text) is not None, f"Required TLS build flag is missing: {flag}")

    forbidden_flag = re.compile(r"(?m)^[ \t]*-D[ \t]*FREEINK_WOLFSSL_DEBUG(?:[= \t]|$)")
    for config_path in project_dir.glob("platformio*.ini"):
        require(
            forbidden_flag.search(config_path.read_text(encoding="utf-8")) is None,
            f"wolfSSL debug opt-in is enabled in {config_path.name}",
        )

    forbidden_define = re.compile(
        r"(?m)^[ \t]*#[ \t]*define[ \t]+FREEINK_WOLFSSL_DEBUG(?:[ \t]|$)"
    )
    for source_root_name in ("src", "lib", "freeink-sdk"):
        source_root = project_dir / source_root_name
        for source_path in source_root.rglob("*"):
            if not source_path.is_file() or ".git" in source_path.parts:
                continue
            if source_path.suffix.lower() not in (".c", ".cc", ".cpp", ".h", ".hh", ".hpp"):
                continue
            source = source_path.read_text(encoding="utf-8", errors="strict")
            require(
                forbidden_define.search(without_c_comments(source)) is None,
                f"wolfSSL debug opt-in is defined in {source_path.relative_to(project_dir)}",
            )


def self_test(project_dir: Path) -> None:
    validate_project_configuration(project_dir)
    with tempfile.TemporaryDirectory(prefix="xtinct-wolfssl-selftest-") as temporary_name:
        fixture = Path(temporary_name) / "user_settings.h"
        original = "#define DEBUG_WOLFSSL\n#define NO_DH\n#define FP_MAX_BITS 16384\n"
        fixture.write_text(original, encoding="utf-8", newline="\n")
        patched_once = render_patched_settings(fixture.read_text(encoding="utf-8"))
        require(not debug_wolfssl_is_defined(patched_once),
                "wolfSSL debug self-test failed")
        require(render_patched_settings(patched_once) == patched_once,
                "wolfSSL settings rendering is not idempotent")
        require(sha256_bytes(patched_once.encode("utf-8") + b"!") !=
                sha256_bytes(patched_once.encode("utf-8")),
                "wolfSSL mutation self-test was accepted")
    print("PATCH_WOLFSSL_SELF_TEST_OK")


if env is None:
    if sys.argv[1:] != ["--self-test"]:
        raise SystemExit("Run this PlatformIO extra script directly only with --self-test")
    self_test(Path(__file__).resolve().parents[1])
    raise SystemExit(0)


PROJECT_DIR = Path(env.subst("$PROJECT_DIR"))
validate_project_configuration(PROJECT_DIR)
verify_private_settings(
    PROJECT_DIR,
    Path(env.subst("$PROJECT_LIBDEPS_DIR")),
    env.subst("$PIOENV"),
)
print("Verified exact prepatched wolfSSL private dependency")
