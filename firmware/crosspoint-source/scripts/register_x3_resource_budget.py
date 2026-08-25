"""PlatformIO post-link gate for the X3 resource contract."""

Import("env")

import subprocess
import sys
from pathlib import Path


project = Path(env.subst("$PROJECT_DIR")).resolve()
checker = project / "scripts" / "check_x3_resource_budgets.py"
environment = env.subst("$PIOENV")
X3_ENVIRONMENTS = frozenset({"default", "gh_release", "gh_release_rc", "slim"})
NON_X3_ENVIRONMENTS = frozenset({"sticky"})


def run_budget_gate(arguments):
    result = subprocess.run(
        [sys.executable, "-B", str(checker), "--project-root", str(project), *arguments],
        cwd=project,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
    )
    if result.stdout:
        print(result.stdout, end="")
    if result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout or "X3 resource budget gate failed").strip())


# Fail before compilation if the spec, generated sheet, or source constants drift.
run_budget_gate([])


def verify_linked_budget(source, target, env):
    build_dir = Path(env.subst("$BUILD_DIR")).resolve()
    program = env.subst("${PROGNAME}")
    firmware_bin = build_dir / f"{program}.bin"
    firmware_map = build_dir / f"{program}.map"
    packages = Path(env.subst("$PROJECT_PACKAGES_DIR")).resolve()
    sdkconfig = (
        packages / "framework-arduinoespressif32-libs" / "esp32c3" /
        "dio_qspi" / "include" / "sdkconfig.h"
    )
    run_budget_gate([
        "--firmware-bin", str(firmware_bin),
        "--firmware-map", str(firmware_map),
        "--sdkconfig", str(sdkconfig),
    ])


if environment in X3_ENVIRONMENTS:
    env.AddPostAction("$BUILD_DIR/${PROGNAME}.bin", verify_linked_budget)
elif environment not in NON_X3_ENVIRONMENTS:
    raise RuntimeError(
        f"Unclassified PlatformIO environment {environment!r}; explicitly classify it "
        "before bypassing or applying the X3 linked-resource gate"
    )
