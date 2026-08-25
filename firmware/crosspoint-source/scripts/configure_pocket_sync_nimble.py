"""Fail-closed PlatformIO bridge for the pinned NimBLE ESP32-C3 headers.

pioarduino's component filtering can leave the ESP-IDF `bt` include directory
out of an Arduino library compile after an interrupted build. NimBLE-Arduino
bundles its host but deliberately uses Espressif's controller API (`esp_bt.h`).
Resolve that one SDK include through PlatformIO's package manager, verify the
pinned header bytes, then add it without mutating a package in place.
"""

from __future__ import annotations

import hashlib
from pathlib import Path


Import("env")  # type: ignore[name-defined]  # noqa: F821

EXPECTED_ESP_BT_SHA256 = "fe9ddbfcda7b724e294e9c0000ab3acae412a60a679e17e649f4ab93df4661e0"
EXPECTED_NIMCONFIG_SHA256 = "c4caa5fe877b734349dce027ba5037e5e875df085931eb72404ecf0fa10cc830"
PATCHED_NIMCONFIG_SHA256 = "332223dd5b0bed8c50608501ac9e99f7da538831d5b48daeae303ad5c948c2ab"
EXPECTED_NIMBLE_SERVER_SHA256 = "af4335cf6b9e5ca3be63770307736fe50d29b53529c0dd3579f7ed515b553895"
PATCHED_NIMBLE_SERVER_SHA256 = "3ef0726e66b5933d3b4a9e5b163a7f249472b2bb76b2b16ab03e96226a5cada0"
GATT_PROCS_DEFAULT = b"#define CONFIG_BT_NIMBLE_GATT_MAX_PROCS 4"
GATT_PROCS_GUARDED = (
    b"#ifndef CONFIG_BT_NIMBLE_GATT_MAX_PROCS\n"
    b"#define CONFIG_BT_NIMBLE_GATT_MAX_PROCS 4\n"
    b"#endif"
)
NOTIFY_TX_WITHOUT_PEER = b"""            if (pChar == nullptr) {
                return 0;
            }

            if (event->notify_tx.indication) {
"""
NOTIFY_TX_WITH_PEER = b"""            if (pChar == nullptr) {
                return 0;
            }

            rc = ble_gap_conn_find(event->notify_tx.conn_handle, &peerInfo.m_desc);
            if (rc != 0) {
                return 0;
            }

            if (event->notify_tx.indication) {
"""
def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


platform = env.PioPlatform()  # type: ignore[name-defined]  # noqa: F821
sdk_package = platform.get_package_dir("framework-arduinoespressif32-libs")
require(bool(sdk_package), "Pocket Sync cannot resolve the pinned Arduino ESP-IDF libraries")
sdk_root = Path(sdk_package).resolve()
bt_include = sdk_root / "esp32c3" / "include" / "bt" / "include" / "esp32c3" / "include"
esp_bt_header = bt_include / "esp_bt.h"
require(bt_include.is_dir() and esp_bt_header.is_file(), "Pinned ESP32-C3 Bluetooth controller header is missing")
actual_digest = hashlib.sha256(esp_bt_header.read_bytes()).hexdigest()
require(actual_digest == EXPECTED_ESP_BT_SHA256, "Pinned ESP32-C3 esp_bt.h provenance changed")

env.AppendUnique(CPPPATH=[str(bt_include)])  # type: ignore[name-defined]  # noqa: F821

# NimBLE-Arduino 2.5.0 guards every other resource default with `#ifndef`,
# but GATT_MAX_PROCS is unconditional. That silently overwrites the generated
# READY24 sdkconfig value (1) with 4 and emits a redefinition warning. Patch
# only this pinned source byte sequence so the effective compile value remains
# the reviewed sdkconfig value. The library is project-local under .pio; no
# global PlatformIO package is modified.
libdeps_root = Path(env.subst("$PROJECT_LIBDEPS_DIR")).resolve()  # type: ignore[name-defined]  # noqa: F821
nimconfig = libdeps_root / env.subst("$PIOENV") / "NimBLE-Arduino" / "src" / "nimconfig.h"  # type: ignore[name-defined]  # noqa: F821
require(nimconfig.is_file(), "Pinned NimBLE-Arduino nimconfig.h is missing")
nimconfig_bytes = nimconfig.read_bytes()
nimconfig_digest = hashlib.sha256(nimconfig_bytes).hexdigest()
if nimconfig_digest == EXPECTED_NIMCONFIG_SHA256:
    require(nimconfig_bytes.count(GATT_PROCS_DEFAULT) == 1, "Pinned NimBLE GATT default changed")
    patched = nimconfig_bytes.replace(GATT_PROCS_DEFAULT, GATT_PROCS_GUARDED)
    require(hashlib.sha256(patched).hexdigest() == PATCHED_NIMCONFIG_SHA256,
            "Pocket Sync NimBLE compatibility patch produced unexpected bytes")
    nimconfig.write_bytes(patched)
elif nimconfig_digest != PATCHED_NIMCONFIG_SHA256:
    raise RuntimeError("Pinned NimBLE-Arduino nimconfig.h provenance changed")

# NimBLE-Arduino 2.5.0's NOTIFY_TX path calls the connection-aware onStatus
# callback with a zero-initialized NimBLEConnInfo.  XTINCT deliberately rejects
# acknowledgements from the wrong connection, so every non-zero BLE handle can
# leave CONTROL indications stuck forever.  Populate peerInfo from the event's
# handle before either status callback.  The warmed private build launcher
# restores this project-local dependency source after every build attempt.
nimble_server = libdeps_root / env.subst("$PIOENV") / "NimBLE-Arduino" / "src" / "NimBLEServer.cpp"  # type: ignore[name-defined]  # noqa: F821
require(nimble_server.is_file(), "Pinned NimBLE-Arduino NimBLEServer.cpp is missing")
server_bytes = nimble_server.read_bytes()
server_digest = hashlib.sha256(server_bytes).hexdigest()
if server_digest == EXPECTED_NIMBLE_SERVER_SHA256:
    require(server_bytes.count(NOTIFY_TX_WITHOUT_PEER) == 1,
            "Pinned NimBLE NOTIFY_TX callback changed")
    patched_server = server_bytes.replace(NOTIFY_TX_WITHOUT_PEER, NOTIFY_TX_WITH_PEER)
    require(hashlib.sha256(patched_server).hexdigest() == PATCHED_NIMBLE_SERVER_SHA256,
            "Pocket Sync NimBLE connection-info patch produced unexpected bytes")
    nimble_server.write_bytes(patched_server)
elif server_digest != PATCHED_NIMBLE_SERVER_SHA256:
    raise RuntimeError("Pinned NimBLE-Arduino NimBLEServer.cpp provenance changed")

print("Pocket Sync pinned ESP32-C3 NimBLE controller/header configuration verified")
