"""Deterministic host model of the firmware Pocket Sync transactional store.

This lane models the storage and protocol state that is testable without a
Bluetooth controller.  It intentionally does not model RF, NimBLE scheduling,
Android GATT callbacks, connection supervision, or real microSD durability.
The source-contract gate binds these policies to ``PocketSyncContract.h`` and
``PocketSyncStore.cpp`` so this is not accepted as a free-standing mock.
"""

from __future__ import annotations

import binascii
import hashlib
from dataclasses import dataclass, field

from .x3_behavior_model import ModelError, VirtualSd, normalize_sd_path


MANIFEST_STREAM = 0xFF
MAX_MANIFEST_BYTES = 64 * 1024
MAX_OBJECTS = 68
MAX_OBJECT_BYTES = 20 * 1024 * 1024
MAX_PACK_BYTES = 64 * 1024 * 1024
MAX_PLAN_OPERATIONS = 203
MAX_RECEIPTS = 16
WINDOW_CHUNKS = 4
DEVICE_MAX_CHUNK = 234


class PocketModelError(ModelError):
    """A modeled fail-closed Pocket Sync result."""

    def __init__(self, result: str, message: str) -> None:
        super().__init__(message)
        self.result = result


class SimulatedPowerLoss(RuntimeError):
    """Abrupt stop which deliberately leaves the durable commit journal."""


def crc16_ccitt_false(data: bytes) -> int:
    return binascii.crc_hqx(data, 0xFFFF)


def _is_sha256(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _pack_hex(pack_id: str) -> str:
    if len(pack_id) != 68 or not pack_id.startswith("ps1-") or not _is_sha256(pack_id[4:]):
        raise PocketModelError("replay", "Replay-safe pack ID is invalid")
    return pack_id[4:]


@dataclass(frozen=True)
class PocketObjectSpec:
    """The security-relevant object ledger fields derived from the manifest."""

    size: int
    sha256: str
    references: int = 1

    def validate(self) -> None:
        if not 0 < self.size <= MAX_OBJECT_BYTES:
            raise PocketModelError("manifest", "Object size is outside the firmware bound")
        if not _is_sha256(self.sha256):
            raise PocketModelError("manifest", "Object hash is not canonical lower-case SHA-256")
        if not 0 < self.references <= 255:
            raise PocketModelError("manifest", "Every staged object must be referenced")


@dataclass
class _DiskStream:
    data: bytearray = field(default_factory=bytearray)
    durable_offset: int = 0
    exists: bool = False
    offset_readable: bool = True
    readable: bool = True
    writable: bool = True
    checkpoint_writable: bool = True
    marker_writable: bool = True
    truncate_allowed: bool = True
    reset_allowed: bool = True
    complete_marker: bool = False

    def reset(self) -> None:
        if not self.reset_allowed:
            raise PocketModelError("storage", "Staging stream could not be discarded")
        self.data.clear()
        self.durable_offset = 0
        self.exists = False
        self.offset_readable = True
        self.readable = True
        self.complete_marker = False


@dataclass(frozen=True)
class _StartIdentity:
    manifest_bytes: int
    manifest_sha256: str
    total_object_bytes: int
    object_count: int
    chunk: int


@dataclass
class _DiskSession:
    identity: _StartIdentity
    manifest: _DiskStream = field(default_factory=_DiskStream)
    objects: list[_DiskStream] = field(default_factory=list)
    object_specs: list[PocketObjectSpec] = field(default_factory=list)
    sealed: bool = False
    from_cursor: int = 0
    to_cursor: int = 0


@dataclass(frozen=True)
class PocketPlanOperation:
    """One bounded, idempotent operation in the SD-backed commit plan."""

    op: str
    path: str
    stream: int | None = None
    prepared: bytes | None = None

    @classmethod
    def install_object(cls, path: str, stream: int) -> "PocketPlanOperation":
        return cls("install-object", path, stream=stream)

    @classmethod
    def install_prepared(cls, path: str, data: bytes) -> "PocketPlanOperation":
        return cls("install-prepared", path, prepared=bytes(data))

    @classmethod
    def delete(cls, path: str) -> "PocketPlanOperation":
        return cls("delete", path)


@dataclass
class _CommitJournal:
    pack_hex: str
    phase: str
    next_operation: int
    operations: list[PocketPlanOperation]
    originals: dict[str, bytes | None]
    to_cursor: int
    corrupt: bool = False


@dataclass
class PocketPersistentState:
    """State which survives a modeled disconnect, reset, or power loss."""

    sd: VirtualSd = field(default_factory=VirtualSd)
    sessions: dict[str, _DiskSession] = field(default_factory=dict)
    receipts: list[str] = field(default_factory=list)
    last_pack: str | None = None
    cursor: int = 0
    active_commit: _CommitJournal | None = None
    receipt_writable: bool = True
    rollback_writable: bool = True
    # Test-only fault injection for the fresh-session SD tree. Firmware retries
    # this pre-manifest operation once after removing its owned partial tree.
    fresh_session_tree_failures_remaining: int = 0


def recover_atomic_sidecars(sd: VirtualSd, final_path: str) -> bool:
    """Mirror PocketSyncStore::recoverAtomic for final/.pstmp/.psbak."""

    final_path = normalize_sd_path(final_path, allow_root=False)
    temporary = final_path + ".pstmp"
    backup = final_path + ".psbak"

    def remove(path: str) -> bool:
        if path not in sd.files:
            return True
        try:
            sd.delete(path)
        except ModelError:
            return False
        return True

    if final_path in sd.files:
        return remove(temporary) and remove(backup)
    if backup in sd.files:
        if final_path in sd.fail_deletes or backup in sd.fail_deletes:
            return False
        sd.files[final_path] = sd.files.pop(backup)
        return remove(temporary)
    return remove(temporary)


class PocketSyncStoreModel:
    """START/resume/seal/object/commit model of ``PocketSyncStore``.

    A fresh instance represents a fresh firmware/NimBLE session.  Reuse the
    same :class:`PocketPersistentState` to model reconnects and reboots.
    """

    def __init__(self, persistent: PocketPersistentState | None = None) -> None:
        self.persistent = persistent or PocketPersistentState()
        self.phase = "idle"
        self.result = "ok"
        self.active = False
        self.sealed = False
        self.pack_id: str | None = None
        self.pack_hex: str | None = None
        self.current_stream = MANIFEST_STREAM
        self.accepted_offset = 0
        self.durable_offset = 0
        self.chunks_since_checkpoint = 0
        self.checkpoints: list[tuple[int, int]] = []

    @property
    def _session(self) -> _DiskSession:
        if self.pack_hex is None or self.pack_hex not in self.persistent.sessions:
            raise PocketModelError("sequence", "No active staging session")
        return self.persistent.sessions[self.pack_hex]

    def _fail(self, result: str, message: str) -> None:
        self.phase = "error"
        self.result = result
        raise PocketModelError(result, message)

    def query_state(self) -> tuple[int, str | None]:
        if not self._recover_pending_commit():
            self._fail("storage", "Pending Pocket commit could not be recovered")
        return self.persistent.cursor, self.persistent.last_pack

    def start(
        self,
        *,
        pack_id: str,
        manifest_bytes: int,
        manifest_sha256: str,
        total_object_bytes: int,
        object_count: int,
        chunk: int,
        queried: bool = True,
    ) -> None:
        if not queried:
            self._fail("protocol", "START is forbidden before QUERY_STATE")
        try:
            pack_hex = _pack_hex(pack_id)
        except PocketModelError as error:
            self._fail(error.result, str(error))
            return
        if (
            not 0 < manifest_bytes <= MAX_MANIFEST_BYTES
            or not _is_sha256(manifest_sha256)
            or not 0 <= total_object_bytes <= MAX_PACK_BYTES
            or not 0 <= object_count <= MAX_OBJECTS
            or not 0 < chunk <= DEVICE_MAX_CHUNK
        ):
            self._fail("bounds", "START metadata exceeds a Pocket Sync bound")
        if not self._recover_pending_commit():
            self._fail("storage", "START refused an unrecoverable pending commit")

        self.pack_id = pack_id
        self.pack_hex = pack_hex
        self.current_stream = MANIFEST_STREAM
        self.accepted_offset = 0
        self.durable_offset = 0
        self.chunks_since_checkpoint = 0
        self.sealed = False
        self.active = False
        self.result = "ok"

        if pack_hex in self.persistent.receipts:
            # An exact retry after a lost final indication is idempotent.
            self.phase = "complete"
            return

        identity = _StartIdentity(
            manifest_bytes,
            manifest_sha256,
            total_object_bytes,
            object_count,
            chunk,
        )
        existing = self.persistent.sessions.get(pack_hex)
        if existing is None:
            for attempt in range(2):
                if self.persistent.fresh_session_tree_failures_remaining > 0:
                    self.persistent.fresh_session_tree_failures_remaining -= 1
                    # Represent a partially-created private staging tree, then
                    # require its complete cleanup before the one safe retry.
                    self.persistent.sessions[pack_hex] = _DiskSession(identity)
                    self.persistent.sessions.pop(pack_hex, None)
                    if attempt == 1:
                        self._fail("storage", "Fresh Pocket staging tree failed twice")
                    continue
                self.persistent.sessions[pack_hex] = _DiskSession(identity)
                break
        elif existing.identity != identity:
            # Same digest with mismatched session metadata is corrupt/orphaned
            # state and is recreated from byte zero.
            self.persistent.sessions[pack_hex] = _DiskSession(identity)
        self.active = True
        session = self._session
        self.sealed = session.sealed
        if session.sealed:
            manifest_valid = (
                session.manifest.exists
                and len(session.manifest.data) == manifest_bytes
                and hashlib.sha256(session.manifest.data).hexdigest() == manifest_sha256
                and len(session.object_specs) == object_count
            )
            if not manifest_valid:
                self._fail("manifest", "Sealed manifest state is corrupt")
            self._select_next_object(0)
            return
        self._resume_stream(MANIFEST_STREAM)
        self.phase = "manifest"

    def _stream(self, stream: int) -> _DiskStream:
        session = self._session
        if stream == MANIFEST_STREAM:
            return session.manifest
        if not session.sealed or not 0 <= stream < len(session.objects):
            raise PocketModelError("sequence", "Object stream is unavailable before manifest seal")
        return session.objects[stream]

    def _expected_bytes(self, stream: int) -> int:
        session = self._session
        if stream == MANIFEST_STREAM:
            return session.identity.manifest_bytes
        if not session.sealed or not 0 <= stream < len(session.object_specs):
            return 0
        return session.object_specs[stream].size

    def _resume_stream(self, stream: int) -> None:
        expected = self._expected_bytes(stream)
        if expected == 0:
            self._fail("storage", "Resume stream has no declared byte count")
        disk = self._stream(stream)
        impossible = (
            not disk.offset_readable
            or disk.durable_offset > expected
            or (not disk.exists and disk.durable_offset != 0)
            or (disk.exists and (not disk.readable or len(disk.data) < disk.durable_offset))
        )
        if impossible:
            try:
                disk.reset()
            except PocketModelError as error:
                self._fail(error.result, str(error))
        elif disk.exists and len(disk.data) > disk.durable_offset:
            if disk.truncate_allowed:
                del disk.data[disk.durable_offset :]
            else:
                try:
                    disk.reset()
                except PocketModelError as error:
                    self._fail(error.result, str(error))
        self.current_stream = stream
        self.accepted_offset = disk.durable_offset
        self.durable_offset = disk.durable_offset
        self.chunks_since_checkpoint = 0

    def _object_valid(self, stream: int) -> bool:
        session = self._session
        disk = session.objects[stream]
        spec = session.object_specs[stream]
        return (
            disk.exists
            and len(disk.data) == spec.size
            and hashlib.sha256(disk.data).hexdigest() == spec.sha256
        )

    def _mark_object_complete(self, stream: int) -> bool:
        disk = self._session.objects[stream]
        if not self._object_valid(stream) or not disk.marker_writable:
            return False
        disk.complete_marker = True
        return True

    def _select_next_object(self, first: int) -> None:
        session = self._session
        for stream in range(first, len(session.objects)):
            disk = session.objects[stream]
            if disk.complete_marker:
                if self._object_valid(stream):
                    continue
                try:
                    disk.reset()
                except PocketModelError as error:
                    self._fail(error.result, str(error))
            self._resume_stream(stream)
            if self.accepted_offset == session.object_specs[stream].size:
                if self._mark_object_complete(stream):
                    continue
                try:
                    disk.reset()
                except PocketModelError as error:
                    self._fail(error.result, str(error))
                self._resume_stream(stream)
            self.phase = "objects"
            return
        self.current_stream = len(session.objects)
        self.accepted_offset = 0
        self.durable_offset = 0
        self.phase = "validating"

    def receive(self, *, stream: int, offset: int, data: bytes, crc: int) -> None:
        if not self.active or self.phase not in {"manifest", "objects"}:
            self._fail("sequence", "DATA arrived outside an active writable phase")
        session = self._session
        if (
            not data
            or len(data) > DEVICE_MAX_CHUNK
            or len(data) > session.identity.chunk
            or crc16_ccitt_false(data) != crc
        ):
            self._fail("crc", "DATA failed chunk bounds or CRC")
        if stream != self.current_stream or offset != self.accepted_offset:
            self._fail("sequence", "DATA stream or offset is out of sequence")
        expected = self._expected_bytes(stream)
        if expected == 0 or offset > expected or len(data) > expected - offset:
            self._fail("storage", "DATA would exceed the declared stream")
        disk = self._stream(stream)
        if not disk.writable:
            self._fail("storage", "Staging write failed")
        if not disk.exists:
            disk.exists = True
            disk.data.clear()
        if len(disk.data) != offset:
            self._fail("storage", "Staging file length does not match accepted offset")
        disk.data.extend(data)
        self.accepted_offset += len(data)
        self.chunks_since_checkpoint += 1
        complete = self.accepted_offset == expected
        if self.chunks_since_checkpoint < WINDOW_CHUNKS and not complete:
            return
        if not disk.checkpoint_writable:
            self._fail("storage", "Durable offset checkpoint failed")
        disk.durable_offset = self.accepted_offset
        self.durable_offset = self.accepted_offset
        self.checkpoints.append((stream, self.accepted_offset))
        self.chunks_since_checkpoint = 0
        if not complete or stream == MANIFEST_STREAM:
            return
        if not self._mark_object_complete(stream):
            self._fail("hash", "Completed object failed byte/SHA validation")
        self._select_next_object(stream + 1)
        # The released Android companion always begins the newly selected
        # object at zero.  Match the firmware's in-session stale-tail reset.
        if self.phase == "objects" and self.accepted_offset != 0:
            next_disk = self._stream(self.current_stream)
            try:
                next_disk.reset()
            except PocketModelError as error:
                self._fail(error.result, str(error))
            self._resume_stream(self.current_stream)

    def seal_manifest(
        self,
        *,
        objects: list[PocketObjectSpec],
        from_cursor: int,
        to_cursor: int,
        mode: str,
        semantic_valid: bool = True,
    ) -> None:
        if not self.active or self.sealed or self.current_stream != MANIFEST_STREAM:
            self._fail("sequence", "SEAL_MANIFEST is out of sequence")
        session = self._session
        disk = session.manifest
        if (
            self.accepted_offset != session.identity.manifest_bytes
            or disk.durable_offset != session.identity.manifest_bytes
        ):
            self._fail("incomplete", "Manifest has not reached its durable declared length")
        if hashlib.sha256(disk.data).hexdigest() != session.identity.manifest_sha256:
            self._fail("hash", "Manifest SHA-256 does not match START")
        if not semantic_valid or len(objects) != session.identity.object_count:
            self._fail("manifest", "Manifest object ledger is malformed")
        try:
            for spec in objects:
                spec.validate()
        except PocketModelError as error:
            self._fail(error.result, str(error))
        if sum(spec.size for spec in objects) != session.identity.total_object_bytes:
            self._fail("manifest", "Manifest object bytes do not match START")
        if (
            from_cursor != self.persistent.cursor
            or to_cursor < from_cursor
            or (from_cursor == 0 and mode != "snapshot")
            or (from_cursor != 0 and mode != "delta")
        ):
            self._fail("manifest", "Manifest cursor transition is invalid")
        session.object_specs = list(objects)
        session.objects = [_DiskStream() for _ in objects]
        session.from_cursor = from_cursor
        session.to_cursor = to_cursor
        session.sealed = True
        disk.complete_marker = True
        self.sealed = True
        if objects:
            self._resume_stream(0)
            self.phase = "objects"
        else:
            self.current_stream = 0
            self.accepted_offset = 0
            self.durable_offset = 0
            self.phase = "validating"

    def abort(self) -> None:
        if self.pack_hex is not None and self.active and self.persistent.active_commit is None:
            self.persistent.sessions.pop(self.pack_hex, None)
        self.active = False
        self.sealed = False
        self.phase = "idle"
        self.result = "ok"
        self.current_stream = MANIFEST_STREAM
        self.accepted_offset = 0
        self.durable_offset = 0

    def _operation_bytes(self, session: _DiskSession, operation: PocketPlanOperation) -> bytes:
        if operation.op == "install-prepared" and operation.prepared is not None:
            return operation.prepared
        if operation.op == "install-object" and operation.stream is not None:
            if not 0 <= operation.stream < len(session.objects):
                raise PocketModelError("commit", "Commit references an invalid staged object")
            disk = session.objects[operation.stream]
            spec = session.object_specs[operation.stream]
            if (
                not disk.exists
                or len(disk.data) != spec.size
                or hashlib.sha256(disk.data).hexdigest() != spec.sha256
            ):
                raise PocketModelError("commit", "Commit references an invalid staged object")
            return bytes(disk.data)
        raise PocketModelError("commit", "Commit operation has an invalid source")

    def _apply_operation(self, session: _DiskSession, operation: PocketPlanOperation) -> None:
        path = normalize_sd_path(operation.path, allow_root=False)
        if operation.op == "delete":
            if path in self.persistent.sd.files:
                self.persistent.sd.delete(path)
            return
        data = self._operation_bytes(session, operation)
        self.persistent.sd.atomic_replace(path, data)

    def _rollback(self, journal: _CommitJournal) -> bool:
        if not self.persistent.rollback_writable:
            journal.phase = "rollback"
            return False
        for path, original in journal.originals.items():
            if original is None:
                self.persistent.sd.files.pop(path, None)
            else:
                self.persistent.sd.files[path] = original
        self.persistent.active_commit = None
        self.persistent.sessions.pop(journal.pack_hex, None)
        return True

    def _write_receipt(self, journal: _CommitJournal) -> bool:
        if not self.persistent.receipt_writable:
            return False
        if journal.pack_hex not in self.persistent.receipts:
            while len(self.persistent.receipts) >= MAX_RECEIPTS:
                self.persistent.receipts.pop(0)
            self.persistent.receipts.append(journal.pack_hex)
        self.persistent.last_pack = journal.pack_hex
        self.persistent.cursor = journal.to_cursor
        return True

    def _finish_commit(self, journal: _CommitJournal) -> bool:
        if not self._write_receipt(journal):
            journal.phase = "rollback"
            return self._rollback(journal) and False
        self.persistent.active_commit = None
        self.persistent.sessions.pop(journal.pack_hex, None)
        return True

    def _recover_pending_commit(self) -> bool:
        journal = self.persistent.active_commit
        if journal is None:
            return True
        if (
            journal.corrupt
            or not _is_sha256(journal.pack_hex)
            or journal.pack_hex not in self.persistent.sessions
            or len(journal.operations) > MAX_PLAN_OPERATIONS
            or not 0 <= journal.next_operation <= len(journal.operations)
            or journal.phase not in {"backup", "apply", "rollback"}
        ):
            return False
        if journal.phase == "rollback":
            return self._rollback(journal)
        session = self.persistent.sessions[journal.pack_hex]
        journal.phase = "apply"
        try:
            for index in range(journal.next_operation, len(journal.operations)):
                self._apply_operation(session, journal.operations[index])
                journal.next_operation = index + 1
        except ModelError:
            journal.phase = "rollback"
            self._rollback(journal)
            return False
        return self._finish_commit(journal)

    def commit(
        self,
        operations: list[PocketPlanOperation],
        *,
        fail_at: int | None = None,
        interrupt_after: int | None = None,
    ) -> None:
        if not self.active or not self.sealed:
            self._fail("sequence", "COMMIT requires a sealed active pack")
        session = self._session
        if any(not disk.complete_marker or not self._object_valid(index) for index, disk in enumerate(session.objects)):
            self._fail("incomplete", "COMMIT requires every object marker and hash")
        if len(operations) > MAX_PLAN_OPERATIONS:
            self._fail("commit", "Commit plan exceeds the firmware operation bound")
        try:
            paths = [normalize_sd_path(operation.path, allow_root=False) for operation in operations]
        except ModelError as error:
            self._fail("commit", str(error))
            return
        if len(set(paths)) != len(paths):
            self._fail("commit", "Commit plan contains duplicate targets")
        originals = {path: self.persistent.sd.files.get(path) for path in paths}
        journal = _CommitJournal(
            pack_hex=self.pack_hex or "",
            phase="backup",
            next_operation=0,
            operations=list(operations),
            originals=originals,
            to_cursor=session.to_cursor,
        )
        self.persistent.active_commit = journal
        journal.phase = "apply"
        self.phase = "committing"
        try:
            for index, operation in enumerate(journal.operations):
                if fail_at == index:
                    raise PocketModelError("commit", "Simulated commit operation failure")
                self._apply_operation(session, operation)
                journal.next_operation = index + 1
                if interrupt_after == index:
                    raise SimulatedPowerLoss("Power lost after a durably checkpointed operation")
        except SimulatedPowerLoss:
            raise
        except ModelError as error:
            journal.phase = "rollback"
            if not self._rollback(journal):
                self._fail("commit", "Commit and rollback both failed")
            self._fail("commit", str(error))
        if not self._finish_commit(journal):
            self._fail("commit", "Receipt write failed; published files were rolled back")
        self.active = False
        self.phase = "complete"
        self.result = "ok"
