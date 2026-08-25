from __future__ import annotations

import hashlib
import unittest

from .pocket_sync_model import (
    DEVICE_MAX_CHUNK,
    MANIFEST_STREAM,
    MAX_MANIFEST_BYTES,
    MAX_OBJECT_BYTES,
    MAX_PACK_BYTES,
    MAX_RECEIPTS,
    PocketModelError,
    PocketObjectSpec,
    PocketPersistentState,
    PocketPlanOperation,
    PocketSyncStoreModel,
    SimulatedPowerLoss,
    crc16_ccitt_false,
    recover_atomic_sidecars,
)
from .x3_behavior_model import VirtualSd


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def send(store: PocketSyncStoreModel, stream: int, payload: bytes, *, chunk: int) -> None:
    offset = store.accepted_offset
    while offset < len(payload):
        part = payload[offset : offset + chunk]
        store.receive(stream=stream, offset=offset, data=part, crc=crc16_ccitt_false(part))
        offset += len(part)


class PocketSyncStoreQa(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = b'{"schema":"xtinct-pocket-sync-pack/1"}'
        self.article = b"A verified synthetic Pocket Sync article."
        self.pack_id = "ps1-" + "a" * 64

    def start_one(
        self,
        persistent: PocketPersistentState | None = None,
        *,
        pack_id: str | None = None,
        chunk: int = 10,
    ) -> tuple[PocketPersistentState, PocketSyncStoreModel]:
        persistent = persistent or PocketPersistentState()
        store = PocketSyncStoreModel(persistent)
        store.start(
            pack_id=pack_id or self.pack_id,
            manifest_bytes=len(self.manifest),
            manifest_sha256=sha(self.manifest),
            total_object_bytes=len(self.article),
            object_count=1,
            chunk=chunk,
        )
        return persistent, store

    def seal_one(self, store: PocketSyncStoreModel, *, cursor: int = 7) -> None:
        send(store, MANIFEST_STREAM, self.manifest, chunk=store._session.identity.chunk)
        store.seal_manifest(
            objects=[PocketObjectSpec(len(self.article), sha(self.article))],
            from_cursor=store.persistent.cursor,
            to_cursor=cursor,
            mode="snapshot" if store.persistent.cursor == 0 else "delta",
        )

    def complete_one(self, store: PocketSyncStoreModel, *, cursor: int = 7) -> None:
        self.seal_one(store, cursor=cursor)
        send(store, 0, self.article, chunk=store._session.identity.chunk)
        self.assertEqual(store.phase, "validating")

    def test_happy_start_manifest_seal_objects_commit_receipt_and_cursor(self) -> None:
        persistent, store = self.start_one()
        persistent.sd.mkdir("/Books")
        persistent.sd.mkdir("/Meta")
        self.complete_one(store)
        store.commit(
            [
                PocketPlanOperation.install_object("/Books/pocket.txt", 0),
                PocketPlanOperation.install_prepared("/Meta/item.json", b'{"item":"pocket"}'),
            ]
        )
        self.assertEqual(store.phase, "complete")
        self.assertEqual(persistent.sd.files["/Books/pocket.txt"], self.article)
        self.assertEqual(persistent.cursor, 7)
        self.assertEqual(persistent.last_pack, "a" * 64)
        self.assertEqual(persistent.receipts, ["a" * 64])
        self.assertIsNone(persistent.active_commit)
        self.assertNotIn("a" * 64, persistent.sessions)

    def test_start_requires_query_and_pins_cloud_bounds_without_allocating_payloads(self) -> None:
        store = PocketSyncStoreModel()
        with self.assertRaisesRegex(PocketModelError, "QUERY_STATE") as caught:
            store.start(
                pack_id=self.pack_id,
                manifest_bytes=1,
                manifest_sha256="0" * 64,
                total_object_bytes=0,
                object_count=0,
                chunk=1,
                queried=False,
            )
        self.assertEqual(caught.exception.result, "protocol")

        maximum = PocketSyncStoreModel()
        maximum.start(
            pack_id=self.pack_id,
            manifest_bytes=MAX_MANIFEST_BYTES,
            manifest_sha256="0" * 64,
            total_object_bytes=MAX_PACK_BYTES,
            object_count=68,
            chunk=DEVICE_MAX_CHUNK,
        )
        self.assertEqual(maximum.phase, "manifest")
        for override in (
            {"manifest_bytes": 0},
            {"manifest_bytes": MAX_MANIFEST_BYTES + 1},
            {"total_object_bytes": MAX_PACK_BYTES + 1},
            {"object_count": 69},
            {"chunk": 0},
            {"chunk": DEVICE_MAX_CHUNK + 1},
            {"manifest_sha256": "A" * 64},
        ):
            arguments = dict(
                pack_id="ps1-" + "b" * 64,
                manifest_bytes=1,
                manifest_sha256="0" * 64,
                total_object_bytes=0,
                object_count=0,
                chunk=1,
            )
            arguments.update(override)
            with self.subTest(override=override), self.assertRaises(PocketModelError):
                PocketSyncStoreModel().start(**arguments)
        with self.assertRaises(PocketModelError):
            PocketSyncStoreModel().start(
                pack_id="ps1-" + "G" * 64,
                manifest_bytes=1,
                manifest_sha256="0" * 64,
                total_object_bytes=0,
                object_count=0,
                chunk=1,
            )

    def test_ordering_rejects_object_before_seal_premature_seal_and_commit(self) -> None:
        _persistent, store = self.start_one()
        with self.assertRaises(PocketModelError) as caught:
            store.receive(stream=0, offset=0, data=b"x", crc=crc16_ccitt_false(b"x"))
        self.assertEqual(caught.exception.result, "sequence")

        _persistent, store = self.start_one(PocketPersistentState())
        with self.assertRaises(PocketModelError) as caught:
            store.seal_manifest(objects=[], from_cursor=0, to_cursor=0, mode="snapshot")
        self.assertEqual(caught.exception.result, "incomplete")

        _persistent, store = self.start_one(PocketPersistentState())
        with self.assertRaises(PocketModelError) as caught:
            store.commit([])
        self.assertEqual(caught.exception.result, "sequence")

    def test_four_chunk_checkpoint_and_reconnect_truncate_uncheckpointed_tail(self) -> None:
        manifest = b"abcdefghijkl"
        persistent = PocketPersistentState()
        store = PocketSyncStoreModel(persistent)
        arguments = dict(
            pack_id=self.pack_id,
            manifest_bytes=len(manifest),
            manifest_sha256=sha(manifest),
            total_object_bytes=0,
            object_count=0,
            chunk=2,
        )
        store.start(**arguments)
        for offset in range(0, 10, 2):
            part = manifest[offset : offset + 2]
            store.receive(stream=MANIFEST_STREAM, offset=offset, data=part, crc=crc16_ccitt_false(part))
        self.assertEqual(store.accepted_offset, 10)
        self.assertEqual(store.durable_offset, 8)
        self.assertEqual(store.checkpoints, [(MANIFEST_STREAM, 8)])

        resumed = PocketSyncStoreModel(persistent)
        resumed.start(**arguments)
        self.assertEqual((resumed.accepted_offset, resumed.durable_offset), (8, 8))
        self.assertEqual(bytes(resumed._session.manifest.data), manifest[:8])
        send(resumed, MANIFEST_STREAM, manifest, chunk=2)
        self.assertEqual(resumed.durable_offset, len(manifest))

    def test_corrupt_or_orphaned_resume_state_resets_to_zero(self) -> None:
        cases = (
            {"offset_readable": False},
            {"durable_offset": len(self.manifest) + 1},
            {"exists": False, "durable_offset": 3},
            {"exists": True, "readable": False, "durable_offset": 1},
            {"exists": True, "durable_offset": 4, "data": bytearray(b"ab")},
        )
        for mutation in cases:
            persistent, store = self.start_one(PocketPersistentState())
            disk = store._session.manifest
            disk.data = bytearray(b"abcdefgh")
            disk.exists = True
            disk.durable_offset = 4
            for key, value in mutation.items():
                setattr(disk, key, value)
            resumed = PocketSyncStoreModel(persistent)
            with self.subTest(mutation=mutation):
                resumed.start(
                    pack_id=self.pack_id,
                    manifest_bytes=len(self.manifest),
                    manifest_sha256=sha(self.manifest),
                    total_object_bytes=len(self.article),
                    object_count=1,
                    chunk=10,
                )
                self.assertEqual(resumed.accepted_offset, 0)
                self.assertEqual(bytes(resumed._session.manifest.data), b"")

    def test_failed_tail_truncation_discards_uncommitted_stream_for_retry(self) -> None:
        persistent, store = self.start_one()
        disk = store._session.manifest
        disk.exists = True
        disk.data = bytearray(b"abcdef")
        disk.durable_offset = 4
        disk.truncate_allowed = False
        resumed = PocketSyncStoreModel(persistent)
        resumed.start(
            pack_id=self.pack_id,
            manifest_bytes=len(self.manifest),
            manifest_sha256=sha(self.manifest),
            total_object_bytes=len(self.article),
            object_count=1,
            chunk=10,
        )
        self.assertEqual(resumed.accepted_offset, 0)
        self.assertFalse(resumed._session.manifest.exists)

    def test_crc_oversize_stream_and_offset_fail_closed_without_commit(self) -> None:
        def fresh() -> PocketSyncStoreModel:
            return self.start_one(PocketPersistentState(), chunk=10)[1]

        cases = (
            lambda store: store.receive(stream=MANIFEST_STREAM, offset=0, data=b"x", crc=0),
            lambda store: store.receive(
                stream=MANIFEST_STREAM, offset=0, data=b"x" * 11, crc=crc16_ccitt_false(b"x" * 11)
            ),
            lambda store: store.receive(stream=0, offset=0, data=b"x", crc=crc16_ccitt_false(b"x")),
            lambda store: store.receive(stream=MANIFEST_STREAM, offset=1, data=b"x", crc=crc16_ccitt_false(b"x")),
        )
        for operation in cases:
            store = fresh()
            with self.subTest(operation=operation), self.assertRaises(PocketModelError):
                operation(store)
            self.assertEqual(store.phase, "error")
            self.assertEqual(store.persistent.receipts, [])

    def test_manifest_and_object_hashes_and_semantics_gate_seal_and_commit(self) -> None:
        persistent, store = self.start_one()
        send(store, MANIFEST_STREAM, self.manifest, chunk=10)
        with self.assertRaises(PocketModelError) as caught:
            store.seal_manifest(
                objects=[PocketObjectSpec(len(self.article), sha(self.article), references=0)],
                from_cursor=0,
                to_cursor=1,
                mode="snapshot",
            )
        self.assertEqual(caught.exception.result, "manifest")

        persistent, store = self.start_one(PocketPersistentState())
        send(store, MANIFEST_STREAM, self.manifest, chunk=10)
        with self.assertRaises(PocketModelError):
            store.seal_manifest(
                objects=[PocketObjectSpec(MAX_OBJECT_BYTES + 1, "0" * 64)],
                from_cursor=0,
                to_cursor=1,
                mode="snapshot",
            )

        persistent, store = self.start_one(PocketPersistentState())
        self.seal_one(store)
        wrong = b"x" * len(self.article)
        with self.assertRaises(PocketModelError) as caught:
            send(store, 0, wrong, chunk=10)
        self.assertEqual(caught.exception.result, "hash")
        self.assertEqual(persistent.receipts, [])

        resumed = PocketSyncStoreModel(persistent)
        resumed.start(
            pack_id=self.pack_id,
            manifest_bytes=len(self.manifest),
            manifest_sha256=sha(self.manifest),
            total_object_bytes=len(self.article),
            object_count=1,
            chunk=10,
        )
        self.assertEqual(resumed.current_stream, 0)
        self.assertEqual(resumed.accepted_offset, 0)

    def test_session_identity_mismatch_removes_orphaned_staging_bytes(self) -> None:
        persistent, store = self.start_one(chunk=2)
        for offset in range(0, 8, 2):
            part = self.manifest[offset : offset + 2]
            store.receive(stream=MANIFEST_STREAM, offset=offset, data=part, crc=crc16_ccitt_false(part))
        self.assertEqual(store.durable_offset, 8)
        replacement = b"replacement-manifest"
        restarted = PocketSyncStoreModel(persistent)
        restarted.start(
            pack_id=self.pack_id,
            manifest_bytes=len(replacement),
            manifest_sha256=sha(replacement),
            total_object_bytes=0,
            object_count=0,
            chunk=2,
        )
        self.assertEqual(restarted.accepted_offset, 0)
        self.assertEqual(bytes(restarted._session.manifest.data), b"")

    def test_fresh_session_tree_retries_once_after_cleaning_partial_state(self) -> None:
        persistent = PocketPersistentState(fresh_session_tree_failures_remaining=1)
        _, store = self.start_one(persistent)
        self.assertEqual(persistent.fresh_session_tree_failures_remaining, 0)
        self.assertEqual(store.phase, "manifest")
        self.assertTrue(store.active)
        self.assertEqual(list(persistent.sessions), ["a" * 64])

        persistent = PocketPersistentState(fresh_session_tree_failures_remaining=2)
        with self.assertRaises(PocketModelError) as caught:
            self.start_one(persistent)
        self.assertEqual(caught.exception.result, "storage")
        self.assertEqual(persistent.sessions, {})

    def test_in_session_transition_resets_stale_partial_next_object(self) -> None:
        second = b"second object"
        persistent = PocketPersistentState()
        store = PocketSyncStoreModel(persistent)
        store.start(
            pack_id=self.pack_id,
            manifest_bytes=len(self.manifest),
            manifest_sha256=sha(self.manifest),
            total_object_bytes=len(self.article) + len(second),
            object_count=2,
            chunk=10,
        )
        send(store, MANIFEST_STREAM, self.manifest, chunk=10)
        store.seal_manifest(
            objects=[PocketObjectSpec(len(self.article), sha(self.article)), PocketObjectSpec(len(second), sha(second))],
            from_cursor=0,
            to_cursor=9,
            mode="snapshot",
        )
        stale = store._session.objects[1]
        stale.exists = True
        stale.data = bytearray(second[:4])
        stale.durable_offset = 4
        send(store, 0, self.article, chunk=10)
        self.assertEqual(store.current_stream, 1)
        self.assertEqual(store.accepted_offset, 0)
        self.assertEqual(bytes(stale.data), b"")

    def test_commit_failure_and_receipt_failure_roll_back_every_published_target(self) -> None:
        for failure in ("operation", "receipt"):
            persistent, store = self.start_one(PocketPersistentState())
            persistent.sd.mkdir("/Books")
            persistent.sd.mkdir("/Meta")
            persistent.sd.write("/Books/pocket.txt", b"old-book")
            persistent.sd.write("/Meta/item.json", b"old-meta")
            self.complete_one(store)
            operations = [
                PocketPlanOperation.install_object("/Books/pocket.txt", 0),
                PocketPlanOperation.install_prepared("/Meta/item.json", b"new-meta"),
            ]
            if failure == "receipt":
                persistent.receipt_writable = False
            with self.subTest(failure=failure), self.assertRaises(PocketModelError):
                store.commit(operations, fail_at=1 if failure == "operation" else None)
            self.assertEqual(persistent.sd.files["/Books/pocket.txt"], b"old-book")
            self.assertEqual(persistent.sd.files["/Meta/item.json"], b"old-meta")
            self.assertEqual(persistent.cursor, 0)
            self.assertEqual(persistent.receipts, [])
            self.assertIsNone(persistent.active_commit)

    def test_power_loss_resumes_only_uncheckpointed_commit_operations(self) -> None:
        persistent, store = self.start_one()
        persistent.sd.mkdir("/Books")
        persistent.sd.mkdir("/Meta")
        persistent.sd.write("/Books/pocket.txt", b"old-book")
        persistent.sd.write("/Meta/item.json", b"old-meta")
        self.complete_one(store, cursor=23)
        operations = [
            PocketPlanOperation.install_object("/Books/pocket.txt", 0),
            PocketPlanOperation.install_prepared("/Meta/item.json", b"new-meta"),
        ]
        with self.assertRaises(SimulatedPowerLoss):
            store.commit(operations, interrupt_after=0)
        self.assertEqual(persistent.active_commit.next_operation, 1)
        self.assertEqual(persistent.sd.files["/Books/pocket.txt"], self.article)
        self.assertEqual(persistent.sd.files["/Meta/item.json"], b"old-meta")
        self.assertEqual(persistent.receipts, [])

        rebooted = PocketSyncStoreModel(persistent)
        cursor, last_pack = rebooted.query_state()
        self.assertEqual((cursor, last_pack), (23, "a" * 64))
        self.assertEqual(persistent.sd.files["/Meta/item.json"], b"new-meta")
        self.assertIsNone(persistent.active_commit)

    def test_corrupt_commit_journal_is_retained_and_fails_closed(self) -> None:
        persistent, store = self.start_one()
        persistent.sd.mkdir("/Books")
        self.complete_one(store)
        with self.assertRaises(SimulatedPowerLoss):
            store.commit([PocketPlanOperation.install_object("/Books/pocket.txt", 0)], interrupt_after=0)
        persistent.active_commit.corrupt = True
        rebooted = PocketSyncStoreModel(persistent)
        with self.assertRaises(PocketModelError) as caught:
            rebooted.query_state()
        self.assertEqual(caught.exception.result, "storage")
        self.assertIsNotNone(persistent.active_commit)

    def test_completed_pack_replay_is_idempotent_and_receipts_are_bounded(self) -> None:
        persistent = PocketPersistentState()
        first_store: PocketSyncStoreModel | None = None
        for index in range(MAX_RECEIPTS + 1):
            manifest = f"manifest-{index}".encode()
            pack_id = "ps1-" + f"{index + 1:064x}"
            store = PocketSyncStoreModel(persistent)
            store.start(
                pack_id=pack_id,
                manifest_bytes=len(manifest),
                manifest_sha256=sha(manifest),
                total_object_bytes=0,
                object_count=0,
                chunk=20,
            )
            send(store, MANIFEST_STREAM, manifest, chunk=20)
            store.seal_manifest(
                objects=[],
                from_cursor=persistent.cursor,
                to_cursor=index + 1,
                mode="snapshot" if index == 0 else "delta",
            )
            store.commit([])
            if index == 0:
                first_store = store
        self.assertIsNotNone(first_store)
        self.assertEqual(len(persistent.receipts), MAX_RECEIPTS)
        self.assertNotIn(f"{1:064x}", persistent.receipts)
        self.assertEqual(persistent.last_pack, f"{MAX_RECEIPTS + 1:064x}")
        self.assertEqual(persistent.cursor, MAX_RECEIPTS + 1)

        replay_pack = "ps1-" + f"{MAX_RECEIPTS + 1:064x}"
        replay_manifest = f"manifest-{MAX_RECEIPTS}".encode()
        before = dict(persistent.sd.files)
        replay = PocketSyncStoreModel(persistent)
        replay.start(
            pack_id=replay_pack,
            manifest_bytes=len(replay_manifest),
            manifest_sha256=sha(replay_manifest),
            total_object_bytes=0,
            object_count=0,
            chunk=20,
        )
        self.assertEqual(replay.phase, "complete")
        self.assertFalse(replay.active)
        self.assertEqual(persistent.sd.files, before)

    def test_abort_discards_uncommitted_pack_without_advancing_receipt_or_cursor(self) -> None:
        persistent, store = self.start_one()
        send(store, MANIFEST_STREAM, self.manifest[:10], chunk=10)
        self.assertIn("a" * 64, persistent.sessions)
        store.abort()
        self.assertEqual(store.phase, "idle")
        self.assertNotIn("a" * 64, persistent.sessions)
        self.assertEqual((persistent.cursor, persistent.receipts), (0, []))

    def test_atomic_sidecar_recovery_covers_final_backup_temporary_and_failure(self) -> None:
        final = "/state.json"
        sd = VirtualSd(files={final: b"final", final + ".pstmp": b"new", final + ".psbak": b"old"})
        self.assertTrue(recover_atomic_sidecars(sd, final))
        self.assertEqual(sd.files, {final: b"final"})

        sd = VirtualSd(files={final + ".pstmp": b"new", final + ".psbak": b"old"})
        self.assertTrue(recover_atomic_sidecars(sd, final))
        self.assertEqual(sd.files, {final: b"old"})

        sd = VirtualSd(files={final + ".pstmp": b"uncommitted"})
        self.assertTrue(recover_atomic_sidecars(sd, final))
        self.assertEqual(sd.files, {})

        sd = VirtualSd(files={final: b"final", final + ".pstmp": b"new"})
        sd.fail_deletes.add(final + ".pstmp")
        self.assertFalse(recover_atomic_sidecars(sd, final))
        self.assertEqual(sd.files[final], b"final")


if __name__ == "__main__":
    unittest.main()
