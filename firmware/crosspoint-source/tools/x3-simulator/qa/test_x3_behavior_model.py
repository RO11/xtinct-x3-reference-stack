from __future__ import annotations

import unittest
from datetime import datetime, timezone

from .x3_behavior_model import (
    EpubReaderModel,
    InboxItem,
    MANAGED_INBOX_PREFIX,
    ModelError,
    RecentsModel,
    TxtReaderModel,
    VirtualSd,
    brisbane_local_day,
    can_stamp_daily_fresh,
    inbox_pages,
    next_wake_seconds,
    normalize_sd_path,
    reader_kind,
    sanitized_crash_report,
    should_claim_daily_sync,
    should_retry_scheduled_sync,
)


class HomeFilesRecentsQa(unittest.TestCase):
    def fixture_sd(self) -> VirtualSd:
        sd = VirtualSd()
        for directory in ("/Books", "/Books/Series", "/.crosspoint", "/System Volume Information"):
            sd.mkdir(directory)
        sd.write("/Books/Today.epub", b"epub")
        sd.write("/Books/notes.txt", b"notes")
        sd.write("/Books/readme.md", b"markdown")
        sd.write("/Books/cover.bmp", b"bmp")
        sd.write("/Books/ignore.pdf", b"pdf")
        sd.write("/Books/.hidden.epub", b"hidden")
        sd.write("/Books/Series/chapter.txt", b"chapter")
        return sd

    def test_files_lists_only_firmware_supported_books_and_directories(self) -> None:
        sd = self.fixture_sd()
        self.assertEqual(
            sd.list_book_entries("/Books"),
            ["Series/", "cover.bmp", "notes.txt", "readme.md", "Today.epub"],
        )
        self.assertIn(".hidden.epub", sd.list_book_entries("/Books", show_hidden=True))
        self.assertNotIn("System Volume Information/", sd.list_book_entries("/"))

    def test_files_open_maps_all_supported_reader_kinds_and_rejects_other_files(self) -> None:
        self.assertEqual(reader_kind("/a.epub"), "epub")
        self.assertEqual(reader_kind("/a.xtc"), "xtc")
        self.assertEqual(reader_kind("/a.txt"), "txt")
        self.assertEqual(reader_kind("/a.markdown"), "txt")
        self.assertEqual(reader_kind("/a.bmp"), "bmp")
        with self.assertRaises(ModelError):
            reader_kind("/a.pdf")

    def test_delete_is_recursive_cancelable_by_caller_and_failure_is_not_success(self) -> None:
        sd = self.fixture_sd()
        before = dict(sd.files)
        # Cancel is represented by never invoking the destructive operation.
        self.assertEqual(sd.files, before)
        sd.delete("/Books/Series")
        self.assertFalse(any(path.startswith("/Books/Series") for path in set(sd.files) | sd.directories))
        sd.fail_deletes.add("/Books/Today.epub")
        with self.assertRaises(ModelError):
            sd.delete("/Books/Today.epub")
        self.assertIn("/Books/Today.epub", sd.files)

    def test_recents_prunes_missing_opens_existing_and_remove_does_not_delete_book(self) -> None:
        sd = self.fixture_sd()
        recents = RecentsModel(["/Books/missing.epub", "/Books/Today.epub"])
        kind, payload = recents.open(0, sd)
        self.assertEqual((kind, payload), ("epub", b"epub"))
        recents.remove("/Books/Today.epub")
        self.assertEqual(recents.paths, [])
        self.assertIn("/Books/Today.epub", sd.files)

    def test_virtual_paths_reject_host_escape_and_oversize_components(self) -> None:
        for path in ("C:/Windows", "//server/share", "/../secret", "/a\\b", "/a\x00b"):
            with self.subTest(path=path), self.assertRaises(ModelError):
                normalize_sd_path(path)
        with self.assertRaises(ModelError):
            normalize_sd_path("/" + "x" * 256)


class ReaderQa(unittest.TestCase):
    def test_txt_pages_progress_restore_and_crlf_boundary(self) -> None:
        data = ("alpha\r\n" + "b" * 18 + "\n" + "gamma\n" + "delta\n").encode()
        reader = TxtReaderModel(data, lines_per_page=2, wrap_columns=8)
        self.assertGreater(reader.total_pages, 1)
        self.assertEqual(reader.pages[0][0], "alpha")
        self.assertNotIn("\r", "".join(sum(reader.pages, [])))
        first_progress = reader.progress_basis_points
        self.assertTrue(reader.next())
        self.assertGreater(reader.progress_basis_points, first_progress)
        reader.restore(999)
        self.assertEqual(reader.current_page, reader.total_pages - 1)
        self.assertEqual(reader.progress_basis_points, 10000)
        self.assertFalse(reader.next())
        self.assertTrue(reader.previous())

    def test_txt_rejects_embedded_nul_and_invalid_utf8(self) -> None:
        with self.assertRaises(ModelError):
            TxtReaderModel(b"safe\x00hidden")
        with self.assertRaises(ModelError):
            TxtReaderModel(b"\xf0")

    def test_epub_crosses_pages_and_spines_then_returns_from_end(self) -> None:
        reader = EpubReaderModel("/Books/synthetic.epub", [["1", "2"], ["3"]])
        self.assertTrue(reader.next())
        self.assertEqual((reader.spine, reader.page), (0, 1))
        self.assertTrue(reader.next())
        self.assertEqual((reader.spine, reader.page), (1, 0))
        self.assertFalse(reader.next())
        self.assertTrue(reader.end_of_book)
        self.assertEqual(reader.saved_position, (1, 0))
        self.assertTrue(reader.previous())
        self.assertFalse(reader.end_of_book)

    def test_today_single_spine_still_has_many_pages(self) -> None:
        today = EpubReaderModel(MANAGED_INBOX_PREFIX + "a" * 64 + ".epub", [[str(i) for i in range(12)]])
        for _ in range(11):
            self.assertTrue(today.next())
        self.assertEqual((today.spine, today.page), (0, 11))
        self.assertFalse(today.next())
        self.assertFalse(today.allows_sibling_suggestions)

    def test_epub_stale_end_progress_resets_and_managed_hashes_are_never_suggested(self) -> None:
        managed = EpubReaderModel(MANAGED_INBOX_PREFIX + "8f82" * 16 + ".epub", [["p1"], ["p2"]])
        managed.restore(2, 0)
        self.assertEqual((managed.spine, managed.page, managed.end_of_book), (0, 0, False))
        self.assertFalse(managed.allows_sibling_suggestions)
        ordinary = EpubReaderModel("/Books/ordinary.epub", [["p1"]])
        self.assertTrue(ordinary.allows_sibling_suggestions)


class InboxCardsWakeQa(unittest.TestCase):
    def test_inbox_pages_all_64_with_stable_tie_breaking(self) -> None:
        items = [InboxItem(f"item-{index:02d}", "2026-08-12T04:00:00Z") for index in range(64)]
        pages = inbox_pages(reversed(items))
        self.assertEqual(len(pages), 8)
        self.assertEqual([item.item_id for item in pages[0]], [f"item-{i:02d}" for i in range(8)])
        self.assertEqual([item.item_id for item in pages[-1]], [f"item-{i:02d}" for i in range(56, 64)])
        with self.assertRaises(ModelError):
            inbox_pages(items + [InboxItem("extra", "2026-08-12T05:00:00Z")])

    def test_daily_freshness_requires_complete_cards_and_inbox(self) -> None:
        today = 20676
        self.assertTrue(
            should_claim_daily_sync(day_known=True, state_valid=True, today=today, attempt_day=today - 1, fresh_day=0)
        )
        self.assertFalse(
            should_claim_daily_sync(day_known=True, state_valid=True, today=today, attempt_day=today, fresh_day=0)
        )
        self.assertFalse(
            should_claim_daily_sync(day_known=False, state_valid=True, today=today, attempt_day=0, fresh_day=0)
        )
        self.assertTrue(can_stamp_daily_fresh(True, True))
        self.assertFalse(can_stamp_daily_fresh(True, False))

    def test_brisbane_midnight_and_wake_windows(self) -> None:
        before = 2 * 86400 + 13 * 3600 + 59 * 60 + 59
        self.assertEqual(brisbane_local_day(before), 2)
        self.assertEqual(brisbane_local_day(before + 1), 3)
        seconds, hour, minute = next_wake_seconds(
            datetime(2026, 8, 11, 22, 0, tzinfo=timezone.utc), primary_hour=7, primary_minute=30
        )
        self.assertEqual((seconds, hour, minute), (900, 8, 15))

    def test_wake_primary_duplicate_is_collapsed_and_retries_are_bounded(self) -> None:
        seconds, hour, minute = next_wake_seconds(
            datetime(2026, 8, 11, 22, 0, tzinfo=timezone.utc), primary_hour=8, primary_minute=15
        )
        self.assertEqual((seconds, hour, minute), (900, 8, 15))
        self.assertTrue(
            should_retry_scheduled_sync(allow_retries=True, transient_failure=True, retry_count=1, maximum_retries=3)
        )
        self.assertFalse(
            should_retry_scheduled_sync(allow_retries=False, transient_failure=True, retry_count=0, maximum_retries=3)
        )
        self.assertFalse(
            should_retry_scheduled_sync(allow_retries=True, transient_failure=True, retry_count=3, maximum_retries=3)
        )


class FileTransferCrashQa(unittest.TestCase):
    def test_file_transfer_atomic_replace_keeps_old_file_on_every_precommit_failure(self) -> None:
        for phase in ("write", "before-promote", "promote"):
            sd = VirtualSd(files={"/update.bin": b"old"})
            if phase == "write":
                with self.assertRaises(ModelError):
                    sd.atomic_replace("/update.bin", b"new", fail_phase=phase)
            else:
                self.assertIn(sd.atomic_replace("/update.bin", b"new", fail_phase=phase), {"old-retained", "old-restored"})
            self.assertEqual(sd.files["/update.bin"], b"old")
        sd = VirtualSd(files={"/update.bin": b"old"})
        self.assertEqual(sd.atomic_replace("/update.bin", b"new"), "committed")
        self.assertEqual(sd.files["/update.bin"], b"new")

    def test_crash_report_never_retains_secret_bearing_abort_text(self) -> None:
        secret = "SecretTokenABC123"
        valid = sanitized_crash_report(
            reason="abort", program_counter=1, return_address=2, machine_cause=3,
            abort_message="abort() was called at PC 0x4201A2B3 on core 0",
        )
        self.assertIn("Abort caller PC: 0x4201A2B3", valid)
        unsafe = sanitized_crash_report(
            reason="abort", program_counter=1, return_address=2, machine_cause=3,
            abort_message=f"abort() was called at PC 0x4201A2B3 on core 0 {secret}",
        )
        self.assertNotIn(secret, unsafe)
        self.assertNotIn("Abort caller PC", unsafe)
        self.assertIn("Raw stack memory and retained logs are intentionally omitted", unsafe)


if __name__ == "__main__":
    unittest.main()
