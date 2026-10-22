"""Exercise corpus identity and archive handling with harmless, in-memory data."""

import copy
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("corpus_validator", ROOT / "tests/validate_corpus.py")
corpus = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(corpus)


class CorpusTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="corpus-inert-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.name = "Python-3.12.3/Lib/example.py"
        self.empty = "Python-3.12.3/Lib/empty.py"
        self.data = b"# Harmless source text; never executed.\n"
        self.entries = [(self.name, self.data), (self.empty, b"")]
        self.manifest = {
            "schema_version": 1, "selection": copy.deepcopy(corpus.SELECTION),
            "totals": {"files": 2, "bytes": len(self.data), "empty_files": 1},
            "files": [{"path": name, "size_bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                      for name, data in self.entries],
        }
        self.raw = self.pack(self.entries)
        self.pin(self.raw)

    @staticmethod
    def pack(entries):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:xz") as archive:
            for entry in entries:
                name, data = entry[:2]
                member = tarfile.TarInfo(name)
                member.type = entry[2] if len(entry) == 3 else tarfile.REGTYPE
                if member.isfile():
                    member.size = len(data)
                elif member.issym() or member.islnk():
                    member.linkname = "../../outside"
                archive.addfile(member, io.BytesIO(data))
        return buffer.getvalue()

    def pin(self, raw):
        self.manifest["archive"] = {"size_bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}

    def test_public_manifest_totals_and_identity(self):
        manifest, digest = corpus.load_manifest()
        self.assertEqual(manifest["totals"], {"files": 690, "bytes": 11665088, "empty_files": 5})
        self.assertEqual(manifest["release_date"], "2024-04-09")
        self.assertEqual(manifest["archive"]["size_bytes"], 20625068)
        self.assertEqual(manifest["archive"]["sha256"],
                         "56bfef1fdfc1221ce6720e43a661e3eb41785dd914ce99698d8c7896af4bdaa1")
        self.assertEqual(digest, hashlib.sha256(corpus.MANIFEST.read_bytes()).hexdigest())
        self.assertEqual([item["path"] for item in manifest["files"]],
                         sorted(item["path"] for item in manifest["files"]))

    def test_manifest_rejects_invalid_paths_sizes_hashes_and_totals(self):
        mutations = [
            lambda m: m["files"].append(m["files"][0]),
            lambda m: m["files"][0].update(path="../outside.py"),
            lambda m: m["files"][0].update(size_bytes=True),
            lambda m: m["files"][0].update(size_bytes=corpus.MAX_FILE_BYTES),
            lambda m: m["files"][0].update(sha256="unknown"),
            lambda m: m["totals"].update(files=3),
            lambda m: m["archive"].update(size_bytes=corpus.MAX_ARCHIVE_BYTES + 1),
            lambda m: m["selection"].update(prefix="different/"),
        ]
        path = self.root / "manifest.json"
        for number, mutate in enumerate(mutations):
            with self.subTest(mutation=number):
                manifest = copy.deepcopy(self.manifest)
                mutate(manifest)
                path.write_text(json.dumps(manifest))
                with self.assertRaises(ValueError):
                    corpus.load_manifest(path)

    def test_hash_is_checked_before_archive_parsing(self):
        for data in (self.raw + b"x", bytes([self.raw[0] ^ 1]) + self.raw[1:]):
            with self.subTest(size=len(data)), mock.patch.object(corpus.tarfile, "open") as open_tar:
                with self.assertRaisesRegex(ValueError, "pinned manifest"):
                    list(corpus.verified_members(data, self.manifest))
                open_tar.assert_not_called()

    def test_only_selected_regular_files_are_returned(self):
        raw = self.pack([*self.entries, ("Python-3.12.3/Lib/test/example.py", b"excluded"),
                         ("Python-3.12.3/Lib/idlelib/idle_test/example.py", b"excluded"),
                         ("Python-3.12.3/README.rst", b"excluded")])
        self.pin(raw)
        self.assertEqual(list(corpus.verified_members(raw, self.manifest)), self.entries)

    def test_missing_and_unlisted_selected_members_are_errors(self):
        for entries in (self.entries[:1], [*self.entries, ("Python-3.12.3/Lib/extra.py", b"extra")]):
            with self.subTest(entries=len(entries)):
                raw = self.pack(entries)
                self.pin(raw)
                with self.assertRaises(ValueError):
                    list(corpus.verified_members(raw, self.manifest))

    def test_unsafe_duplicate_link_and_special_members_are_errors(self):
        additions = [
            ("/absolute.py", b""), ("../outside.py", b""),
            ("Python-3.12.3/Lib/../outside.py", b""), ("Python-3.12.3/Lib/back\\slash.py", b""),
            (self.name, self.data),
            ("Python-3.12.3/link", b"", tarfile.SYMTYPE),
            ("Python-3.12.3/link", b"", tarfile.LNKTYPE),
            ("Python-3.12.3/fifo", b"", tarfile.FIFOTYPE),
        ]
        for extra in additions:
            with self.subTest(member=extra[0], kind=extra[2:]):
                raw = self.pack([*self.entries, extra])
                self.pin(raw)
                with self.assertRaises(ValueError):
                    list(corpus.verified_members(raw, self.manifest))

    def test_member_sizes_and_content_are_verified(self):
        for data in (b"x" * len(self.data), b"changed size"):
            with self.subTest(size=len(data)):
                raw = self.pack([(self.name, data), self.entries[1]])
                self.pin(raw)
                with self.assertRaises(ValueError):
                    list(corpus.verified_members(raw, self.manifest))

    def test_member_and_byte_budgets_fail_closed(self):
        for name in ("MAX_MEMBERS", "MAX_MEMBER_BYTES", "MAX_FILE_BYTES"):
            with self.subTest(limit=name), mock.patch.object(corpus, name, 1):
                with self.assertRaises(ValueError):
                    list(corpus.verified_members(self.raw, self.manifest))

    def test_bounded_reader_refuses_oversized_and_nonregular_files(self):
        path = self.root / "archive.xz"
        path.write_bytes(self.raw)
        with self.assertRaises(ValueError):
            corpus.bounded_regular_bytes(path, 1)
        with self.assertRaises(ValueError):
            corpus.bounded_regular_bytes(self.root, 1)
        if hasattr(os, "mkfifo"):
            fifo = self.root / "fifo"
            os.mkfifo(fifo)
            with self.assertRaises(ValueError):
                corpus.bounded_regular_bytes(fifo, 1)

    def test_empty_files_are_verified_but_not_scanned_and_scratch_is_removed(self):
        paths = []

        def scan(engine, executable, rules, path, scratch):
            self.assertEqual(path.read_bytes(), self.data)
            self.assertEqual(rules.read_bytes(), b"inert rule fixture")
            self.assertEqual(path.suffix, ".txt")
            self.assertTrue(path.stem.isdecimal())
            self.assertEqual(scratch.stat().st_mode & 0o777, 0o700)
            paths.append(path)
            return set()

        with mock.patch.object(corpus.validator, "scan_case", side_effect=scan):
            result = corpus.scan_corpus(self.raw, self.manifest, "yara", "unused", b"inert rule fixture")
        self.assertEqual((result["verified_files"], result["empty_files"], result["scanned_files"]), (2, 1, 1))
        self.assertTrue(result["complete_within_scope"])
        self.assertTrue(result["validation_passed"])
        self.assertEqual(result["exit_code"], 0)
        self.assertTrue(all(not path.parent.exists() for path in paths))

    def test_match_is_a_failed_reference_validation_not_an_incomplete_scan(self):
        with mock.patch.object(corpus.validator, "scan_case", return_value={corpus.validator.ENCODED}):
            result = corpus.scan_corpus(self.raw, self.manifest, "yara", "unused", b"inert")
        self.assertTrue(result["complete_within_scope"])
        self.assertFalse(result["validation_passed"])
        self.assertEqual(result["exit_code"], 1)
        self.assertEqual(result["matches"][0]["path"], self.name)

    def test_cli_success_and_match_output_preserve_exit_codes(self):
        archive = self.root / "archive.xz"
        archive.write_bytes(self.raw)
        argv = ["validate_corpus", "--archive", str(archive), "--engine", "yara"]
        version = subprocess.CompletedProcess([], 0, "inert scanner version\n", "")
        for code in (0, 1):
            result = {"exit_code": code, "complete_within_scope": True, "validation_passed": code == 0}
            with self.subTest(exit_code=code), mock.patch.object(sys, "argv", argv):
                with (mock.patch.object(corpus, "load_manifest", return_value=(self.manifest, "fixture")),
                      mock.patch.object(corpus.shutil, "which", return_value="unused"),
                      mock.patch.object(corpus.subprocess, "run", return_value=version),
                      mock.patch.object(corpus, "scan_corpus", return_value=result),
                      mock.patch.object(sys, "stdout", new_callable=io.StringIO) as output):
                    self.assertEqual(corpus.main(), code)
                    report = json.loads(output.getvalue())
            self.assertEqual(report["exit_code"], code)
            self.assertTrue(report["complete_within_scope"])
            self.assertEqual(report["validation_passed"], code == 0)

    def test_cli_output_write_and_flush_failures_exit_incomplete(self):
        program = textwrap.dedent("""\
            import errno
            import runpy
            import sys

            path, stream, phase, missing = sys.argv[1:]
            class OutputFailure:
                def write(self, text):
                    if phase == "write":
                        raise OSError(errno.ENOSPC, "inert write failure")
                    return len(text)
                def flush(self):
                    raise OSError(errno.ENOSPC, "inert flush failure")

            setattr(sys, stream, OutputFailure())
            sys.argv = [path, "--engine", "yara", "--archive", missing]
            runpy.run_path(path, run_name="__main__")
        """)
        for stream in ("stdout", "stderr"):
            for phase in ("write", "flush"):
                with self.subTest(stream=stream, phase=phase):
                    proc = subprocess.run(
                        [sys.executable, "-I", "-S", "-B", "-c", program,
                         str(ROOT / "tests/validate_corpus.py"), stream, phase, str(self.root / "missing.xz")],
                        capture_output=True, timeout=15, check=False,
                    )
                    self.assertEqual(proc.returncode, 2, proc.stderr)
                    self.assertNotIn(b"Traceback", proc.stderr)

    def test_cli_scanner_errors_and_warnings_are_incomplete(self):
        archive = self.root / "archive.xz"
        archive.write_bytes(self.raw)
        argv = ["validate_corpus", "--archive", str(archive), "--engine", "yara"]
        version = subprocess.CompletedProcess([], 0, "inert scanner version\n", "")
        for error in (RuntimeError, subprocess.TimeoutExpired, MemoryError):
            failure = error("scanner", 60) if error is subprocess.TimeoutExpired else error("inert failure")
            with self.subTest(error=error.__name__), mock.patch.object(sys, "argv", argv):
                with (mock.patch.object(corpus, "load_manifest", return_value=(self.manifest, "fixture")),
                      mock.patch.object(corpus.shutil, "which", return_value="unused"),
                      mock.patch.object(corpus.subprocess, "run", return_value=version),
                      mock.patch.object(corpus.validator, "scan_case", side_effect=failure),
                      mock.patch.object(sys, "stdout", new_callable=io.StringIO) as output,
                      mock.patch.object(sys, "stderr")):
                    self.assertEqual(corpus.main(), 2)
                    report = json.loads(output.getvalue())
            self.assertFalse(report["complete_within_scope"])
            self.assertFalse(report["validation_passed"])
            self.assertEqual(report["error_type"], error.__name__)
            self.assertNotIn(str(self.root), json.dumps(report))


if __name__ == "__main__":
    unittest.main()
