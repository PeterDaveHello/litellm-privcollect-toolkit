"""Exercise rule snapshot consistency using inert data and mocked scanners."""

import hashlib
import importlib.util
import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("rule_validator", ROOT / "tests/validate.py")
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


class RuleValidatorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="rule-validator-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "rules" / "litellm_11070.yar"
        self.source.parent.mkdir()
        self.rules_data = b"rule inert_fixture { condition: false }\n"
        self.source.write_bytes(self.rules_data)
        self.scratch_paths = []
        temporary_directory = tempfile.TemporaryDirectory

        def scratch_directory(**kwargs):
            directory = temporary_directory(**kwargs)
            self.scratch_paths.append(Path(directory.name))
            return directory

        self.enterContext(mock.patch.object(validator, "__file__", str(self.root / "tests" / "validate.py")))
        self.enterContext(mock.patch.object(validator.tempfile, "TemporaryDirectory", side_effect=scratch_directory))
        self.enterContext(mock.patch.object(validator.shutil, "which", side_effect=lambda name: "/inert/" + name))
        self.enterContext(mock.patch.object(validator, "synthetic_cases", return_value=[
            ("first", b"inert first case", set()), ("second", b"inert second case", set()),
        ]))
        self.output = self.enterContext(mock.patch.object(sys, "stdout", new_callable=io.StringIO))
        self.run = self.enterContext(mock.patch.object(
            validator.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "inert version\n", "")
        ))

    def tearDown(self):
        for path in self.scratch_paths:
            self.assertFalse(path.exists(), f"Scratch directory was not removed: {path}")

    def run_main(self, engine):
        self.output.seek(0)
        self.output.truncate()
        with mock.patch.object(sys, "argv", ["validate", "--engine", engine]):
            with self.assertRaises(SystemExit) as result:
                validator.main()
        return result.exception.code

    def test_two_cases_use_same_snapshot_after_source_change_or_removal(self):
        read_bytes = Path.read_bytes
        for engine in ("yara", "clamav"):
            for mutation in ("change", "remove"):
                with self.subTest(engine=engine, mutation=mutation):
                    self.source.write_bytes(self.rules_data)
                    snapshots = []
                    reads = []

                    def read(path, reads=reads):
                        reads.append(path)
                        return read_bytes(path)

                    def scan(command, engine=engine, mutation=mutation, snapshots=snapshots, **kwargs):
                        if command[-1] == "--version":
                            return subprocess.CompletedProcess(command, 0, "inert version\n", "")
                        rules = Path(command[1] if engine == "yara" else command[command.index("-d") + 1])
                        self.assertNotEqual(rules, self.source)
                        self.assertEqual(rules.read_bytes(), self.rules_data)
                        self.assertEqual(rules.suffix, ".yar")
                        self.assertEqual(rules.parent.stat().st_mode & 0o777, 0o700)
                        self.assertEqual(Path(command[-1]).parent, rules.parent)
                        snapshots.append(rules)
                        if len(snapshots) == 1:
                            if mutation == "change":
                                self.source.write_bytes(b"changed checkout rules")
                            else:
                                self.source.unlink()
                        return subprocess.CompletedProcess(command, 0, "", "")

                    self.run.side_effect = scan
                    with mock.patch.object(Path, "read_bytes", autospec=True, side_effect=read):
                        self.assertEqual(self.run_main(engine), 0)
                    self.assertEqual(reads.count(self.source), 1)
                    self.assertEqual(len(snapshots), 2)
                    self.assertEqual(snapshots[0], snapshots[1])
                    self.assertFalse(snapshots[0].exists())
                    self.assertFalse(snapshots[0].parent.exists())
                    self.assertIn(f"Rules snapshot SHA256: {hashlib.sha256(self.rules_data).hexdigest()}",
                                  self.output.getvalue())
                    self.assertIn(f"2/2 cases passed ({engine})", self.output.getvalue())

    def test_source_read_errors_cannot_pass(self):
        for error in (FileNotFoundError("missing rules"), PermissionError("unreadable rules")):
            with self.subTest(error=type(error).__name__):
                with mock.patch.object(Path, "read_bytes", side_effect=error):
                    with self.assertRaises(type(error)):
                        self.run_main("yara")
        self.assertTrue(self.scratch_paths)
        self.assertTrue(all(call.args[0][-1] == "--version" for call in self.run.call_args_list))
        self.assertNotIn("PASS ", self.output.getvalue())
        self.assertNotIn("cases passed", self.output.getvalue())
        self.assertNotIn("Rules snapshot SHA256:", self.output.getvalue())

    def test_snapshot_write_error_cannot_pass_and_removes_partial_snapshot(self):
        write_bytes = Path.write_bytes
        snapshots = []

        def fail_write(path, data):
            snapshots.append(path)
            write_bytes(path, data[:4])
            raise OSError("inert disk full")

        with mock.patch.object(Path, "write_bytes", autospec=True, side_effect=fail_write):
            with self.assertRaisesRegex(OSError, "inert disk full"):
                self.run_main("clamav")
        self.assertEqual(len(snapshots), 1)
        self.assertFalse(snapshots[0].exists())
        self.run.assert_called_once()
        self.assertNotIn("PASS ", self.output.getvalue())
        self.assertNotIn("cases passed", self.output.getvalue())
        self.assertNotIn("Rules snapshot SHA256:", self.output.getvalue())

    def test_scan_errors_fail_and_remove_snapshot(self):
        for engine in ("yara", "clamav"):
            for error in (RuntimeError("inert scan failure"), subprocess.TimeoutExpired("inert", 60)):
                with self.subTest(engine=engine, error=type(error).__name__):
                    snapshots = []

                    def fail_scan(engine, executable, rules, path, scratch, snapshots=snapshots, error=error):
                        self.assertEqual(rules.read_bytes(), self.rules_data)
                        snapshots.append(rules)
                        raise error

                    with mock.patch.object(validator, "scan_case", side_effect=fail_scan):
                        self.assertEqual(self.run_main(engine), 1)
                    self.assertEqual(len(snapshots), 2)
                    self.assertEqual(snapshots[0], snapshots[1])
                    self.assertFalse(snapshots[0].exists())
                    self.assertFalse(snapshots[0].parent.exists())
                    self.assertIn(f"0/2 cases passed ({engine})", self.output.getvalue())
        self.assertNotIn("PASS ", self.output.getvalue())

    def test_scanner_oserror_cannot_pass_and_removes_snapshot(self):
        with mock.patch.object(validator, "scan_case", side_effect=OSError("inert executable failure")):
            with self.assertRaisesRegex(OSError, "inert executable failure"):
                self.run_main("yara")
        self.assertTrue(self.scratch_paths)
        self.assertNotIn("PASS ", self.output.getvalue())
        self.assertNotIn("cases passed", self.output.getvalue())


if __name__ == "__main__":
    unittest.main()
