"""Harmless fixture tests for the read-only checker and public catalog."""

import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("ioc_checker", ROOT / "tools" / "scan_iocs.py")
scanner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(scanner)


@unittest.skipUnless(scanner.DESCRIPTOR_APIS, "Descriptor-relative filesystem APIs are required")
class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ioc-inert-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.payload = b"harmless test bytes"
        self.catalog = {
            "schema_version": 1,
            "incident": {"name": "Fixture", "package": "fixture", "affected_release": "1"},
            "sources": {"TEST": "https://example.invalid/research"},
            "file_hashes": [{"id": "fixture", "name": "known.bin", "kind": "release_reference",
                             "size_bytes": len(self.payload), "sha256": hashlib.sha256(self.payload).hexdigest(),
                             "interpretation": "Harmless test reference, not malware", "sources": ["TEST"]}],
            "host_artifacts": [{"id": "name-only", "basename_pattern": "candidate-*",
                                "interpretation": "Filename observation only", "sources": ["TEST"]}],
            "network": [], "container_images": [], "runtime_indicators": [], "correlation_indicators": [],
        }

    def write_catalog(self):
        p = self.root / "catalog.json"
        p.write_text(json.dumps(self.catalog))
        return p

    def test_renamed_exact_bytes_are_a_reference_not_infection_verdict(self):
        p = self.root / "renamed.txt"
        p.write_bytes(self.payload)
        result = scanner.scan_paths([p], self.catalog)
        self.assertEqual(result["exit_code"], 1)
        self.assertEqual(result["observations"][0]["kind"], "release_reference")
        self.assertNotIn(str(self.root), json.dumps(result))

    def test_different_bytes_same_size_do_not_match(self):
        p = self.root / "other"
        p.write_bytes(b"x" * len(self.payload))
        result = scanner.scan_paths([p], self.catalog)
        self.assertEqual(result["hashed_files"], 1)
        self.assertEqual(result["exit_code"], 0)

    def test_unknown_size_renamed_archive_requires_hash_all(self):
        self.catalog["file_hashes"][0]["size_bytes"] = None
        p = self.root / "renamed.archive"
        p.write_bytes(self.payload)
        self.assertEqual(scanner.scan_paths([p], self.catalog)["hashed_files"], 0)
        self.assertEqual(scanner.scan_paths([p], self.catalog, hash_all=True)["exit_code"], 1)
        named = self.root / "known.bin"
        named.write_bytes(self.payload)
        self.assertEqual(scanner.scan_paths([named], self.catalog)["exit_code"], 1)

    def test_filename_only_observation(self):
        p = self.root / "candidate-empty"
        p.touch()
        result = scanner.scan_paths([p], self.catalog)
        self.assertEqual(result["observations"][0]["match"], "basename_observation")
        self.assertEqual(result["observations"][0]["sha256"], hashlib.sha256(b"").hexdigest())
        self.assertEqual(result["hashed_files"], 1)

    def test_known_name_with_different_size_is_hashed(self):
        p = self.root / "known.bin"
        p.write_bytes(b"changed harmless bytes")
        result = scanner.scan_paths([p], self.catalog)
        self.assertEqual(result["hashed_files"], 1)
        self.assertEqual(result["observations"], [])

    def test_public_bytecode_names_remain_observations_only(self):
        catalog = scanner.load_catalog(scanner.CATALOG)
        for name, indicator in (("cook", "collector-bytecode-name"), ("sitecustomize", "loader-bytecode-name")):
            marker = next(item for item in catalog["host_artifacts"] if item["id"] == indicator)
            for suffix in (".pyc", ".cpython-312.pyc", ".cpython-312.opt-1.pyc"):
                with self.subTest(name=name, suffix=suffix):
                    p = self.root / (name + suffix)
                    p.write_bytes(self.payload)
                    result = scanner.scan_paths([p], catalog)
                    self.assertEqual(result["exit_code"], 1)
                    self.assertTrue(result["complete_within_scope"])
                    self.assertEqual(result["hashed_files"], 1)
                    self.assertEqual(result["observations"], [{
                        "root": "input_1", "path": p.name, "match": "basename_observation",
                        "indicator_id": indicator, "interpretation": marker["interpretation"],
                        "sha256": hashlib.sha256(self.payload).hexdigest(),
                    }])

    def test_public_bytecode_patterns_exclude_similar_module_names(self):
        catalog = scanner.load_catalog(scanner.CATALOG)
        for name in ("cookies", "cookiejar", "sitecustomizer"):
            for suffix in (".pyc", ".cpython-312.pyc", ".cpython-312.opt-1.pyc"):
                with self.subTest(name=name, suffix=suffix):
                    p = self.root / (name + suffix)
                    p.write_bytes(self.payload)
                    result = scanner.scan_paths([p], catalog)
                    self.assertEqual(result["exit_code"], 0)
                    self.assertTrue(result["complete_within_scope"])
                    self.assertEqual(result["observations"], [])
                    self.assertEqual(result["hashed_files"], 0)

    def test_prefilter_scope_and_timestamps(self):
        p = self.root / "unrelated"
        p.write_bytes(b"short")
        result = scanner.scan_paths([p], self.catalog)
        self.assertEqual(result["prefilter_skipped"], 1)
        self.assertEqual(result["hashed_files"], 0)
        self.assertEqual(result["tool"]["version"], scanner.VERSION)
        self.assertEqual(result["scope"]["same_device_bind_mounts"], "not distinguished")
        start = datetime.fromisoformat(result["started_at_utc"])
        end = datetime.fromisoformat(result["completed_at_utc"])
        self.assertIsNotNone(start.tzinfo)
        self.assertGreaterEqual(end, start)

    def test_windows_crlf_hook_hash_matches_when_renamed(self):
        p = self.root / "renamed.txt"
        p.write_bytes(b"import cook\r\n")
        catalog = scanner.load_catalog(scanner.CATALOG)
        for hash_all in (False, True):
            with self.subTest(hash_all=hash_all):
                result = scanner.scan_paths([p], catalog, hash_all=hash_all)
                self.assertEqual(result["exit_code"], 1)
                self.assertEqual(result["observations"][0]["indicator_id"], "raw-hook-windows")
                self.assertEqual(result["observations"][0]["kind"], "startup_hook")

    def test_nested_symlink_is_not_followed(self):
        outside = self.root / "outside.bin"
        outside.write_bytes(self.payload)
        tree = self.root / "tree"
        tree.mkdir()
        (tree / "link").symlink_to(outside)
        result = scanner.scan_paths([tree], self.catalog, hash_all=True)
        self.assertEqual(result["skipped_symlinks"], 1)
        self.assertEqual(result["observations"], [])
        self.assertEqual(scanner.scan_paths([tree / "link"], self.catalog)["exit_code"], 2)

    def test_missing_root_is_incomplete(self):
        result = scanner.scan_paths([self.root / "absent"], self.catalog)
        self.assertEqual(result["exit_code"], 2)
        self.assertFalse(result["complete_within_scope"])

    def test_resolution_failure_is_incomplete(self):
        p = self.root / "input"
        p.write_bytes(self.payload)
        for error, reason in ((RuntimeError, "path_resolution_failed"), (RecursionError, "recursion_limit")):
            with self.subTest(error=error.__name__):
                with mock.patch.object(scanner.Path, "resolve", side_effect=error("sensitive path")):
                    result = scanner.scan_paths([p], self.catalog)
                self.assertEqual(result["exit_code"], 2)
                self.assertEqual(result["errors"][0]["error"], reason)
                self.assertNotIn("sensitive path", json.dumps(result))

    def test_live_proc_input_is_refused(self):
        if not Path("/proc/self/stat").exists():
            self.skipTest("Linux procfs is not available")
        result = scanner.scan_paths([Path("/proc/self/stat")], self.catalog, hash_all=True)
        self.assertEqual(result["exit_code"], 2)
        self.assertEqual(result["hashed_files"], 0)

    def test_size_and_file_count_limits(self):
        for n in ("a", "b"):
            (self.root / n).write_bytes(self.payload)
        result = scanner.scan_paths([self.root], self.catalog, max_files=1)
        self.assertEqual(result["exit_code"], 2)
        self.assertTrue(result["observations"])
        self.assertIn("file_count_limit", [e["error"] for e in result["errors"]])
        result = scanner.scan_paths([self.root / "a"], self.catalog, max_bytes=1)
        self.assertEqual(result["exit_code"], 2)
        self.assertEqual(result["oversized_candidates"], 1)

    def test_read_failure_is_not_clean(self):
        p = self.root / "input"
        p.write_bytes(self.payload)
        with mock.patch.object(scanner, "file_digest", side_effect=PermissionError):
            self.assertEqual(scanner.scan_paths([p], self.catalog)["exit_code"], 2)

    def test_directory_swap_to_symlink_does_not_escape(self):
        tree = self.root / "tree"
        tree.mkdir()
        child = tree / "child"
        child.mkdir()
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "known.bin").write_bytes(self.payload)
        original_open = os.open
        swapped = False

        def replace_before_open(path, flags, *args, **kwargs):
            nonlocal swapped
            if path == "child" and kwargs.get("dir_fd") is not None and not swapped:
                child.rename(tree / "old-child")
                child.symlink_to(outside, target_is_directory=True)
                swapped = True
            return original_open(path, flags, *args, **kwargs)

        with mock.patch.object(scanner.os, "open", side_effect=replace_before_open):
            result = scanner.scan_paths([tree], self.catalog, hash_all=True)
        self.assertTrue(swapped)
        self.assertEqual(result["hashed_files"], 0)
        self.assertEqual(result["observations"], [])
        self.assertEqual(result["exit_code"], 2)

    def test_directory_fd_survives_path_replacement(self):
        tree = self.root / "tree"
        tree.mkdir()
        child = tree / "child"
        child.mkdir()
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "known.bin").write_bytes(self.payload)
        identity = child.stat().st_ino
        original_scandir = os.scandir
        swapped = False

        def replace_before_scandir(fd):
            nonlocal swapped
            if isinstance(fd, int) and os.fstat(fd).st_ino == identity and not swapped:
                child.rename(tree / "old-child")
                child.symlink_to(outside, target_is_directory=True)
                swapped = True
            return original_scandir(fd)

        with mock.patch.object(scanner.os, "scandir", side_effect=replace_before_scandir):
            result = scanner.scan_paths([tree], self.catalog, hash_all=True)
        self.assertTrue(swapped)
        self.assertEqual(result["hashed_files"], 0)
        self.assertEqual(result["observations"], [])

    def test_directory_depth_and_entry_limits(self):
        (self.root / "a" / "b").mkdir(parents=True)
        result = scanner.scan_paths([self.root], self.catalog, max_depth=1)
        self.assertEqual(result["exit_code"], 2)
        self.assertIn("directory_depth_limit", [e["error"] for e in result["errors"]])
        result = scanner.scan_paths([self.root], self.catalog, max_entries=1)
        self.assertEqual(result["exit_code"], 2)
        self.assertIn("entry_count_limit", [e["error"] for e in result["errors"]])

    def test_unsupported_descriptor_api_fails_closed(self):
        with mock.patch.object(scanner, "DESCRIPTOR_APIS", False), self.assertRaises(ValueError):
            scanner.scan_paths([self.root], self.catalog)

    def test_changed_identity_is_rejected(self):
        p = self.root / "input"
        p.write_bytes(self.payload)
        other = self.root / "other"
        other.write_bytes(self.payload)
        with self.assertRaises(OSError):
            scanner.file_digest(p, other.stat(), 1024)

    def test_change_between_stat_and_open_is_rejected(self):
        p = self.root / "input"
        p.write_bytes(self.payload)
        observed = p.stat()
        p.write_bytes(b"changed after stat")
        os.utime(p, ns=(observed.st_atime_ns, observed.st_mtime_ns + 1))
        with self.assertRaisesRegex(scanner.ScanError, "file_changed_before_hashing"):
            scanner.file_digest(p, observed, 1024)

    def test_catalog_rejects_bad_hash_and_reference(self):
        self.assertEqual(scanner.load_catalog(self.write_catalog())["schema_version"], 1)
        self.catalog["file_hashes"][0]["sha256"] = "not-a-hash"
        with self.assertRaises(ValueError):
            scanner.load_catalog(self.write_catalog())
        self.catalog["file_hashes"][0]["sha256"] = hashlib.sha256(self.payload).hexdigest()
        self.catalog["file_hashes"][0]["sources"] = ["UNKNOWN"]
        with self.assertRaises(ValueError):
            scanner.load_catalog(self.write_catalog())

    def test_catalog_requires_explicit_size(self):
        del self.catalog["file_hashes"][0]["size_bytes"]
        with self.assertRaisesRegex(ValueError, "Missing file size"):
            scanner.load_catalog(self.write_catalog())

    def test_existing_report_prevents_scan(self):
        output = self.root / "report.json"
        output.write_text("preserve this")
        argv = ["scan_iocs", "--output", str(output), str(self.root)]
        with mock.patch.object(sys, "argv", argv), mock.patch.object(scanner, "scan_paths") as scan:
            with mock.patch.object(sys, "stderr"):
                self.assertEqual(scanner.main(), 2)
        scan.assert_not_called()

    def test_cli_output_is_private_and_refuses_overwrite(self):
        p = self.root / "input"
        p.write_bytes(self.payload)
        output = self.root / "report.json"
        args = [sys.executable, "-I", "-S", "-B", str(ROOT / "tools/scan_iocs.py"),
                "--catalog", str(self.write_catalog()), "--output", str(output), str(p)]
        first = subprocess.run(args, capture_output=True, check=False)
        self.assertEqual(first.returncode, 1)
        before = output.read_bytes()
        report = json.loads(before)
        catalog_digest = hashlib.sha256((self.root / "catalog.json").read_bytes()).hexdigest()
        self.assertEqual(report["catalog_sha256"], catalog_digest)
        self.assertEqual(os.stat(output).st_mode & 0o777, 0o600)
        self.assertEqual(subprocess.run(args, capture_output=True, check=False).returncode, 2)
        self.assertEqual(output.read_bytes(), before)

    def test_unexpected_checker_errors_exit_incomplete(self):
        argv = ["scan_iocs", "--catalog", str(self.write_catalog()), str(self.root)]
        for error in (RuntimeError, MemoryError):
            with self.subTest(error=error.__name__), mock.patch.object(sys, "argv", argv):
                with mock.patch.object(scanner, "scan_paths", side_effect=error), mock.patch.object(sys, "stderr"):
                    self.assertEqual(scanner.main(), 2)

    def test_cli_valid_output_preserves_exit_codes(self):
        catalog = self.write_catalog()
        p = self.root / "input"
        for code, payload in ((0, b"unrelated"), (1, self.payload)):
            p.write_bytes(payload)
            for destination in ("stdout", "file"):
                with self.subTest(code=code, destination=destination):
                    output = self.root / f"report-{code}.json"
                    args = [sys.executable, "-I", "-S", "-B", str(ROOT / "tools/scan_iocs.py"),
                            "--catalog", str(catalog), str(p)]
                    if destination == "file":
                        args.extend(["--output", str(output)])
                    proc = subprocess.run(args, capture_output=True, timeout=15, check=False)
                    self.assertEqual(proc.returncode, code, proc.stderr)
                    self.assertEqual(proc.stderr, b"")
                    report = json.loads(output.read_bytes() if destination == "file" else proc.stdout)
                    self.assertEqual(report["exit_code"], code)
                    self.assertTrue(report["complete_within_scope"])
                    self.assertEqual(bool(report["observations"]), bool(code))
                    if destination == "file":
                        self.assertEqual(proc.stdout, b"")

    def test_cli_output_write_and_flush_failures_exit_incomplete(self):
        program = textwrap.dedent("""\
            import errno
            import runpy
            import sys

            path, streams, phase, catalog, target = sys.argv[1:]
            class OutputFailure:
                def write(self, text):
                    if phase == "write":
                        raise OSError(errno.ENOSPC, "inert write failure")
                    return len(text)
                def flush(self):
                    raise OSError(errno.ENOSPC, "inert flush failure")

            for stream in streams.split(","):
                setattr(sys, stream, OutputFailure())
            sys.argv = [path, "--catalog", catalog, target]
            runpy.run_path(path, run_name="__main__")
        """)
        catalog = self.write_catalog()
        p = self.root / "input"
        p.write_bytes(self.payload)
        for streams in ("stdout", "stderr", "stdout,stderr"):
            for phase in ("write", "flush"):
                with self.subTest(streams=streams, phase=phase):
                    selected_catalog = self.root / "missing.json" if streams == "stderr" else catalog
                    proc = subprocess.run(
                        [sys.executable, "-I", "-S", "-B", "-c", program,
                         str(ROOT / "tools/scan_iocs.py"), streams, phase, str(selected_catalog), str(p)],
                        capture_output=True, timeout=15, check=False,
                    )
                    self.assertEqual(proc.returncode, 2, proc.stderr)
                    self.assertNotIn(b"Traceback", proc.stderr)
                    self.assertNotIn(b"Exception ignored", proc.stderr)
                    if streams == "stdout":
                        self.assertIn(b"Check incomplete: OSError; no clean verdict", proc.stderr)

    @unittest.skipUnless(sys.platform.startswith("linux") and Path("/dev/full").exists(),
                         "Linux /dev/full is required")
    def test_cli_full_output_device_exits_incomplete(self):
        catalog = self.write_catalog()
        p = self.root / "input"
        for code, payload in ((0, b"unrelated"), (1, self.payload)):
            p.write_bytes(payload)
            for streams in ("stdout", "stderr", "stdout,stderr"):
                with self.subTest(code=code, streams=streams), open("/dev/full", "wb", buffering=0) as full:
                    selected_catalog = self.root / "missing.json" if streams == "stderr" else catalog
                    proc = subprocess.run(
                        [sys.executable, "-I", "-S", "-B", str(ROOT / "tools/scan_iocs.py"),
                         "--catalog", str(selected_catalog), str(p)],
                        stdout=full if "stdout" in streams else subprocess.PIPE,
                        stderr=full if "stderr" in streams else subprocess.PIPE,
                        timeout=15, check=False,
                    )
                    self.assertEqual(proc.returncode, 2, proc.stderr)
                    if streams == "stdout":
                        self.assertIn(b"Check incomplete: OSError; no clean verdict", proc.stderr)
                        self.assertNotIn(b"Exception ignored", proc.stderr)


class ProjectTests(unittest.TestCase):
    def test_public_catalog_scope_and_sources(self):
        data = scanner.load_catalog(scanner.CATALOG)
        self.assertEqual(data["incident"]["affected_release"], "1.107.0")
        self.assertEqual(len(data["file_hashes"]), 16)
        refs = (ROOT / "docs/references.md").read_text()
        for source in data["sources"]:
            self.assertIn("## " + source + "\n", refs)
        sdist = next(x for x in data["file_hashes"] if x["id"] == "release-sdist")
        self.assertEqual(sdist["kind"], "release_reference")

    def test_sample_and_rule_identifiers_match_catalog(self):
        spec = importlib.util.spec_from_file_location("rule_validator", ROOT / "tests/validate.py")
        validator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(validator)
        catalog = {item["id"]: item for item in scanner.load_catalog(scanner.CATALOG)["file_hashes"]}
        for filename, suffix in (("cook.py.evidence", "cook"), ("sitecustomize.py.evidence", "loader")):
            self.assertEqual(validator.SAMPLE_HASHES[filename], catalog[f"raw-{suffix}"]["sha256"])
            self.assertEqual(validator.DECODED_HASHES[filename], catalog[f"decoded-{suffix}"]["sha256"])
        rules = dict(re.findall(r"\brule\s+(\w+)[^{]*\{(.*?)\n\}",
                                (ROOT / "rules/litellm_11070.yar").read_text(), re.S))
        for rule, key, indicator in (
            (validator.ENCODED, "sample_sha256", "raw-cook"),
            (validator.LOADER, "sample_sha256", "raw-loader"),
            (validator.COLLECTOR, "decoded_sample_sha256", "decoded-cook"),
        ):
            self.assertIn(f'{key} = "{catalog[indicator]["sha256"]}"', rules[rule])
        self.assertIn(f'$blob = "{validator.PREFIX.decode("ascii")}" ascii', rules[validator.ENCODED])

    def test_auxiliary_catalog_fields(self):
        catalog = scanner.load_catalog(scanner.CATALOG)
        for group in ("network", "container_images", "runtime_indicators", "correlation_indicators"):
            for item in catalog[group]:
                with self.subTest(indicator=item["id"]):
                    for key in ("kind", "value"):
                        self.assertIsInstance(item[key], str)
                        self.assertTrue(item[key])
        for item in catalog["network"]:
            self.assertIn(item["classification"], {
                "campaign_destination", "specific_shared_host_resource", "correlation_only",
                "benign_infrastructure_context",
            })
        images = {item["id"]: item for item in catalog["container_images"]}
        for item in images.values():
            self.assertRegex(item["value"], r"^sha256:[0-9a-f]{64}$")
            self.assertIn(item["kind"], ("image_index", "platform_manifest"))
            if item["kind"] == "platform_manifest":
                self.assertEqual(images[item["parent_index_id"]]["kind"], "image_index")
                self.assertIn(item["platform"], ("linux/amd64", "linux/arm64"))
            else:
                for key in ("repositories", "tags_at_observation"):
                    self.assertIsInstance(item[key], list)
                    self.assertTrue(item[key])
                    self.assertTrue(all(isinstance(value, str) and value for value in item[key]))

    def test_correlation_identifiers_are_separate_from_file_hashes(self):
        catalog = scanner.load_catalog(scanner.CATALOG)
        entries = {item["kind"]: item for item in catalog["correlation_indicators"]}
        self.assertEqual(set(entries), {"source_repository", "git_commit", "workflow_run", "rsa_spki_sha256"})
        self.assertRegex(entries["git_commit"]["value"], r"^[0-9a-f]{40}$")
        self.assertEqual(entries["git_commit"]["repository_id"], entries["source_repository"]["id"])
        self.assertRegex(entries["workflow_run"]["value"], r"^[0-9]+$")
        run = entries["workflow_run"]
        self.assertEqual(run["url"], f'https://github.com/{run["repository"]}/actions/runs/{run["value"]}')
        self.assertRegex(entries["rsa_spki_sha256"]["value"], r"^[0-9a-f]{64}$")
        self.assertEqual(entries["rsa_spki_sha256"]["key_bits"], 4096)
        hashes = {item["sha256"] for item in catalog["file_hashes"]}
        self.assertTrue(all(item["value"] not in hashes for item in entries.values()))
        self.assertTrue(all("S12" in item["sources"] for item in entries.values()))

    def test_relative_document_links_exist(self):
        for p in [*ROOT.glob("*.md"), *ROOT.glob("docs/*.md")]:
            for target in re.findall(r"\]\(([^)]+)\)", p.read_text()):
                if "://" in target or target.startswith("#"):
                    continue
                file_part = target.split("#", 1)[0]
                self.assertTrue((p.parent / file_part).exists(), f"Broken link in {p.name}: {target}")


if __name__ == "__main__":
    unittest.main()
