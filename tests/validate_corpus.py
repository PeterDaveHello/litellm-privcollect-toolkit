#!/usr/bin/env python3
"""Scan a pinned public CPython corpus offline, without installing or executing it."""

import argparse
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "tests/corpora/cpython-3.12.3.json"
ARCHIVE_ROOT = "Python-3.12.3"
MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_MEMBERS = 20000
MAX_MEMBER_BYTES = 512 * 1024 * 1024
MAX_FILE_BYTES = 2 * 1024 * 1024
SELECTION = {
    "prefix": ARCHIVE_ROOT + "/Lib/",
    "suffix": ".py",
    "exclude_prefixes": [ARCHIVE_ROOT + "/Lib/test/", ARCHIVE_ROOT + "/Lib/idlelib/idle_test/"],
    "max_size_exclusive": MAX_FILE_BYTES,
}
SPEC = importlib.util.spec_from_file_location("rule_validator", ROOT / "tests/validate.py")
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


def selected(name):
    return (name.startswith(SELECTION["prefix"]) and name.endswith(SELECTION["suffix"])
            and not name.startswith(tuple(SELECTION["exclude_prefixes"])))


def safe_member_name(name):
    return (isinstance(name, str) and 0 < len(name) <= 512 and name.isprintable()
            and "\\" not in name and all(part not in ("", ".", "..") for part in name.split("/"))
            and (name == ARCHIVE_ROOT or name.startswith(ARCHIVE_ROOT + "/")))


def bounded_regular_bytes(path, limit):
    """Read one bounded regular-file snapshot; never block on a FIFO."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError("Expected a bounded regular file")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(limit + 1)
    finally:
        os.close(fd)
    if len(data) > limit:
        raise ValueError("Input exceeds its byte limit")
    return data


def load_manifest(path=MANIFEST):
    raw = bounded_regular_bytes(path, 1024 * 1024)
    manifest = json.loads(raw)
    if (not isinstance(manifest, dict) or type(manifest.get("schema_version")) is not int
            or manifest["schema_version"] != 1 or manifest.get("selection") != SELECTION):
        raise ValueError("Unexpected corpus manifest or selection")
    archive = manifest.get("archive", {})
    if (not isinstance(archive, dict) or type(archive.get("size_bytes")) is not int
            or not 0 < archive["size_bytes"] <= MAX_ARCHIVE_BYTES
            or not isinstance(archive.get("sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", archive["sha256"])):
        raise ValueError("Invalid archive identity")
    files = manifest.get("files")
    if not isinstance(files, list) or not 0 < len(files) <= MAX_MEMBERS:
        raise ValueError("Invalid corpus file list")
    names = set()
    for entry in files:
        if not isinstance(entry, dict):
            raise ValueError("Invalid corpus file entry")
        name = entry.get("path")
        if not safe_member_name(name) or not selected(name) or name in names:
            raise ValueError("Invalid or duplicate corpus path")
        names.add(name)
        if (type(entry.get("size_bytes")) is not int or not 0 <= entry["size_bytes"] < MAX_FILE_BYTES
                or not isinstance(entry.get("sha256"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"])):
            raise ValueError("Invalid corpus file identity")
    expected = {"files": len(files), "bytes": sum(entry["size_bytes"] for entry in files),
                "empty_files": sum(entry["size_bytes"] == 0 for entry in files)}
    if manifest.get("totals") != expected or expected["bytes"] > MAX_MEMBER_BYTES:
        raise ValueError("Corpus totals disagree with its entries")
    return manifest, hashlib.sha256(raw).hexdigest()


def verified_members(raw, manifest):
    """Verify the compressed snapshot before parsing, then yield selected bytes."""
    identity = manifest["archive"]
    if len(raw) != identity["size_bytes"] or hashlib.sha256(raw).hexdigest() != identity["sha256"]:
        raise ValueError("Archive size or SHA-256 differs from the pinned manifest")
    expected = {entry["path"]: entry for entry in manifest["files"]}
    seen = set()
    found = set()
    total_bytes = 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r|xz") as archive:
        for member in archive:
            name = member.name.rstrip("/") if member.isdir() else member.name
            if not safe_member_name(name) or name in seen:
                raise ValueError("Unsafe or duplicate archive member")
            seen.add(name)
            total_bytes += member.size
            if len(seen) > MAX_MEMBERS or member.size < 0 or total_bytes > MAX_MEMBER_BYTES:
                raise ValueError("Archive member budget exceeded")
            if member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE) or member.sparse is not None:
                raise ValueError("Links, sparse files and special archive members are not allowed")
            if not selected(name):
                continue
            entry = expected.get(name)
            if (entry is None or not member.isfile() or member.size != entry["size_bytes"]
                    or member.size >= MAX_FILE_BYTES):
                raise ValueError("Selected member differs from the corpus manifest")
            with archive.extractfile(member) as stream:
                data = stream.read(member.size + 1)
            if len(data) != member.size or hashlib.sha256(data).hexdigest() != entry["sha256"]:
                raise ValueError("Selected member content differs from the corpus manifest")
            found.add(name)
            yield name, data
    if found != set(expected):
        raise ValueError("Corpus members are missing from the archive")


def scan_corpus(raw, manifest, engine, executable, rules):
    result = {"verified_files": 0, "empty_files": 0, "scanned_files": 0, "matches": []}
    with tempfile.TemporaryDirectory(prefix="yara-public-corpus-") as directory:
        scratch = Path(directory)
        rule_path = scratch / "rules.yar"
        rule_path.write_bytes(rules)
        for name, data in verified_members(raw, manifest):
            result["verified_files"] += 1
            if not data:
                result["empty_files"] += 1
                continue
            path = scratch / f'{result["verified_files"]:05d}.txt'
            path.write_bytes(data)
            try:
                matches = validator.scan_case(engine, executable, rule_path, path, scratch)
            finally:
                path.unlink()
            result["scanned_files"] += 1
            if matches:
                result["matches"].append({"path": name, "rules": sorted(matches)})
    result["complete_within_scope"] = True
    result["validation_passed"] = not result["matches"]
    result["exit_code"] = 1 if result["matches"] else 0
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True, help="Locally acquired Python-3.12.3.tar.xz")
    parser.add_argument("--engine", choices=["yara", "clamav"], required=True)
    args = parser.parse_args()
    started = datetime.now(UTC).isoformat()
    try:
        manifest, manifest_digest = load_manifest()
        raw = bounded_regular_bytes(args.archive, MAX_ARCHIVE_BYTES)
        executable = shutil.which("yara" if args.engine == "yara" else "clamscan")
        if not executable:
            raise RuntimeError("Required scanner is not installed")
        version = subprocess.run([executable, "--version"], capture_output=True, text=True, timeout=15, check=True)
        if version.stderr.strip() or not version.stdout.strip():
            raise RuntimeError("Scanner version is unavailable or warned")
        rules = bounded_regular_bytes(ROOT / "rules/litellm_11070.yar", 65536)
        result = scan_corpus(raw, manifest, args.engine, executable, rules)
        result.update(schema_version=1, tool="validate_corpus", engine=args.engine,
                      engine_version=version.stdout.strip(), archive_sha256=manifest["archive"]["sha256"],
                      manifest_sha256=manifest_digest, rules_sha256=hashlib.sha256(rules).hexdigest(),
                      started_at_utc=started, completed_at_utc=datetime.now(UTC).isoformat())
    except Exception as error:
        result = {"schema_version": 1, "tool": "validate_corpus", "complete_within_scope": False,
                  "validation_passed": False, "exit_code": 2, "error_type": type(error).__name__,
                  "started_at_utc": started, "completed_at_utc": datetime.now(UTC).isoformat()}
    try:
        if result["exit_code"] == 2:
            print("Corpus validation is incomplete; check the archive, manifest and scanner.", file=sys.stderr)
            sys.stderr.flush()
        print(json.dumps(result, indent=2))
        sys.stdout.flush()
    except Exception:
        # Prevent a repeated shutdown flush from replacing the incomplete exit status.
        sys.stdout = None
        sys.stderr = None
        return 2
    return result["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
