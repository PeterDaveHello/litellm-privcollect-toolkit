#!/usr/bin/env python3
"""Offline, read-only file-indicator checker. Never execute or unpack inputs."""

import argparse
import fnmatch
import hashlib
import json
import os
import re
import stat
import sys
from datetime import UTC, datetime
from pathlib import Path

VERSION = "0.1.0"
CATALOG = Path(__file__).resolve().parent.parent / "iocs" / "litellm-1.107.0.json"
DESCRIPTOR_APIS = (
    os.open in os.supports_dir_fd and os.stat in os.supports_dir_fd and os.scandir in os.supports_fd
    and hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY")
)


class ScanError(OSError):
    """Carry a controlled reason without disclosing an absolute evidence path."""


def load_catalog(path, *, with_digest=False):
    with path.open("rb") as stream:
        raw = stream.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise ValueError("Catalog exceeds 1 MiB")
    data = json.loads(raw)
    if not isinstance(data, dict) or type(data.get("schema_version")) is not int or data["schema_version"] != 1:
        raise ValueError("Unsupported catalog schema")
    incident = data.get("incident")
    if not isinstance(incident, dict) or any(
        not isinstance(incident.get(key), str) or not incident[key]
        for key in ("name", "package", "affected_release")
    ):
        raise ValueError("Missing incident scope")
    sources = data.get("sources")
    if not isinstance(sources, dict) or not sources:
        raise ValueError("Missing source registry")
    ids = set()
    digests = set()
    for group in ("file_hashes", "host_artifacts", "network", "container_images",
                  "runtime_indicators", "correlation_indicators"):
        entries = data.get(group)
        if not isinstance(entries, list):
            raise ValueError("Missing indicator group")
        for entry in entries:
            if not isinstance(entry, dict):
                raise ValueError("Indicator must be an object")
            key = entry.get("id")
            refs = entry.get("sources")
            if not isinstance(key, str) or not key or key in ids:
                raise ValueError("Missing or duplicate indicator ID")
            ids.add(key)
            if not isinstance(refs, list) or not refs or any(ref not in sources for ref in refs):
                raise ValueError("Unknown or missing source reference")
            if not isinstance(entry.get("interpretation"), str) or not entry["interpretation"]:
                raise ValueError("Missing indicator interpretation")
            if group == "file_hashes":
                digest = entry.get("sha256")
                if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest) or digest in digests:
                    raise ValueError("Invalid SHA-256")
                digests.add(digest)
                if "size_bytes" not in entry:
                    raise ValueError("Missing file size; use null for unknown sizes")
                size = entry["size_bytes"]
                if size is not None and (type(size) is not int or size < 0):
                    raise ValueError("Invalid file size")
                name = entry.get("name")
                if not isinstance(name, str) or not name or "/" in name or "\\" in name:
                    raise ValueError("Artifact name must be a basename")
                if not isinstance(entry.get("kind"), str) or not entry["kind"]:
                    raise ValueError("Missing artifact kind")
            if group == "host_artifacts":
                pattern = entry.get("basename_pattern")
                if not isinstance(pattern, str) or not pattern or "/" in pattern or "\\" in pattern:
                    raise ValueError("Host pattern must match a basename")
    return (data, hashlib.sha256(raw).hexdigest()) if with_digest else data


def file_digest(path, observed, max_bytes, *, dir_fd=None):
    """Bound reads and reject changed identities, symlinks and special files."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags, dir_fd=dir_fd)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or (before.st_dev, before.st_ino) != (observed.st_dev, observed.st_ino):
            raise ScanError("file_identity_changed")
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            observed.st_size, observed.st_mtime_ns, observed.st_ctime_ns
        ):
            raise ScanError("file_changed_before_hashing")
        digest = hashlib.sha256()
        total = 0
        while True:
            block = stream.read(min(65536, max_bytes - total + 1))
            if not block:
                break
            total += len(block)
            if total > max_bytes:
                raise ScanError("read_limit_exceeded")
            digest.update(block)
        after = os.fstat(stream.fileno())
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_size, after.st_mtime_ns, after.st_ctime_ns
        ) or total != before.st_size:
            raise ScanError("file_changed_during_hashing")
        return digest.hexdigest()


def scan_paths(roots, catalog, *, hash_all=False, max_bytes=128 * 1024 * 1024,
               max_files=100000, max_entries=200000, max_depth=32):
    if not DESCRIPTOR_APIS:
        raise ValueError("Descriptor-relative scanning is unavailable; use a supported analysis host")
    if min(max_bytes, max_files, max_entries, max_depth) < 1 or max_depth > 256:
        raise ValueError("Limits must be positive")
    hashes = {row["sha256"]: row for row in catalog["file_hashes"]}
    sizes = {row["size_bytes"] for row in catalog["file_hashes"] if row["size_bytes"] is not None}
    names = {row["name"] for row in catalog["file_hashes"]}
    result = {
        "schema_version": 1,
        "tool": {"name": "scan_iocs", "version": VERSION},
        "started_at_utc": datetime.now(UTC).isoformat(),
        "scope": {"hash_all": hash_all, "max_bytes": max_bytes, "max_files": max_files,
                  "max_entries": max_entries, "max_depth": max_depth,
                  "hash_selection": "all_regular_files" if hash_all else "known_sizes_or_names_or_host_patterns",
                  "symlinks": "excluded", "cross_device_filesystems": "excluded",
                  "same_device_bind_mounts": "not distinguished", "archives": "not unpacked"},
        "regular_files": 0, "hashed_files": 0, "skipped_symlinks": 0,
        "skipped_special": 0, "skipped_mounts": 0, "skipped_repeated_directories": 0,
        "oversized_candidates": 0, "prefilter_skipped": 0, "entries_seen": 0,
        "observations": [], "errors": [],
    }
    exhausted = False

    def scan_root(original, label):
        root = Path(original).absolute()

        def error_at(relative, reason):
            item = {"root": label, "path": relative}
            if isinstance(reason, ScanError):
                item["error"] = str(reason)
            elif isinstance(reason, OSError):
                item.update(error=type(reason).__name__, errno=reason.errno)
            elif isinstance(reason, RecursionError):
                item["error"] = "recursion_limit"
            elif isinstance(reason, RuntimeError):
                item["error"] = "path_resolution_failed"
            else:
                item["error"] = reason
            result["errors"].append(item)

        def consume_entry(relative):
            nonlocal exhausted
            if result["entries_seen"] >= max_entries:
                error_at(relative, "entry_count_limit")
                exhausted = True
                return False
            result["entries_seen"] += 1
            return True

        def observe(name, relative):
            matches = []
            for marker in catalog["host_artifacts"]:
                if fnmatch.fnmatchcase(name, marker["basename_pattern"]):
                    matches.append({"root": label, "path": relative,
                        "match": "basename_observation", "indicator_id": marker["id"],
                        "interpretation": marker["interpretation"]})
            result["observations"].extend(matches)
            return matches

        def check_file(name, relative, info, markers, parent_fd=None):
            nonlocal exhausted
            if result["regular_files"] >= max_files:
                error_at(relative, "file_count_limit")
                exhausted = True
                return
            result["regular_files"] += 1
            if not (hash_all or info.st_size in sizes or Path(name).name in names or markers):
                result["prefilter_skipped"] += 1
                return
            if info.st_size > max_bytes:
                result["oversized_candidates"] += 1
                error_at(relative, "file_size_limit")
                return
            digest = file_digest(name, info, max_bytes, dir_fd=parent_fd)
            result["hashed_files"] += 1
            for marker in markers:
                marker["sha256"] = digest
            if digest in hashes:
                item = hashes[digest]
                result["observations"].append({"root": label, "path": relative, "match": "sha256",
                    "indicator_id": item["id"], "kind": item["kind"], "sha256": digest,
                    "interpretation": item["interpretation"]})

        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        seen_directories = set()

        def walk(directory_fd, relative, depth):
            with os.scandir(directory_fd) as entries:
                for entry in entries:
                    child_path = str(Path(relative) / entry.name)
                    if exhausted or not consume_entry(child_path):
                        return
                    try:
                        info = os.stat(entry.name, dir_fd=directory_fd, follow_symlinks=False)
                        if stat.S_ISLNK(info.st_mode):
                            result["skipped_symlinks"] += 1
                            continue
                        if info.st_dev != root_stat.st_dev:
                            result["skipped_mounts"] += 1
                            continue
                        markers = observe(entry.name, child_path)
                        if stat.S_ISDIR(info.st_mode):
                            if depth >= max_depth:
                                error_at(child_path, "directory_depth_limit")
                                continue
                            child_fd = os.open(entry.name, directory_flags, dir_fd=directory_fd)
                            try:
                                current = os.fstat(child_fd)
                                identity = (current.st_dev, current.st_ino)
                                if identity != (info.st_dev, info.st_ino):
                                    raise ScanError("directory_identity_changed")
                                if identity in seen_directories:
                                    result["skipped_repeated_directories"] += 1
                                    continue
                                seen_directories.add(identity)
                                walk(child_fd, child_path, depth + 1)
                            finally:
                                os.close(child_fd)
                        elif stat.S_ISREG(info.st_mode):
                            check_file(entry.name, child_path, info, markers, directory_fd)
                        else:
                            result["skipped_special"] += 1
                    except OSError as error:
                        error_at(child_path, error)

        try:
            root_stat = root.lstat()
            if stat.S_ISLNK(root_stat.st_mode):
                raise ScanError("symlink_root_refused")
            canonical = root.resolve(strict=True)
            if any(
                canonical == Path(prefix) or Path(prefix) in canonical.parents
                for prefix in ("/proc", "/sys", "/dev")
            ):
                raise ScanError("virtual_filesystem_root_refused")
            if not (stat.S_ISREG(root_stat.st_mode) or stat.S_ISDIR(root_stat.st_mode)):
                raise ScanError("special_file_root_refused")
            relative = root.name if stat.S_ISREG(root_stat.st_mode) else "."
            if not consume_entry(relative):
                return
            markers = observe(root.name, relative)
            if stat.S_ISREG(root_stat.st_mode):
                check_file(root, relative, root_stat, markers)
            else:
                root_fd = os.open(root, directory_flags)
                try:
                    current = os.fstat(root_fd)
                    if (current.st_dev, current.st_ino) != (root_stat.st_dev, root_stat.st_ino):
                        raise ScanError("root_identity_changed")
                    seen_directories.add((current.st_dev, current.st_ino))
                    walk(root_fd, ".", 0)
                finally:
                    os.close(root_fd)
        except (OSError, RuntimeError) as error:
            error_at(".", error)

    for index, original in enumerate(roots, 1):
        scan_root(original, f"input_{index}")
        if exhausted:
            break
    result["complete_within_scope"] = not result["errors"]
    result["exit_code"] = 2 if result["errors"] else (1 if result["observations"] else 0)
    result["completed_at_utc"] = datetime.now(UTC).isoformat()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", type=Path)
    parser.add_argument("--catalog", type=Path, default=CATALOG)
    parser.add_argument("--hash-all", action="store_true")
    parser.add_argument("--max-bytes", type=int, default=128 * 1024 * 1024)
    parser.add_argument("--max-files", type=int, default=100000)
    parser.add_argument("--max-entries", type=int, default=200000)
    parser.add_argument("--max-depth", type=int, default=32)
    parser.add_argument("--output", type=Path, help="New JSON report path; never overwritten")
    args = parser.parse_args()
    try:
        if args.output and os.path.lexists(args.output):
            raise FileExistsError("Output already exists")
        data, catalog_digest = load_catalog(args.catalog, with_digest=True)
        report = scan_paths(args.paths, data, hash_all=args.hash_all,
                            max_bytes=args.max_bytes, max_files=args.max_files,
                            max_entries=args.max_entries, max_depth=args.max_depth)
        report["catalog_sha256"] = catalog_digest
        text = json.dumps(report, indent=2) + "\n"
        if args.output:
            fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as stream:
                stream.write(text)
        else:
            try:
                sys.stdout.write(text)
                sys.stdout.flush()
            except Exception:
                # Prevent a repeated shutdown flush from replacing the incomplete exit status.
                sys.stdout = None
                raise
    except Exception as error:
        try:
            print(f"Check incomplete: {type(error).__name__}; no clean verdict", file=sys.stderr)
            sys.stderr.flush()
        except Exception:
            sys.stderr = None
        return 2
    return report["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
