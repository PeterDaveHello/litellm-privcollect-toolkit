#!/usr/bin/env python3
"""Exercise YARA rules using inert text and optional, hash-verified evidence.

Run with a trusted system Python using -I -S. Never execute a sample.
"""

import argparse
import ast
import base64
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
import zlib
from pathlib import Path

ENCODED = "LiteLLM_11070_EncodedCollector"
LOADER = "LiteLLM_11070_RemoteLoader"
COLLECTOR = "LiteLLM_11070_DecodedCollector"
RULE_NAMES = {ENCODED, LOADER, COLLECTOR}
PREFIX = b"eNrdfWt327qu4Pf+Ck/XdCTvxu9HnJydcydN0zZtHt1J+nRytGSJtlXLkirJdpKuzm8"
SAMPLE_HASHES = {
    "cook.py.evidence": "9dd0a3926f96a37eb86cf1ee2310d9be93139cc4ebef3ef9e2efe9531390be25",
    "sitecustomize.py.evidence": "34bef04fe88ac9d0aae0475630b1738681d15b94f233ac8aa46eacf5968305fa",
}
DECODED_HASHES = {
    "cook.py.evidence": "6ea3d8ef6cf73a72d8df24f663b7a31ce67494eeb9b0d707b93484e66675d2df",
    "sitecustomize.py.evidence": "20a59e5a285799e7cf7fa16cfba1c1414f1e84a8459e14207cfd4e998c2cd24b",
}


def inert(*tokens):
    return b"INERT TEST DATA - NOT EXECUTABLE\n" + b"\n".join(tokens) + b"\n"


def synthetic_cases():
    encoded = inert(PREFIX, b"b64decode", b"decompress", b"exec(")
    loader = inert(b"remote_code_loader.lock", b"/codepy", b"<remote>",
                   b"_acquire_daemon_lock", b"_daemonize", b"_run_forever")
    collector = inert(b"PRIVCOLLECT_ACTIVE", b"privcollect", b"pc_aes_enc", b"pc_rsa_enc",
                      b"pc_post", b"mod_env_vars", b"mod_ssh_keys", b"mod_ai_devtools")
    cases = [
        ("encoded_markers", encoded, {ENCODED}),
        ("encoded_exec_spacing", encoded.replace(b"exec(", b"exec \n ("), {ENCODED}),
        ("encoded_crlf", encoded.replace(b"\n", b"\r\n"), {ENCODED}),
        ("encoded_changed_fingerprint", encoded.replace(PREFIX, b"different-compressed-payload"), set()),
        ("loader_markers", loader, {LOADER}),
        ("loader_repository_anchor", loader.replace(b"remote_code_loader.lock",
                                                  b"letters9813/pythonclient-test"), {LOADER}),
        ("loader_changed_anchor", loader.replace(b"remote_code_loader.lock", b"example.lock"), set()),
        ("collector_markers", collector, {COLLECTOR}),
        ("collector_changed_guard", collector.replace(b"PRIVCOLLECT_ACTIVE", b"EXAMPLE_ACTIVE"), set()),
        ("benign_import_hook", b"import cook\n", set()),
        ("benign_encoding_example", inert(b"base64", b"zlib", b"b64decode", b"decompress", b"exec("), set()),
        ("benign_repository_reference", inert(b"letters9813/pythonclient-test"), set()),
        ("benign_security_indicator_list", inert(b"remote_code_loader.lock", b"/codepy",
                                                b"PRIVCOLLECT_ACTIVE"), set()),
        ("benign_python_startup", b"import os\nimport site\nsite.ENABLE_USER_SITE = False\n", set()),
    ]
    for label, data, tokens in [
        ("encoded", encoded, [PREFIX, b"b64decode", b"decompress", b"exec("]),
        ("loader", loader, [b"/codepy", b"<remote>", b"_daemonize"]),
        ("collector", collector, [b"pc_post", b"mod_env_vars", b"privcollect"]),
    ]:
        for number, token in enumerate(tokens):
            cases.append((f"{label}_missing_required_{number}", data.replace(token, b"REMOVED"), set()))
        rule = {"encoded": ENCODED, "loader": LOADER, "collector": COLLECTOR}[label]
        cases.append((f"{label}_below_size_cap", data + b" " * (2 * 1024 * 1024 - 1 - len(data)), {rule}))
        cases.append((f"{label}_at_size_cap", data + b" " * (2 * 1024 * 1024 - len(data)), set()))
    return cases


def decode_verified_literal(source, expected_hash):
    """Decode one bounded literal from verified source, without evaluating it."""
    decoded = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Constant) or not isinstance(node.value, (str, bytes)):
            continue
        value = node.value
        if not 10000 < len(value) < 100000:
            continue
        try:
            compressed = base64.b64decode(value, validate=True)
            decoder = zlib.decompressobj()
            data = decoder.decompress(compressed, 1024 * 1024)
        except (ValueError, zlib.error):
            continue
        if not decoder.eof or decoder.unconsumed_tail or decoder.unused_data:
            continue
        if hashlib.sha256(data).hexdigest() == expected_hash:
            decoded.append(data)
    if len(decoded) != 1:
        raise ValueError("Expected exactly one decoded payload with the published hash")
    return decoded[0]


def evidence_cases(directory):
    catalog_path = Path(__file__).resolve().parent.parent / "iocs" / "litellm-1.107.0.json"
    catalog = {item["id"]: item for item in json.loads(catalog_path.read_bytes())["file_hashes"]}
    cases = []
    for name, expected_hash in SAMPLE_HASHES.items():
        path = directory / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 100000:
            raise ValueError("Missing or unexpected evidence file")
        with path.open("rb") as stream:
            data = stream.read(100001)
        if len(data) > 100000:
            raise ValueError("Evidence exceeds the source-size limit")
        if hashlib.sha256(data).hexdigest() != expected_hash:
            raise ValueError("Evidence hash does not match the published sample")
        rules = {ENCODED} if name.startswith("cook") else {ENCODED, LOADER}
        label = "cook" if name.startswith("cook") else "loader"
        crlf = data.replace(b"\n", b"\r\n")
        windows = catalog[f"raw-{label}-windows"]
        if hashlib.sha256(crlf).hexdigest() != windows["sha256"] or len(crlf) != windows["size_bytes"]:
            raise ValueError("Derived CRLF artifact does not match the catalog identity and size")
        cases.extend([
            (f"sample_{label}", data, rules),
            (f"sample_{label}_comment", b"# Analyst-only static fixture\n" + data + b"\n# End fixture\n", rules),
            (f"sample_{label}_crlf", crlf, rules),
        ])
        decoded = decode_verified_literal(data, DECODED_HASHES[name])
        if len(decoded) != catalog[f"decoded-{label}"]["size_bytes"]:
            raise ValueError("Decoded artifact size does not match the catalog")
        cases.extend([
            (f"sample_{label}_decoded", decoded, {COLLECTOR}),
            (f"sample_{label}_decoded_comment", b"# Static fixture\n" + decoded, {COLLECTOR}),
            (f"sample_{label}_decoded_renamed_function",
             decoded.replace(b"pc_post", b"analyst_fixture_transport"), {COLLECTOR}),
        ])
        if label == "loader":
            cases.append(("sample_loader_changed_repository",
                          data.replace(b"letters9813/pythonclient-test", b"example/analysis-fixture"), rules))
    return cases


def parse_scanner_output(engine, returncode, stdout, stderr):
    """Reject every unexpected output line, including coexisting limit alerts."""
    allowed = {0} if engine == "yara" else {0, 1}
    if returncode not in allowed or stderr.strip():
        raise RuntimeError(f"Scanner failed or warned (exit {returncode}); not a passing test")
    matches = set()
    for line in stdout.splitlines():
        if not line.strip():
            continue
        if engine == "yara":
            parts = line.split(maxsplit=1)
            if len(parts) != 2 or parts[0] not in RULE_NAMES:
                raise RuntimeError("Unexpected YARA output; not a passing test")
            matches.add(parts[0])
        else:
            match = re.fullmatch(r".+: YARA\.(LiteLLM_11070_\w+)\.UNOFFICIAL FOUND", line)
            if not match or match.group(1) not in RULE_NAMES:
                raise RuntimeError("Unexpected ClamAV output or limit alert; not a passing test")
            matches.add(match.group(1))
    if engine == "clamav" and (returncode == 1) != bool(matches):
        raise RuntimeError("ClamAV exit status disagrees with its detection output")
    return matches


def parser_checks():
    """Exercise output handling without invoking any external scanner."""
    hit = "fixture.txt: YARA." + ENCODED + ".UNOFFICIAL FOUND\n"
    checks = [
        ("clamav", 0, "", "", set()),
        ("clamav", 1, hit, "", {ENCODED}),
        ("clamav", 1, hit + "fixture.txt: Heuristics.Limits.Exceeded.MaxFileSize FOUND\n", "", None),
        ("clamav", 1, hit + "fixture.txt: Other.Detection FOUND\n", "", None),
        ("clamav", 1, hit + "fixture.txt: Access denied ERROR\n", "", None),
        ("clamav", 1, hit, "WARNING: failed to read another file", None),
        ("clamav", 1, "", "", None),
        ("clamav", 0, hit, "", None),
        ("clamav", 2, "", "", None),
        ("yara", 0, ENCODED + " fixture.txt\n", "", {ENCODED}),
        ("yara", 0, "", "", set()),
        ("yara", 0, ENCODED + " fixture.txt\nWARNING: partial scan\n", "", None),
        ("yara", 0, "", "warning: ignored rule", None),
        ("yara", 1, "", "", None),
    ]
    for engine, code, stdout, stderr, expected in checks:
        try:
            actual = parse_scanner_output(engine, code, stdout, stderr)
        except RuntimeError:
            if expected is not None:
                raise AssertionError("Parser rejected an expected valid result") from None
        else:
            if expected is None or actual != expected:
                raise AssertionError("Parser accepted an invalid or mismatched result")
    print(f"{len(checks)}/{len(checks)} scanner-output checks passed")


def scan_case(engine, executable, rules, path, scratch):
    if engine == "yara":
        command = [executable, str(rules), str(path)]
    else:
        command = [executable, "--no-summary", "--allmatch", "--suppress-ok-results", "--normalize=no",
                   "--max-filesize=4M", "--max-scansize=8M", "--alert-exceeds-max=yes",
                   "--tempdir=" + str(scratch), "-d", str(rules), str(path)]
    proc = subprocess.run(command, capture_output=True, text=True, timeout=60, check=False)
    return parse_scanner_output(engine, proc.returncode, proc.stdout, proc.stderr)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", choices=["yara", "clamav"], required=True)
    parser.add_argument(
        "--samples", type=Path, help="Optional restricted directory of published, hash-verified evidence"
    )
    args = parser.parse_args()
    parser_checks()
    executable = shutil.which("yara" if args.engine == "yara" else "clamscan")
    if not executable:
        raise SystemExit("Required scanner is not installed; no tests were run")
    version = subprocess.run([executable, "--version"], capture_output=True, text=True, timeout=15, check=True)
    if version.stderr.strip() or not version.stdout.strip():
        raise SystemExit("Cannot establish scanner version without warnings; no fixture tests were run")
    print(f"Engine version: {version.stdout.strip()}")
    rules = Path(__file__).resolve().parent.parent / "rules" / "litellm_11070.yar"
    cases = synthetic_cases()
    if args.samples:
        cases += evidence_cases(args.samples.resolve())
    failures = 0
    with tempfile.TemporaryDirectory(prefix="yara-inert-tests-") as directory:
        scratch = Path(directory)
        rules_data = rules.read_bytes()
        rules = scratch / rules.name
        rules.write_bytes(rules_data)
        print(f"Rules snapshot SHA256: {hashlib.sha256(rules_data).hexdigest()}")
        for name, data, expected in cases:
            path = scratch / (name + ".txt")
            path.write_bytes(data)
            try:
                actual = scan_case(args.engine, executable, rules, path, scratch)
                passed = actual == expected
                status = "PASS" if passed else "FAIL"
                print(f"{status} {name}: expected={sorted(expected)} actual={sorted(actual)}")
            except (RuntimeError, subprocess.TimeoutExpired) as error:
                passed = False
                print(f"FAIL {name}: {error}")
            finally:
                path.unlink()
            failures += not passed
    print(f"{len(cases) - failures}/{len(cases)} cases passed ({args.engine})")
    raise SystemExit(1 if failures else 0)


if __name__ == "__main__":
    main()
