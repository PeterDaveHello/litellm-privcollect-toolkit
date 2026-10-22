# Validation and scope

Status: **experimental investigation rules**, not a vendor signature release.

Validated on 2026-10-22 with native **YARA 4.5.0** and **ClamAV 1.5.4**.
ClamAV was configured with `--normalize=no` and loaded only this `.yar` file,
so detections are attributable to these rules rather than antivirus hashes.

## Reproducible rule tests

| Test set | Native YARA | ClamAV |
| --- | --- | --- |
| Inert synthetic positives, negatives, thresholds, and size boundaries | 30/30 | 30/30 |
| Hash-verified public samples, static decoding, and bounded fixture edits | 13/13 | 13/13 |
| Total | 43/43 | 43/43 |

Each run also executes 14 pure output-parser regression checks. They verify
that a valid detection cannot hide a coexisting limit alert, unknown detection,
read error, or conflicting exit status. These are separate from the 43
scanner-driven fixture cases above.

Each fixture run reads the rules once, uses a private temporary snapshot for
every case, and prints its SHA-256. Editing the checkout during a run does
not change the rules used by later cases.

An additional end-to-end output check combined an inert positive fixture,
an intentionally oversized inert file, and a nonexistent path in one ClamAV
invocation. The scanner emitted the expected YARA hit, a limit alert, and the
missing-path error; the parser correctly rejected the incomplete result.

The optional sample set uses these publicly reported source identifiers:

| Sample | SHA-256 |
| --- | --- |
| `cook.py` | `9dd0a3926f96a37eb86cf1ee2310d9be93139cc4ebef3ef9e2efe9531390be25` |
| `sitecustomize.py` | `34bef04fe88ac9d0aae0475630b1738681d15b94f233ac8aa46eacf5968305fa` |
| Decoded `cook.py` collector | `6ea3d8ef6cf73a72d8df24f663b7a31ce67494eeb9b0d707b93484e66675d2df` |
| Decoded `sitecustomize.py` collector | `20a59e5a285799e7cf7fa16cfba1c1414f1e84a8459e14207cfd4e998c2cd24b` |

Samples were treated as data only. The runner verifies the source hashes,
parses literal values without evaluation, and bounds decompression to 1 MiB.
It does not import, execute, or compile samples. Full samples and derived
payloads are not distributed in this bundle.

Tested edits include comments, CRLF, spacing around `exec`, changing one
loader repository anchor while retaining its lock anchor, and renaming one
collector transport function. These are limited checks, **not** an evasion
resistance evaluation. Some deliberate changes are expected non-matches:
replacing the compressed fingerprint, removing a required anchor, or reaching
the 2 MiB size boundary.

## Historical reference-corpus observation

A Python 3.12 standard-library reference corpus produced no matches in either
engine. The native scan considered 1,240 regular files below the rule-size
boundary, including five empty files; ClamAV reported 1,235 scanned files.
The five empty files account for the difference. Two oversized static libraries were outside
scope. Symlinks were not followed.

These counts describe a one-off scan. The corpus manifest is not distributed,
so this is not a checkout-reproducible benchmark.

This small, language-specific reference set is not a representative clean
enterprise dataset. Zero observed matches is not a measured general
false-positive rate, and does not establish host integrity. No private host
scan results, paths, credentials, identities, or operational logs are included
here.

## Reproducible public reference corpus

The [CPython 3.12.3 manifest](tests/corpora/cpython-3.12.3.json) pins a separate,
publicly obtainable reference set. Python 3.12.3 was
[released on 2024-04-09](https://www.python.org/downloads/release/python-3123/),
before this incident. This old release is **test data**, not a recommendation
to install it as an analysis interpreter.

The archive SHA-256 is
`56bfef1fdfc1221ce6720e43a661e3eb41785dd914ce99698d8c7896af4bdaa1`
and its size is 20,625,068 bytes. The manifest lists every selected path,
size and SHA-256: regular `.py` files under `Python-3.12.3/Lib/`, excluding
`Lib/test/` and `Lib/idlelib/idle_test/`, all below 2 MiB. This is a defined
subset of the source release, not the entire Python distribution.

Acquire the archive explicitly from the official HTTPS source, outside the
checkout, then run the offline validator from the repository root:

```sh
curl --fail --location --proto '=https' --max-filesize 33554432 \
  --output /path/to/Python-3.12.3.tar.xz \
  https://www.python.org/ftp/python/3.12.3/Python-3.12.3.tar.xz
/usr/bin/python3 -I -S -B tests/validate_corpus.py --engine yara \
  --archive /path/to/Python-3.12.3.tar.xz
/usr/bin/python3 -I -S -B tests/validate_corpus.py --engine clamav \
  --archive /path/to/Python-3.12.3.tar.xz
```

The validator does not download, install, build, import or execute corpus
content. It checks the compressed bytes against the pinned archive identity
before parsing them, then checks every selected member against the manifest.
It rejects missing, extra, duplicate, unsafe, linked or special members and
enforces archive/member limits: 32 MiB compressed, 20,000 members and 512 MiB
of declared member contents. It never extracts archive paths or permissions.
Verified nonempty bytes are written only to numbered `.txt` fixtures inside
a private temporary directory and removed after scanning. The rules are
snapshotted for the run. These bounds support this pinned archive workflow,
not a general-purpose sandbox for arbitrary archives.

Results on 2026-10-22, using CPython 3.12.3 on Linux. Other operating systems
have not been validated for this corpus workflow or its permission checks:

| Measurement | Native YARA 4.5.0 | ClamAV 1.5.4 |
| --- | --- | --- |
| Manifest files verified | 690 | 690 |
| Nonempty files submitted to the engine | 685 | 685 |
| Empty files verified but not submitted | 5 | 5 |
| Matches / incomplete scans | 0 / 0 | 0 / 0 |

The selected files total 11,665,088 bytes. The manifest SHA-256 for these runs
was `bf220e0565afbad8c607e43a06683e2a6506c66cfdbe8e3886bfe6ac0b7123b6`;
the rule SHA-256 was
`76b8ba5b8a404b9f378045d9239392d476f736cc27fbd0ffcca9e3a31c8344fc`.
Each completed scan result includes the engine version, archive/manifest/rule hashes
and actual UTC run timestamps. Exit 0 means complete with no matches in this
corpus; exit 1 means a match needs investigation; exit 2 means incomplete or
invalid validation, including engine warnings, timeouts or report-output failures.
An output failure can leave no JSON; exit 2 still means validation is incomplete. A corpus match
does not itself establish malware. Neither a pinned identity nor zero matches
certifies safety or measures a general false-positive rate. This new set
does not reproduce or supersede the different historical counts above.

## Offline checker and document checks

The standard-library unittest suite currently contains 53 checks covering
catalog/source consistency, relative documentation links, renamed hash
matches, unknown-size artifact behavior, basename-only observations, symlink
and virtual-filesystem rejection, bounded/incomplete scans, read failures,
changed file identity, directory-replacement races, traversal budgets,
unsupported-platform refusal, Windows CRLF hook identity, prefilter accounting,
report provenance, strict size fields, private report permissions and refusal to overwrite.
They also check shared sample/rule identifiers, auxiliary catalog fields,
and incomplete status for unexpected checker exceptions.
Bytecode-name controls distinguish `cook` and `sitecustomize` from similarly
named modules. Subprocess checks cover stdout/stderr write and flush failures,
including Linux `/dev/full`, and preserve normal exit codes for successful reports.
Rule-validator checks cover snapshot reuse after source changes or removal,
read/write failures, scan failures and temporary-file cleanup.
The corpus checks exercise archive-before-parse verification,
selection completeness, member identities and limits, path/link rejection,
empty-file accounting, temporary-file cleanup, fail-closed engine errors,
normal CLI results and subprocess-level output write/flush failures.
Fixtures contain harmless text only. These tests validate the checker, not
the truth of every source-reported historical claim.

Optional sample tests also verify the two LF-to-CRLF transformations against
the catalog's published Windows hashes and measured sizes, plus decoded
payload sizes. The default checkout reproduces 30 inert cases per engine;
the 13 additional cases require separately acquired, hash-verified samples.

## Remaining limitations

- Matches can occur in source-code reports, signatures, test fixtures, or
  archived samples. They establish content presence, not execution.
- The encoded fingerprint does not cover arbitrary recompression or payload
  replacement. The plaintext collector rule requires static decoding first
  when the collector is embedded as base64/zlib.
- String-renamed variants, unknown downloaded stages, larger files, memory-only
  activity, and unrelated persistence are not ruled out.
- Native YARA does not unpack archives. ClamAV's unpacking and limits differ;
  identical rule text does not guarantee identical coverage.
- No complete wheel/archive, broad binary-malware, live-memory, or historical
  network-traffic coverage claim is made.
- Validation is limited to the stated versions and fixtures. Review and retest
  before deploying into automated alerting or remediation.
