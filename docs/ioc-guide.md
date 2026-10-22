# Indicator catalog and offline checker

The [JSON catalog](../iocs/litellm-1.107.0.json) is the canonical indicator list.
Every entry cites source IDs linked in the [source register](references.md).
It is not a list of things to delete or endpoints to visit. JSON network
values are un-defanged for machine matching; this tool never requests them.
This is a curated list, not an exhaustive extraction of every constant in
the published research. Shared CDN addresses and generic HTTP headers are
not treated as independently actionable indicators.

| Class | Meaning | Limitation |
| --- | --- | --- |
| Implant / decoded-payload hash | Known content identity | Copied evidence can match without execution |
| Startup-hook hash | The tiny `import cook` statement | Inspect its imported module; the statement alone can be benign |
| Affected wheel hash | Known release artifact | Covers seven named platform wheels, not arbitrary rebuilds |
| Release sdist hash | Source-archive identity | Payload files absent but build settings changed; not approved for recovery |
| Filename / temporary prefix | Investigation observation | Generic filenames can be legitimate |
| Network/header marker | Historical log correlation | Not a blanket blocklist for shared infrastructure |
| Container index / platform manifest | Source-reported image identity at a specific level | A local platform manifest digest need not equal its parent index digest |
| Runtime marker / process traits | Corroborating live-response context | Not checked by the file scanner and not standalone infection evidence |
| Source / workflow / public-key identifier | Cross-reference release evidence or static payload analysis | Not a file hash, network blocklist entry or attribution proof |

The catalog includes LF and Windows CRLF payload identities. `size_basis`
distinguishes measured or statically derived sizes from publisher-reported
values. The two Python CRLF artifacts were derived from hash-verified LF
samples and matched the published Windows hashes; this is not a separate
Windows-wheel acquisition. [S2](references.md#s2), [S5](references.md#s5)

Human-readable network values include `www.litellm[.]dev`,
`hxxp://www.litellm[.]dev/healthcheck`, and
`hxxps://raw.githubusercontent[.]com/letters9813/pythonclient-test/main/domain.txt`.
The `/codepy` host is dynamic; no historical second-stage IP is invented here.
[S1](references.md#s1), [S2](references.md#s2)

Network `classification` distinguishes campaign destinations, specific paths
on shared hosting, correlation-only markers and benign infrastructure context.
Do not turn the entire array into a blocklist. Image tags are historical
observations; compare the full index or platform manifest at the same level.
The supplemental catalog includes Wiz-reported `linux/amd64` and `linux/arm64`
manifests for `ghcr.io/berriai/litellm-database` and
`ghcr.io/berriai/litellm-non_root`. Their parent index identities are unknown;
each entry carries its own repository and historical tag scope. Do not attach
them to the general `litellm` index or infer Docker Hub counterparts.
Incomplete index digest prefixes remain excluded from exact-hash entries.
These four manifests were checked after the initial evidence cutoff; their
earlier publication time was not established. [S14](references.md#s14)

## Correlation identifiers

The `correlation_indicators` group keeps different identity types separate:

| Kind | Reported identifier | Interpretation |
| --- | --- | --- |
| `source_repository` | `https://github.com/Berri-AI/litellm` | Hyphenated source owner, distinct from legitimate `BerriAI/litellm`; do not fetch as part of a scan |
| `git_commit` | `20535d8fa11f786a6c24df7488a0e449ed5f09ad` | Full source revision reported in container provenance, not a SHA-256 file digest |
| `workflow_run` | `BerriAI/project-releaser` run `39587059944` | Reported builder run; an identifier does not imply that its records remain publicly accessible |
| `rsa_spki_sha256` | `a898fd08ad220fed52488906eb45d196f332b972ad5d85214e7726545ecc4218` | SHA-256 of DER-encoded SubjectPublicKeyInfo for the embedded RSA-4096 public key, not a payload-file hash |

These values were published in the unchanged 2026-10-21 12:57:19 UTC
follow-up comment. Correlate them with the appropriate evidence type; none
alone establishes an operator identity, victim execution or successful data
theft. The toolkit does not retrieve workflow records, clone the reported
repository or extract keys from arbitrary files. [S12](references.md#s12),
[S5](references.md#s5)

## Usage

Prefer a trusted analysis host and copied/read-only evidence:

```sh
/usr/bin/python3 -I -S -B tools/scan_iocs.py /path/to/copied/evidence
/usr/bin/python3 -I -S -B tools/scan_iocs.py --hash-all \
  --output /path/outside/repository/report.json /path/to/copied/evidence
```

Default matching hashes files with a catalog size match, known artifact
basename, or host-artifact basename pattern. Thus renamed known-size
payloads can match, but renamed unknown-size wheels may be missed. The report
counts regular files excluded by this selection as `prefilter_skipped`.
`--hash-all` checks every regular file within the byte limit. Neither mode
unpacks archives, decodes payloads, executes files, scans memory, contacts
network endpoints, changes permissions, terminates processes or deletes data.

For a copied package cache, use `--hash-all`: cache entries may have opaque
names, and six of the seven affected wheel sizes are unknown in this catalog.

```sh
/usr/bin/python3 -I -S -B tools/scan_iocs.py --hash-all \
  --output /path/outside/cache/cache-report.json /path/to/copied/package-cache
```

This compares complete file bytes with the catalog hashes. It does not unpack
cached containers, decode HTTP-cache wrappers or reconstruct a wheel from an
extracted cache. Check `prefilter_skipped`, size/count limits and errors when
interpreting coverage; `--hash-all` does not override those limits.

The checker requires POSIX descriptor-relative APIs (tested on Linux). It
anchors directory traversal to open descriptors and refuses unsupported
platforms instead of falling back to path-based traversal. YARA rules remain
usable separately on other platforms. Prefer immutable evidence: this does
not freeze a live filesystem or establish what existed before collection.

Defaults: **100,000 regular files**, **200,000 entries**, **32 directory
levels**, **128 MiB per hashed file**. Configure with `--max-files`,
`--max-entries`, `--max-depth` (at most 256), and `--max-bytes`. Oversized candidates, read errors,
changed files and a reached file-count limit produce an incomplete result.
Nested symlinks, special files and cross-device filesystem boundaries are excluded
and counted. Same-device bind mounts are not distinguished and may be
traversed; do not rely on this check as a mount-boundary sandbox. Supply each
desired mounted evidence tree separately. Do not treat
live `/proc`, `/sys` or device trees as ordinary forensic files. Explicit
inputs resolving beneath `/proc`, `/sys` or `/dev` are refused.
An explicit symlink input root is also refused with exit 2, rather than
silently skipped.
Repeated directory identities, such as bind-mount cycles, are also excluded
and counted.

Reads can update access times on writable filesystems. Use a forensic copy
or appropriately read-only mount when preserving metadata matters.

Output uses input labels and relative paths rather than adding a hostname or
absolute root paths. Filenames can still be sensitive; inspect/redact reports
before sharing. `--output` creates a new mode-0600 file and refuses overwrite.
Reports include UTC start/end timestamps from the analysis host's clock,
tool version and the SHA-256 of the exact catalog bytes loaded. Record clock
skew separately. Basename observations can describe files or directories,
including the reported temporary-directory prefixes. Their optional `sha256`
is present only after successfully hashing a regular file; it is not an
exact catalog match. Only `match: "sha256"` means that match. Interpret
`match`, any `kind`, and the explanation, not just a match count.

| Exit | Meaning |
| --- | --- |
| 0 | No observations within declared scope and no recorded errors; **not** a clean-host verdict |
| 1 | Hash or basename observations requiring interpretation, not automatic infection |
| 2 | Error or incomplete check, even if observations were also found |

Report write or flush failures also exit 2; a valid JSON report may not be
available in that case. Check the process status as well as report contents.

The checker handles only `file_hashes` and `host_artifacts`. Network/image/runtime/correlation
fields support other investigation systems and are not checked by this
program. YARA provides a separate, limited content-detection layer.

## Schema maintenance

`schema_version: 1` groups incident metadata, sources, file hashes, basename
patterns, network values, image digests, runtime context and correlation identifiers. Indicators include unique IDs,
interpretations and references. `size_bytes: null` means unknown here, not
zero. Do not silently change a hash to make tests pass. Verify new values
against primary reports and independently acquired artifacts where possible.

A platform manifest with a known `parent_index_id` must reference a recorded
`image_index`. When the parent is unknown, omit that field and supply the
manifest's own repository, historical tags, platform, source and interpretation.
