# LiteLLM PrivCollect: incident analysis and detection toolkit

Evidence-led analysis, IoCs, YARA rules, and response guidance for the
**October 2026 LiteLLM 1.107.0 PrivCollect supply-chain compromise**.
`privcollect` is a name used inside the
observed payload, not a claim of threat-actor attribution or an official
campaign designation.

This project is limited to this incident. It does not combine the separate
March 2026 LiteLLM/TeamPCP incident or claim to identify every subsequent
payload. The goal is a reference others can independently check and improve,
not a claim that the project or any host has been certified safe.

The [incident report](docs/incident-report.md#sourcebuild-provenance) incorporates
the maintainers' October 23 attack-chain findings, which supersede the earlier
token-theft hypothesis. The [catalog guide](docs/ioc-guide.md#publisher-side-investigation-context)
separates publisher-side investigation indicators from downstream implant evidence.
Socket's [CI follow-up](docs/incident-report.md#ci-evidence-and-delivery-limits)
adds workflow evidence and limits on interpreting successful runs.

## Start here

| Need | Document or tool |
| --- | --- |
| Understand the event and attack sequence | [Incident report](docs/incident-report.md) |
| Check dates and source disagreements | [Timeline](docs/timeline.md), [evidence map](docs/evidence-map.md) |
| Obtain indicators and interpret their strength | [IoC guide](docs/ioc-guide.md), [machine-readable catalog](iocs/litellm-1.107.0.json) |
| Plan evidence collection and recovery | [Triage and response](docs/triage-and-response.md) |
| Run a scoped, offline file-indicator check | [IoC scanner](tools/scan_iocs.py) |
| Use content-based detection | [YARA rules](rules/litellm_11070.yar), instructions below |
| Understand validation and gaps | [Validation](VALIDATION.md) |
| Trace citations and contribute safely | [Sources](docs/references.md), [contribution guide](CONTRIBUTING.md) |

The Python helpers require Python 3.11 or later (tested with 3.12.3).
The file checker additionally requires POSIX descriptor-relative APIs;
see its [platform and traversal limits](docs/ioc-guide.md).

Read-only file-indicator scan, preferably on a trusted analysis host:

```sh
/usr/bin/python3 -I -S -B tools/scan_iocs.py /path/to/copied/evidence
```

The scanner does not execute samples, contact indicator endpoints, inspect
process memory, collect credentials, or remove files. Review its scope and
exit codes in the [IoC guide](docs/ioc-guide.md). It supplements, rather than
replaces, YARA and forensic investigation.

## YARA rules

Content-based rules for investigating the **October 2026** LiteLLM 1.107.0
wheel compromise. These are independently authored community-use rules, not
rules published or endorsed by the researchers cited below. They are not a
generic Linux malware scanner or a clean-host certification.

The project contains rules, inert synthetic tests, and documentation. It does
not contain full malware payloads, credentials, host logs, or private case
details. Rules and inert fixtures contain short public detection fragments.
Nothing is uploaded by its tools or test runner. License: MIT.

## Coverage and limitations

| Rule | Intended target | Important limitation |
| --- | --- | --- |
| `LiteLLM_11070_EncodedCollector` | The known compressed collector plus Python decode/execute markers | Tolerates some wrapper edits, not arbitrary changes or recompression of the embedded payload |
| `LiteLLM_11070_RemoteLoader` | Campaign anchor, remote-execution markers, and loader structure | Can miss renamed anchors/functions or altered endpoints; does not identify arbitrary downloaded payloads |
| `LiteLLM_11070_DecodedCollector` | Statically decoded `privcollect` source or bytecode retaining its strings | Does not automatically decode base64/zlib or inspect process memory |

Rules are case-sensitive, filename-independent, and limited to files smaller
than 2 MiB. They do not use exact whole-file hashes, YARA modules, external
variables, or global rules. Hashes in metadata are reference identifiers,
not detection conditions. The 12-byte `import cook` startup hook is not
classified on its own: an import statement alone does not establish that its
target module is malicious.

Source-code reports, rule files, harmless fixtures, and copied malware text
may match. A match means the selected content is present, not that it ran or
that the containing host is infected. A non-match does not clear a host.
Investigate every match in context; never automatically delete matches.

These rules target this incident, **not** the separate March 2026
LiteLLM/TeamPCP compromise. Unknown second stages, encrypted content,
significantly modified samples, and persistence elsewhere remain outside
their coverage.

## Safe use

Prefer a trusted analysis host or a read-only mounted forensic copy. Do not
launch Python, pip, or uv from an affected environment to inspect it: Python
startup hooks can execute before the requested command. Scanning these
files as data does not require importing them.

### Native YARA

Using a trusted installation of YARA 4.5.0 (the tested version):

```sh
yara -r -N -p 1 -z 2097151 rules/litellm_11070.yar /path/to/copied/evidence
```

`-N` avoids following symlinks; `-p 1` uses one scan thread and `-z` skips
files outside this rule set's size range. Record skipped files as unscanned,
not clean. Native YARA scans raw files; it does not
automatically unpack wheels/archives or decode the collector. Avoid `-s`
when reporting findings: matching strings can contain sensitive data. This
example performs file scanning, not PID/process-memory scanning. Check
stderr and scan completion, not just the presence or absence of matches.

### ClamAV's YARA support

```sh
clamscan --recursive --allmatch --suppress-ok-results --normalize=no \
  --alert-exceeds-max=yes --max-filesize=2M --max-scansize=64M \
  --follow-dir-symlinks=0 --follow-file-symlinks=0 \
  -d rules/litellm_11070.yar /path/to/copied/evidence
```

This loads **only these YARA rules**, not the default antivirus database.
`--normalize=no` avoids case/whitespace normalization changing YARA input.
ClamAV may unpack supported containers, unlike a raw native YARA scan.
Container contents, size limits, and parser support can therefore produce
different results. A file at or above the rules' 2 MiB boundary cannot match
these rules, even if the scanner reads it. `Heuristics.Limits.*` warnings are
coverage limitations, not malware confirmations.

ClamAV exit 1 indicates a detection but may coexist with read errors; inspect
warnings and the summary's error count too. `--suppress-ok-results` hides OK
lines without using `--infected`, which can hide some error details. Do not
use `--remove` or `--move` for investigative scans.

This ClamAV example retains the engine's default directory/container depth
limits and may cross filesystem boundaries. Select a copied evidence tree,
review effective limits and the final summary, and record excluded scope.
The offline checker's traversal policy does not apply to separate engine runs.

## Tests

Run from a trusted environment using system Python with startup hooks
disabled; the runner uses only the standard library:

```sh
/usr/bin/python3 -I -S tests/validate.py --engine yara
/usr/bin/python3 -I -S tests/validate.py --engine clamav
/usr/bin/python3 -I -S -B -m unittest discover -s tests -p 'test_*.py' -v
```

The default fixtures are inert text, not runnable malware. Tests check each
rule's string thresholds, negative controls, selected wrapper changes, and
the file-size boundary. Separate parser regression checks reject additional
limit alerts, unexpected detections, read errors, and inconsistent exit
statuses, including when an expected detection is also present. They are not
a representative enterprise clean
corpus and cannot establish a general false-positive rate.

For an authorized analyst who already possesses the public samples, add
`--samples /path/to/restricted/sample-directory`. Expected filenames are
`cook.py.evidence` and `sitecustomize.py.evidence`. The runner checks their
published SHA-256 values before using them. It parses source as data and
statically decodes bounded base64/zlib literals; it never imports, executes,
or compiles the sample. Temporary fixtures use `.txt` names under a private
directory and are removed when tests finish. No sample is downloaded or
distributed by this bundle. Do not run it against arbitrary untrusted
Python code or use a compromised interpreter.

See `VALIDATION.md` for the tested engine versions and results. Retest after
editing rules or changing engines; successful parsing alone does not prove
detection coverage.

A [public CPython reference-corpus workflow](VALIDATION.md#reproducible-public-reference-corpus)
also verifies a pinned archive and per-file manifest before scanning 685
nonempty files. It uses no private host data and does not install or execute
the corpus. Its limited zero-match result is not a general false-positive rate.

## Public research and engine documentation

See the [complete source register](docs/references.md) for source dates,
corrections and evidence boundaries, including the fixed workflow sources
and platform documentation used in the response guide.

- [JFrog: LiteLLM hijacked again](https://research.jfrog.com/post/litellm-hijacked-again/)
- [OpenSourceMalware: wheel analysis and decoded hashes](https://opensourcemalware.com/blog/litellm-1-107-0-pypi-wheel-contains-a-credential-stealer-and-persistent-python-backdoor)
- [SafeDep: credential stealer and backdoor](https://safedep.io/litellm-pypi-compromise-credential-stealer-backdoor/)
- [LiteLLM maintainers: October 23 attack-chain investigation](https://docs.litellm.ai/blog/security-incident-oct-21-2026-attack-chain)
- [Socket: pre-release CI secret-exfiltration timeline](https://socket.dev/blog/litellm-attack-timeline)
- [AISLE: detection timeline](https://aisle.com/blog/litellm-11070-on-pypi-shipped-a-credential-stealer)
- [Socket: package and container provenance analysis](https://socket.dev/blog/litellm-compromise)
- [Upwind: initial compromise report](https://www.upwind.io/feed/litellm-1-107-0-supply-chain-attack-malicious-code-found-in-pypi-package)
- [Wiz: affected containers and credential-use observations](https://www.wiz.io/blog/litellm-compromised-steals-credentials)
- [Original GitHub security report and discussion](https://github.com/BerriAI/litellm/issues/47826)
- [YARA rule documentation](https://yara.readthedocs.io/en/stable/writingrules.html)
- [YARA command-line documentation](https://yara.readthedocs.io/en/stable/commandline.html)
- [ClamAV YARA compatibility](https://docs.clamav.net/manual/Signatures/YaraRules.html)

References document the threat and engine behavior; they are not claims of
third-party validation or endorsement of this rule set.
