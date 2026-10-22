# Contributing and sharing safely

This project covers the October 2026 LiteLLM 1.107.0 PrivCollect incident.
New incidents require an explicit scope decision; do not silently merge their
indicators or attribution into this one.

## Evidence standard

For a substantive claim or IoC, supply the primary reference, publication or
observation date, artifact identity when applicable, interpretation, and
limitations. Distinguish reproduced results from source-reported facts and
inference. Add source identifiers to the catalog and
[source register](docs/references.md). A source's signature or provenance
record is not automatically proof of authorized publication.

Rule changes need positive controls, negative controls and tested coverage
limits. Keep false-positive discussion and engine versions current. Do not
weaken tests merely to make an unexpected detection disappear.

## Validation

Use a trusted analysis environment. No pip or project dependencies are needed
for the Python helpers; Python 3.11 or later is required (tested with 3.12.3).
Tests use the standard library. YARA and ClamAV are
separate executables and are not automatically installed.

```sh
/usr/bin/python3 -I -S -B -m unittest discover -s tests -p 'test_*.py' -v
/usr/bin/python3 -I -S -B tests/validate.py --engine yara
/usr/bin/python3 -I -S -B tests/validate.py --engine clamav
```

The optional hash-verified sample tests are described in the README. Never
execute samples to validate a signature. Do not commit full malicious
payloads, wheels, memory dumps, packet captures or derived malicious source.

For a repeatable public negative-reference check, use the pinned corpus
[manifest and commands](VALIDATION.md#reproducible-public-reference-corpus).
Keep archive downloads outside the checkout. Do not change pinned identities
to hide a failed integrity check or unexpected detection; investigate first.

Run `markdownlint '**/*.md'` before committing documentation. Line-length
enforcement is intentionally disabled; structural rules remain enabled.
Use an environment without inherited personal Markdownlint overrides;
`--config` can still merge settings from a user-level `.markdownlintrc`.
For Python, use an available Ruff executable with
`ruff check --no-cache --isolated --select E,F,B,I,UP --target-version py312 --line-length 120 tools tests`.

## Publication checklist

- Inspect the exact staged files and diff, including metadata and links.
- Exclude credentials, victim identifiers/IPs, internal paths, private repo
  or review references, operational logs and third-party collaboration data.
- Keep evidence and generated reports outside the repository where possible;
  `.gitignore` is a convenience, not a confidentiality boundary.
- Include only inert fixtures and public, attributable indicators. Explain
  that the static upload-header value is a published attacker-side marker,
  not an authentication credential supplied by a victim.
- Verify checksums for any **immutable release archive**. The source tree
  does not maintain a stale checksum list across edits; generate release
  checksums after freezing the release revision.
- Do not upload files to public scanning services or contact C2 endpoints
  without separate authority and a defensible investigative purpose.
- Have another reviewer verify technical claims, tool behavior and privacy.

Publishing a repository, issue, PR, release or external message is a separate
decision from preparing this source tree. No scripts in this project publish
anything or configure a remote repository.

## Changes and licensing

Use focused commits and explain what changed, why, and how it was tested.
Record material corrections in [CHANGELOG.md](CHANGELOG.md). Retain public
references without copying complete copyrighted research reports. Original
toolkit code and documentation use the [MIT license](LICENSE); cited research
and indicators are not represented as this project's original discoveries.
