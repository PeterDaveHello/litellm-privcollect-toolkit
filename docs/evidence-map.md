# Claims, evidence and confidence

Evidence levels describe support for a specific claim, not certainty about
an entire host. **Reproduced** means static/sample or tool behavior validated
by this toolkit; **source-reported** means attributed to the cited publisher;
**inference** and **unknown** must not be promoted into observed facts.

| ID | Claim | Evidence / status | Boundary |
| --- | --- | --- | --- |
| C01 | Two Python payloads match the published sample identities | Reproduced SHA-256 checks; [S1](references.md#s1), [S3](references.md#s3) | Identifies content, not execution or provenance authorization |
| C02 | Decoding the embedded literals produces the reported collector hashes | Reproduced bounded static decoding; [S3](references.md#s3) | No sample execution; not a general arbitrary-packer decoder |
| C03 | A matching `.pth` can invoke the collector during ordinary startup | Static hook plus Python mechanism; [S7](references.md#s7) | Startup flags and environment paths matter |
| C04 | The once-marker follows the successful-POST branch | Static control flow; [S1](references.md#s1) | Corroborate provenance; marker bytes can be copied, removed or forged |
| C05 | The loader can execute a remotely supplied second stage | Static control flow; [S1](references.md#s1) | Does not establish which code any host actually received |
| C06 | Seven wheels contain the implant | Source-reported cross-platform artifact comparisons; [S2](references.md#s2), [S4](references.md#s4) | This toolkit does not redistribute or independently re-download all seven wheels |
| C07 | Container provenance recorded a look-alike source owner | Source-reported provenance inspection; [S5](references.md#s5) | Maintainer workflow findings are separately attributed below |
| C08 | The sdist has a different risk meaning from the wheels | Source-reported absence of the three payload files and changed build configuration; [S2](references.md#s2) | Neither a payload verdict nor approval to build/install |
| C09 | These YARA rules work on the stated fixtures and engines | Reproduced tests in [VALIDATION.md](../VALIDATION.md) | Not an independent vendor certification or general false-positive estimate |
| C10 | A host without a current match is safe | **Unsupported** | Unknown variants, historical activity and unscanned scope remain |
| C11 | Windows CRLF variants have distinct identities | Reproduced LF-to-CRLF transformations match three published hashes; [S2](references.md#s2), [S5](references.md#s5) | Not independent acquisition of a Windows wheel; see catalog `size_basis` |
| C12 | Compromised credentials redirected the release workflow | Maintainer-reported; [S9](references.md#s9) | Credential-theft route remains partly hypothetical |

## What an investigation should retain

For every observation retain the acquisition time, timezone, acquisition
method/tool version, exact artifact hash, evidence location/access control,
and the analyst's interpretation separately. Record read errors and omitted
scope. Preserve the original before producing derived/decoded evidence.

A process observation needs PID **and** start identity, owner, executable,
parent/session context and relevant open descriptors. A PID alone can be
reused. A disk snapshot preserves storage, not necessarily process memory or
all buffered network evidence. These are collection-design considerations,
not claims that this repository contains a victim's evidence.

## Corrections and disagreements

Use a new dated revision for changed conclusions. Cite the specific evidence
that changes the claim and keep the earlier observation's scope visible.
Report absence of available telemetry as an evidence gap, never as absence
of the event itself. Public sharing must follow the
[contribution and privacy checklist](../CONTRIBUTING.md).
