# Source register

Initial external-evidence cutoff: **2026-10-22 00:24:43 UTC**. Pages may
change after this time. This cutoff describes source availability, not
subsequent access or test execution. Dates below describe the publisher's
event/report, not a victim's execution timeline.
No attacker endpoint was contacted to prepare this project. References are
not endorsements of these rules or this toolkit.

## S1

**JFrog Security Research — LiteLLM Hijacked Again: Malicious 1.107.0 Wheels
Steal Credentials and Load Remote Code** (2026-10-21).

<https://research.jfrog.com/post/litellm-hijacked-again/>

Primary reverse-engineering report: startup hooks, collector, conditional
hourly loader, encryption, Docker digest and investigation limits. Its
zero-byte dead-drop observation is a point-in-time result, not a historical
absence of C2 activity. It does not establish the initial account compromise.

## S2

**SafeDep — Compromised LiteLLM 1.107.0 on PyPI Installs a Credential Stealer
and Backdoor** (2026-10-21).

<https://safedep.io/litellm-pypi-compromise-credential-stealer-backdoor/>

Primary artifact comparison and UTC timeline; seven wheel hashes plus the
sdist hash. Its 13:40 UTC account/repository 404 observation does not establish
the release-removal time or determine every host's exposure window.
Earlier versions reported without this implant are
not thereby certified free of unrelated vulnerabilities.

## S3

**OpenSourceMalware — LiteLLM 1.107.0 PyPI Wheel Contains a Credential Stealer
and Persistent Python Backdoor** (2026-10-21).

<https://opensourcemalware.com/blog/litellm-1-107-0-pypi-wheel-contains-a-credential-stealer-and-persistent-python-backdoor>

Primary analysis of the macOS x86-64 wheel, payload hashes and decoded-source
hashes. Operator-panel observations are not needed for this toolkit's
detection claims; the project does not access that infrastructure.

## S4

**AISLE Research — AISLE Found Compromised LiteLLM Package 3 Minutes After
Release** (2026-10-21).

<https://aisle.com/blog/litellm-11070-on-pypi-shipped-a-credential-stealer>

Publisher-reported detection timestamps and artifact hashes. Detection times
describe that publisher's systems, not universal detection coverage.

## S5

**Socket — LiteLLM PyPI Package and Docker Images Compromised to Steal Cloud
and AI Credentials** (2026-10-21).

<https://socket.dev/blog/litellm-compromise>

Primary investigation reporting retrieved container provenance and the
hyphenated source owner `Berri-AI`, its full revision, builder run,
platform manifests, RSA-4096 public-key fingerprint and runtime caveats.
See S9 for the later maintainer account of the release-workflow compromise.
This toolkit has not independently reproduced the registry-provenance audit.

## S6

**NIST SP 800-61 Rev. 3 — Incident Response Recommendations and Considerations
for Cybersecurity Risk Management** (2025-04).

<https://csrc.nist.gov/pubs/sp/800/61/r3/final>

General incident-response planning reference, not a report about this event.

## S7

**MITRE ATT&CK — Python Startup Hooks (T1546.018)**.

<https://attack.mitre.org/techniques/T1546/018/>

Technique vocabulary for the startup mechanism; sharing a technique does not
establish common attribution with other campaigns.

## S8

**MITRE ATT&CK — Compromise Software Dependencies and Development Tools
(T1195.001)**.

<https://attack.mitre.org/techniques/T1195/001/>

Technique vocabulary for dependency delivery, not proof of the precise
publisher-side access path.

## S9

**LiteLLM maintainers — Contained: Oct 21, 2026 LiteLLM release v1.107.0
Compromised** (2026-10-21; revision marked 20:30 UTC).

<https://docs.litellm.ai/blog/security-incident-oct-21-2026>

Maintainer account of release compromise, removal times and remaining uncertainty.
Containment of distribution does not certify downstream recovery.

## S10

**Upwind Research — LiteLLM 1.107.0 Supply Chain Attack: Malicious Code Found
in PyPI Package** (2026-10-21).

<https://www.upwind.io/feed/litellm-1-107-0-supply-chain-attack-malicious-code-found-in-pypi-package>

Primary discovery report linking to S11, with startup-hook and remote-loader
analysis. Discovery claims are publisher-attributed, not a ranking established
by this project.

## S11

**BerriAI/litellm issue #47826 — security report by LidorMachluf** (2026-10-21).

<https://github.com/BerriAI/litellm/issues/47826>

Original public report and evolving discussion. The issue body documents
bytecode remnants, proxy-database exposure and container variants. Comments
are not automatically maintainer-confirmed facts; cite the relevant author
and revision when using them.

## S12

**LidorMachluf — container provenance and correlation follow-up on issue #47826**
(2026-10-21 12:57:19 UTC).

<https://github.com/BerriAI/litellm/issues/47826#issuecomment-6316601885>

The GitHub API reports identical creation and update timestamps for this
comment. It records the full hyphenated source repository/revision, release
workflow-run identifier and RSA-4096 public-key fingerprint. It also reports
the release-tag commit at 06:59 UTC, the main source-base commit at 08:50 UTC,
and an approximate maturin wheel build time of 11:21 UTC. These are the
comment author's reported observations, not an independent provenance audit
by this toolkit. S5 provides corroborating reporting but no precise revision
timestamp for the article was established.

## S13

**LidorMachluf — release-order correction on issue #47826**
(2026-10-21 13:24:25 UTC).

<https://github.com/BerriAI/litellm/issues/47826#issuecomment-6317194658>

The GitHub API reports identical creation and update timestamps for this
comment. It reports the 1.106.2 PyPI upload at 10:44 UTC and retracts the
inference that a PyPI upload preceding its GitHub release is itself anomalous.
The report's claims about unaffected artifacts are not general security
certification by this toolkit.

## S14

**Wiz Research — LiteLLM Compromised, Steals Credentials** (2026-10-21).

<https://www.wiz.io/blog/litellm-compromised-steals-credentials>

Primary research reporting use of stolen AWS instance-role credentials in
some environments during 16:20–17:01 UTC. Its update log marks the addition
of observed post-exploitation activity at 19:05 UTC and a root-cause update
at 21:45 UTC. The AWS activity is Wiz's observation, not activity reproduced
by this toolkit or proof that every affected environment experienced it.

The supplemental catalog also records four full platform manifests from its
Affected Instances table. The page marks an IOC-table update at 14:05 UTC,
but no historical snapshot establishes when these four rows were added.
They are later source checks, not claims of independently retrieved registry
provenance or confirmed availability before the initial cutoff. The page does
not provide their parent index identities.

## Supplemental source access record

The following sources were accessed on **2026-10-22 UTC**, with this follow-up
check completed at **12:51:48 UTC**, after the initial evidence cutoff.
Earlier access times were not recorded. Page access and the publisher's
revision metadata do not independently verify every claim or reconstruct a
historical page version. Unknown revision times remain unknown.

| Source | Access date (UTC) | Revision information available from the source |
| --- | --- | --- |
| [S1](#s1) | 2026-10-22 | An October 22 update is marked; no precise update time established |
| [S2](#s2) | 2026-10-22 | October 21 publication date; exact content revision not established |
| [S3](#s3) | 2026-10-22 | Publication shown as 2026-10-21 13:36:10.344 UTC; exact revision not established |
| [S4](#s4) | 2026-10-22 | October 21 publication date; exact revision not established |
| [S5](#s5) | 2026-10-22 | Exact article revision not established |
| [S6](#s6) | 2026-10-22 | Final publication history entry: 2025-04-03 |
| [S7](#s7) | 2026-10-22 | Page marks last modified 2025-10-21 |
| [S8](#s8) | 2026-10-22 | Page marks last modified 2026-10-06 |
| [S9](#s9) | 2026-10-22 | Incident statement revision marked 2026-10-21 20:30 UTC |
| [S10](#s10) | 2026-10-22 | October 21 publication date; update section has no precise revision time |
| [S11](#s11) | 2026-10-22 | Mutable issue body; a version at the initial cutoff was not captured |
| [S12](#s12) | 2026-10-22 | API creation and update both 2026-10-21 12:57:19 UTC |
| [S13](#s13) | 2026-10-22 | API creation and update both 2026-10-21 13:24:25 UTC |
| [S14](#s14) | 2026-10-22 | Last listed article update: 2026-10-21 21:45 UTC; individual digest-row history unavailable |

## Tool documentation

- [YARA rules](https://yara.readthedocs.io/en/stable/writingrules.html)
- [YARA command line](https://yara.readthedocs.io/en/stable/commandline.html)
- [ClamAV YARA compatibility](https://docs.clamav.net/manual/Signatures/YaraRules.html)
- [ClamAV scanner source and options](https://github.com/Cisco-Talos/clamav/blob/clamav-1.5.4/docs/man/clamscan.1.in)

## Updating this register

Add the publication date, URL, specific supported claim, and what was actually
verified. Record actual access times and source-provided revision times when
available; do not infer a content revision from HTTP cache metadata or an
issue's general activity timestamp. Keep observations distinct from inferences. Do not silently replace
an older observation with a new endpoint status. Avoid copying full articles,
malware payloads, third-party logs or victim records into this repository.
