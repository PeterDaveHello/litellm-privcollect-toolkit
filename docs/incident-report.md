# Incident report: LiteLLM PrivCollect

**Scope:** the 2026-10-21 LiteLLM **1.107.0** distribution compromise.
**Status:** evolving public-source analysis; attribution unassigned.
**Audience:** responders, developers, package consumers and release engineers.

## Executive assessment

The release delivered a credential collector and a conditional remote-code
loader through Python startup files outside the normal `litellm/` package
directory. Starting a normally initialized interpreter in an affected
environment could trigger the implant without importing LiteLLM. A source-tag
review alone therefore could not establish wheel safety. [S1](references.md#s1)

The material concern is not only the vulnerable dependency: reachable secrets
and user data may have been collected, and a retrieved second stage could
perform actions beyond the fixed collector. Removing files or rotating one
key does not establish eradication. No claim is made that every exposed host
exfiltrated every targeted file or executed a second stage.

## Delivery and execution chain

```text
affected wheel / container image
  -> startup files installed in the Python environment
     -> cook.pth -> cook.py -> decode collector -> collect -> encrypted POST
     -> sitecustomize.py -> detached hourly loader
        -> fetch GitHub dead-drop text
        -> usable domain resolves?
           -> run embedded collector -> fetch /codepy -> execute response
```

The implant entries are `cook.pth`, `cook.py`, and `sitecustomize.py` under
the wheel's `litellm-1.107.0.data/purelib/` directory. The ordinary wheel
installer places them at the environment's library root. `RECORD` includes
their hashes: a self-consistent manifest proves internal consistency, not
trustworthiness. [S2](references.md#s2), [S3](references.md#s3)

### Collector

Static inspection of the hash-identified source shows a base64/zlib-encoded
program that calls itself `privcollect`. It targets credential files,
developer-tool configuration, readable process environments, browser stores,
shell history, and cloud-related data. Some collection paths depend on local
files, permissions, services or configuration; a target list is not an
exfiltration manifest. The public decoded hashes make that static-analysis
input reproducible without executing it. [S3](references.md#s3)

Collected JSON is encrypted with a random AES key; an embedded RSA public key
wraps that key before upload. Transport visibility alone therefore does not
normally reveal the stolen plaintext. The once-marker is written after the
POST helper observes HTTP 200; it does not enumerate successful collection
modules. [S1](references.md#s1)

### Loader and subsequent activity

The loader uses a lock, forks, detaches, suppresses standard streams and
repeats hourly. Its remote-execution branch depends on obtaining and resolving
a domain from a GitHub-hosted locator. The response from `/codepy` is executed
without a payload signature check. Public reports do not bound the content
of every historical second stage. [S1](references.md#s1)

The embedded loader collector lacks the standalone collector's once-marker
check, but both use `PRIVCOLLECT_ACTIVE`. The loader can inherit that guard
after normal `.pth` startup and skip collection while retaining remote-code
execution. Hourly polling is therefore not proof of hourly exfiltration.
[S1](references.md#s1), [S5](references.md#s5)

The fork-based loader path cannot complete on Windows as written; this does
not remove the separate startup collector risk. Python path ordering and
startup options can also affect which hooks execute. Avoid the overstatement
that every Python process everywhere on a host must have loaded the implant.

## Source/build provenance

The source archive lacks the three embedded payload files even though its
build configuration differs from the tag. Separately, Socket reports that
container provenance selected source owner `Berri-AI` rather than `BerriAI`,
and that the referenced source revision contains the matching implant.
The `data = "cook"` build-setting change is worth examining, but is not by
itself a malware signature. The sdist's missing payload files do not make it
an approved recovery artifact. [S2](references.md#s2), [S5](references.md#s5)

### Publisher-side credential chain: corrected account

The maintainers' October 23 investigation is the current account and supersedes
the October 21 response-log token-theft hypothesis. A master key exposed in
the public `LiteLLM-Labs/lite-harness` repository on May 27 remained valid
after the history was rewritten. On October 10, it allowed the attacker to
read agent configuration containing an owner's GitHub CLI OAuth token from
the separate Agent Platform API. Exposure in May does not establish when the
attacker first acquired the key. [S15](references.md#s15)

| Credential | Maintainer-reported acquisition | Maintainer-reported use |
| --- | --- | --- |
| Owner's GitHub CLI OAuth token | Agent Platform API response | CI secret theft, protection overrides, source redirection, staging dispatch and concealment |
| Second maintainer's GitHub CLI OAuth token | CI secret `GH_TOKEN` in `BerriAI/litellm` | Production gate approval |
| Third maintainer's GitHub CLI OAuth token | CI secret `RELEASE_PLEASE_TOKEN` in `BerriAI/litellm-auto` | Deleting release-run records |

This is a source-reported reconstruction, not independently reproduced
account forensics. The use of stolen, already-issued tokens does not establish
a general bypass of GitHub 2FA. Once one attacker controlled multiple tokens,
different account names no longer established independent approvals.
[S15](references.md#s15)

The legitimate pipeline signed and published artifacts from the substituted
source. The subsequent revert and force-push were attacker concealment, not
defender recovery. The [timeline](timeline.md) distinguishes this upstream
activity from downstream distribution and execution. [S15](references.md#s15)

Consequently, review artifact bytes, source identity and provenance together.
Do not equate an attestation's presence with an approved source, or assume a
container provenance observation proves the PyPI publishing path.

The catalog separately records the reported source repository, full Git
revision, release workflow run and RSA public-key fingerprint as
[correlation identifiers](ioc-guide.md#correlation-identifiers). They are not
file hashes or proof of execution. Maintainers also report deletion of
workflow-run records; surviving provenance and account logs must be assessed
with that evidentiary gap in mind. [S12](references.md#s12), [S15](references.md#s15)

### CI evidence and delivery limits

Socket reports two recovered secret-exfiltration workflows in
`BerriAI/litellm`, with October 10 and October 12 execution supported by
Actions performance metrics, repository activity and environment deployment
records. The second workflow targets additional environment-scoped secrets.
Its separate webhook resource and secret set should not be collapsed into a
retry of the first workflow. [S16](references.md#s16)

Direct static inspection of the fixed-revision workflow files confirms:

| Workflow | Jobs | Explicit GitHub Environment bindings | Distinct referenced secret names |
| --- | --- | --- | --- |
| October 10, [S17](references.md#s17) | 1 | 0 | 6 |
| October 12, [S18](references.md#s18) | 6 | 5 | 14 additional names |

These are source-code properties, not observations of the jobs' runtime
values. The 20 distinct names include an App ID, host and port fields as
well as credentials. A repeated name can resolve to different values in
different Environments, so the name count is not a count of valid stolen
credentials. No workflow was executed for this inspection.
[S17](references.md#s17), [S18](references.md#s18)

The maintainers explicitly state that the October 12 additional secrets,
including the activity associated with `1a6e3c1`, were not involved in the
path to the poisoned artifacts; they report rotation and access-log review
for those secrets. This is additional activity within the same intrusion,
not an established prerequisite for the October 21 malicious release.
[S15](references.md#s15)

The workflows suppress transmission errors with `|| true`. A successful job
therefore establishes neither collector receipt nor delivery of every
referenced secret. Secret names in workflow source describe targets, not a
complete exfiltration manifest. Socket's independent visibility does not
cover the initial key theft or all later uses of those credentials; S15
supplies the current maintainer account for the confirmed chain above.
These evidence limits do not restore the superseded initial-access theory.
[S17](references.md#s17), [S18](references.md#s18),
[S16](references.md#s16), [S15](references.md#s15)

## Impact and unanswered questions

| Question | Defensible conclusion |
| --- | --- |
| Can keys and non-secret data be exposed? | The collector includes both; actual contents are host-specific. |
| Does a known file hash prove execution? | No; it identifies bytes, including archived evidence copies. |
| Does a once-marker prove every key was stolen? | No; it supports the upload-success branch when corroborated, not a complete file list. |
| Does a stale lock file prove a live daemon? | No; identify an actual lock holder and process identity. |
| Does unavailable C2 make a host safe? | No; it says nothing conclusive about prior execution or the independent collector. |
| Is root compromise established? | No. A remote payload could exercise available privileges; investigate the host's actual privileges and activity. |
| Is a negative scan a clean-host certificate? | No; coverage limits and unknown code remain. |

Operator identity, the downstream-victim set and all historical second-stage
behavior remain outside this project's evidence. The publisher-side initial
access account above is source-reported, not independently reproduced here.
There is no established link here to the March TeamPCP incident.

## Detection and investigation

The [IoC catalog](../iocs/litellm-1.107.0.json) identifies known bytes and
observable artifacts. The [YARA rules](../rules/litellm_11070.yar) add limited
content-based detection. Neither is a general malware detector. See the
[evidence map](evidence-map.md), [timeline](timeline.md), and
[response guide](triage-and-response.md) before interpreting a result.

Technique mappings are descriptive: dependency compromise
[T1195.001](references.md#s8) and Python startup hooks
[T1546.018](references.md#s7). They are not actor attribution.
