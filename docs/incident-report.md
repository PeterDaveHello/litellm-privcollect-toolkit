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

In their 20:30 UTC update, maintainers report three compromised developer
credential sets, a privileged branch-protection bypass, and a workflow
redirected to attacker-controlled source; signed container images were still affected.
They suspect GitHub CLI tokens exposed in application response logs were
stolen through an internal LiteLLM deployment. Initial access to that
deployment remains unconfirmed. These are maintainer findings/hypotheses,
not an independently reproduced account investigation. [S9](references.md#s9)

Consequently, review artifact bytes, source identity and provenance together.
Do not equate an attestation's presence with an approved source, or assume a
container provenance observation proves the PyPI publishing path.

The catalog separately records the reported source repository, full Git
revision, release workflow run and RSA public-key fingerprint as
[correlation identifiers](ioc-guide.md#correlation-identifiers). They are not
file hashes or proof of execution. Maintainers also report deletion of
workflow-run records; surviving provenance and account logs must be assessed
with that evidentiary gap in mind. [S12](references.md#s12), [S9](references.md#s9)

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

Initial access to the internal deployment, operator identity, the downstream-victim set and
all historical second-stage behavior remain outside this project's evidence.
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
