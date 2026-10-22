# Triage and response guide

This is a decision aid, not an automated remediation script. Use trusted
tools, authorized access and your incident-response process. General planning
guidance is available in [NIST SP 800-61r3](references.md#s6).

## 1. Preserve access and evidence

- Stop new deployments of the affected release; identify artifact hashes,
  running image digests, cached wheels, builders and affected environments.
- Establish an independent management path before network restrictions.
  For a cloud VM, retain console access and account for required services.
- Preserve volatile process/network observations before terminating a
  confirmed implant when operationally safe. Preserve disk snapshots and
  relevant cloud/identity/egress logs with access controls and retention.
- Do not start the affected environment's Python, pip or uv as the first
  inspection step. Even a diagnostic command may process startup hooks.

Avoid publishing process environments, complete command lines, auth files,
browser stores, or memory dumps. They can contain secrets unrelated to this
incident. This toolkit does not collect those values.

## 2. Establish scope

Inspect known filenames and hashes with the [IoC scanner](ioc-guide.md), then
apply the [YARA rules](../README.md#yara-rules) to appropriate copied evidence.
Separate exact matches, lower-confidence path observations, and errors.
Inspect suspicious startup files as data; do not import them.
Include related `__pycache__/cook.*pyc`, `sitecustomize.*pyc` and legacy
bytecode locations when scoping remnants; their names alone do not prove
malicious content. [S11](references.md#s11)

Correlate the known lock path with a live holder rather than assuming a file
proves activity. If using native OS tools, inspect narrowly selected metadata
such as process identity and sockets; do not indiscriminately print `/proc`
environments or secret-bearing logs. A legitimate `sitecustomize.py`, Python
daemon, or metadata-service request is not individually proof of compromise.

Check other persistence locations and privileged access where authorized:
scheduled tasks, system/user services, shell startup files, SSH configuration,
new accounts/keys, containers and application-specific startup mechanisms.
Compare against trusted preincident baselines where available. Verification
against the affected host's own package database is only supporting evidence.

## 3. Investigate possible exfiltration and follow-on activity

Use existing proxy, DNS, flow, endpoint and application audit records to look
for the **specific** locator and upload paths in the [catalog](ioc-guide.md).
Do not visit attacker endpoints to test whether they still respond. Do not
blanket-block all GitHub raw hosting or the legitimate cloud metadata service
based on a shared hostname/address alone.

An HTTP success marker does not identify every stolen file. The application-
layer encryption further limits what a packet capture alone can disclose.
Absence of a marker, empty DNS logs, a current 404, or no current connection
does not reconstruct past behavior. [S1](references.md#s1)

Review identity-provider and cloud/repository/registry records for use of
exposed credentials, new grants, newly created credentials, privilege changes,
publishing activity and unexpected costs. Keep observed activity distinct
from the collector's theoretical reach.

Wiz reported use of stolen AWS instance-role credentials in some environments
between 16:20 and 17:01 UTC on 2026-10-21: `sts:GetCallerIdentity` followed by
`bedrock:ListFoundationModels`. Review the corresponding audit records and
correlate the principal, source, time and surrounding activity. These API
calls can also be legitimate; the report does not establish that every
affected environment experienced them or that paid model inference occurred.
[S14](references.md#s14)

## 4. Contain and recover deliberately

After preserving necessary evidence, remove or quarantine **confirmed**
malicious artifacts and caches, and terminate only positively identified
malicious processes. Do not delete every similarly named startup file or
kill every Python process. Removing files does not necessarily stop code
already loaded into a process.

Revoke/rotate reachable credentials from a trusted environment and inspect
secondary grants. Local logout is not server-side revocation. If arbitrary
remote code could have run, clearing the known files is not a trusted
baseline restoration. Rebuild affected environments/hosts where required by
the risk assessment; JFrog recommends forensic rebuilding. [S1](references.md#s1)

For a LiteLLM Proxy deployment, include provider keys stored in its database,
master/virtual keys and the `DATABASE_URL` password in the exposure assessment
and rotation plan. These may be reachable beyond individual shell variables;
review the service's actual privileges and database access. Also assess
instance/task role sessions and developer-tool OAuth sessions. This is a
precautionary scope, not proof that every listed secret was collected.
[S11](references.md#s11), [S5](references.md#s5)

Where immediate replacement is impractical, document a time-limited residual-
risk decision, restrict sensitive use, apply proportionate access/egress
controls without losing management access, and increase monitoring. Do not
label this exception a clean bill of health. Recovery releases must be
verified for both security and application compatibility, not selected solely
because a source says they lack this particular implant.

## Completion criteria and unresolved gaps

Record what was scanned, what was skipped, which identities were revoked,
which persistence mechanisms were checked, what baseline was restored, and
who accepts remaining uncertainty. Keep notification/legal obligations within
the organization's incident process; this toolkit does not determine them.

No scan result from this project alone establishes eradication, the exact
stolen plaintext, or the absence of historical second-stage execution.
