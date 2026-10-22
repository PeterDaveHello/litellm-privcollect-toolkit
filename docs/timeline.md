# Public event timeline

Times below are **UTC on 2026-10-21** unless a different date is shown.
They come from the named publishers, not private victim telemetry.

| Time | Source-reported event | Source / qualification |
| --- | --- | --- |
| 2026-10-13 | Look-alike exfiltration domain registered | [S1](references.md#s1); reported registration history |
| 2026-10-18 | Dead-drop repository created | [S4](references.md#s4); reported repository history, not proof of an operational second stage |
| 2026-10-18–19 | Reported locator revisions contained `localhost:18909` and `test[.]test[.]com:18909` | [S5](references.md#s5), [S11](references.md#s11); not established as operational C2 destinations |
| 2026-10-20 09:15 | Locator revised to empty content, according to the issue author | [S11](references.md#s11); published revision history is not complete historical response telemetry |
| 06:59 | Timestamp of the commit referenced by the release tag | [S12](references.md#s12); author-reported commit time, not tag creation or installation time |
| 08:50 | Source-base commit on main | [S12](references.md#s12); author-reported commit time |
| 10:08:29–10:08:34 | Workflow change rejected, then protection bypassed | [S9](references.md#s9); maintainer account/workflow investigation |
| 10:44 | 1.106.2 uploaded | [S13](references.md#s13); author-reported upload time, not blanket security certification |
| 10:51:23–11:06:31 | Container build interval recorded in provenance | [S5](references.md#s5); independently retrieving that provenance is outside this toolkit's validation |
| 11:11:18 | Production release approved with a second compromised developer credential set | [S9](references.md#s9); maintainer-reported account activity, not independent identity attribution |
| About 11:21 | Wheel build time reported | [S12](references.md#s12); author-reported maturin build time, not victim execution evidence |
| 11:39:51 | First release file uploaded | [S4](references.md#s4) |
| 11:40:13 | Last release file uploaded | [S4](references.md#s4); seven wheels plus one sdist |
| 11:43:05 | First detection in AISLE's system | [S4](references.md#s4); publisher-specific telemetry |
| 11:46:56 | Compromised container publication | [S9](references.md#s9) |
| 11:53:49–11:54:01 | Workflow-run records deleted with a third compromised developer credential set | [S9](references.md#s9); reported loss of release-investigation records |
| 12:00:06 | All seven wheels flagged in AISLE's system | [S4](references.md#s4) |
| 12:09:38–12:24:52 | Release workflow restored | [S9](references.md#s9); does not establish downstream artifact removal or host recovery |
| 13:01:44 | Empty locator response observed with HTTP 200 | [S5](references.md#s5); a point-in-time observation |
| By 13:23 | PyPI release removed | [S9](references.md#s9); distinct from later observer checks |
| 13:40 | Dead-drop account and repository observed returning 404 | [S2](references.md#s2); observation, not a release-removal time or universal cutoff |
| 13:51 | Affected GHCR tags unavailable; Docker Hub still affected | [S9](references.md#s9) |
| 14:20 | Affected Docker Hub tags removed/repointed | [S9](references.md#s9) |

These are distribution windows, not execution cutoffs: cached packages,
mirrors and previously pulled images can be installed or started later.
The affected floating tags included `latest`, `main-latest` and `main-stable`.
Additional GHCR variants were `litellm-database` and `litellm-non_root`;
their maintainer-reported index digest prefixes are not full identities.
The supplemental catalog adds Wiz-reported platform manifests for both
variants; their parent indexes remain unknown. See the [catalog guide](ioc-guide.md)
for index/platform distinctions and the later source-check boundary.
[S9](references.md#s9), [S5](references.md#s5), [S14](references.md#s14)

The S11 issue body checked on 2026-10-22 mentions a GitHub release publication
time of 11:50:24 UTC in a struck-through passage. S13 retracts the inference
that uploading to PyPI before publishing a GitHub release is itself anomalous.
The passage's version at the initial cutoff was not established, so its exact
release time is excluded from the timeline above. S12's 11:50:20 UTC Actions
start is a different event. [S11](references.md#s11), [S12](references.md#s12),
[S13](references.md#s13)

JFrog separately observed an empty dead-drop body at its inspection time,
while SafeDep and other reports describe later unavailability. Those
observations need not contradict one another. Neither reconstructs the
response received by a particular host earlier. [S1](references.md#s1),
[S2](references.md#s2)

For a victim timeline, separately preserve interpreter starts, package
installation records, file timestamps, process identity, egress records and
identity-provider activity. Normalize timezone and clock skew before
correlation. File mtimes, upload timestamps and first public reporting are
not interchangeable. Preserve conflicting observations rather than silently
choosing the most convenient one.
