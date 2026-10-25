# Public event timeline

Times below are **UTC on 2026-10-21** unless a different date is shown.
They come from the named publishers, not private victim telemetry.
This timeline was corrected on 2026-10-25 using the publisher's
2026-10-23 [S15](references.md#s15) report; it does not extend the downstream
artifact-exposure window back to the earlier credential compromise.
Socket's additional CI observations are separately attributed to
[S16](references.md#s16).

| Time | Source-reported event | Source / qualification |
| --- | --- | --- |
| 2026-05-27 18:53:14 | Agent Platform master key committed in `opencode.json` to public `LiteLLM-Labs/lite-harness`; not revoked after history rewrite | [S15](references.md#s15); exposure, not proof of attacker access that day |
| 2026-10-10 21:13–21:28 | Attacker used the master key against the Agent Platform API; the 21:27:10 response returned an owner's GitHub CLI OAuth token | [S15](references.md#s15); replaces the earlier response-log theft hypothesis |
| 2026-10-10 22:11:45 | Secret-exfiltration workflow runs on `ci-tmp-a351cc` in `BerriAI/litellm` | [S15](references.md#s15); [S16](references.md#s16) corroborates the workflow/branch, while the later `GH_TOKEN` approval use comes from the maintainer investigation |
| 2026-10-10 22:12:09 | Second workflow runs in `BerriAI/litellm-auto`, stealing `RELEASE_PLEASE_TOKEN` | [S15](references.md#s15); this token later deletes release-run records |
| 2026-10-10 22:14:14–22:14:31 | Attacker deletes both secret-exfiltration workflow runs | [S15](references.md#s15); distinct from the October 21 release-run deletions |
| 2026-10-12 12:08–12:30 | Further CI secret theft across repositories | [S15](references.md#s15); maintainers say these additional secrets were not used in the poisoned-artifact path and were addressed through rotation and auditing |
| 2026-10-12 about 12:16 | Socket reports a six-job workflow on `ci-tmp-4d8517` in `BerriAI/litellm` | [S16](references.md#s16); repository/environment evidence is separate from the broader maintainer timeline and does not prove every transmission succeeded |
| 2026-10-13 | Look-alike exfiltration domain registered | [S1](references.md#s1); reported registration history |
| 2026-10-18 | Dead-drop repository created | [S4](references.md#s4); reported repository history, not proof of an operational second stage |
| 2026-10-18–19 | Reported locator revisions contained `localhost:18909` and `test[.]test[.]com:18909` | [S5](references.md#s5), [S11](references.md#s11); not established as operational C2 destinations |
| 2026-10-20 09:15 | Locator revised to empty content, according to the issue author | [S11](references.md#s11); published revision history is not complete historical response telemetry |
| 06:59 | Timestamp of the commit referenced by the release tag | [S12](references.md#s12); author-reported commit time, not tag creation or installation time |
| 08:50 | Source-base commit on main | [S12](references.md#s12); author-reported commit time |
| 10:08:29–10:08:34 | Workflow change rejected with the second maintainer's token, then protection bypassed with the owner's token | [S15](references.md#s15); maintainer account/workflow investigation |
| 10:44 | 1.106.2 uploaded | [S13](references.md#s13); author-reported upload time, not blanket security certification |
| 10:46:39 | Staging workflow dispatched with source `Berri-AI/litellm` at `20535d8f` | [S15](references.md#s15); release orchestration, not artifact publication |
| 10:51:23–11:06:31 | Container build interval recorded in provenance | [S5](references.md#s5); independently retrieving that provenance is outside this toolkit's validation |
| 11:08:09–11:08:53 | Staging run finished, then production pipeline started | [S15](references.md#s15); workflow events, not artifact publication times |
| 11:11:18 | Production release approved with the second maintainer's stolen token | [S15](references.md#s15); account activity, not independent operator attribution |
| About 11:21 | Wheel build time reported | [S12](references.md#s12); author-reported maturin build time, not victim execution evidence |
| 11:39:51 | First release file uploaded | [S4](references.md#s4) |
| 11:40:13 | Last release file uploaded | [S4](references.md#s4); seven wheels plus one sdist |
| 11:43:05 | First detection in AISLE's system | [S4](references.md#s4); publisher-specific telemetry |
| 11:46:56 | Compromised container publication | [S9](references.md#s9) |
| 11:53:49–11:54:01 | Production and staging run records deleted with the third maintainer's stolen token | [S15](references.md#s15); reported loss of release-investigation records |
| 12:00:06 | All seven wheels flagged in AISLE's system | [S4](references.md#s4) |
| 12:06:41 | Public issue #47826 reports the compromise | [S15](references.md#s15); public reporting time, not first victim execution |
| 12:09:38 | Attacker pushes revert `285fbdc5` of the release-workflow change | [S15](references.md#s15); owner-token protection override, not defender-led recovery |
| 12:24:52 | Attacker force-pushes `main` back to `d687b69`, hiding the change and revert from visible history | [S15](references.md#s15); concealment, not artifact removal or host recovery |
| 13:01:44 | Empty locator response observed with HTTP 200 | [S5](references.md#s5); a point-in-time observation |
| 13:02 | Maintainers begin incident response | [S15](references.md#s15); separate from the attacker's earlier history changes |
| By 13:23 | PyPI release quarantined | [S15](references.md#s15); distinct from later observer checks |
| 13:40 | Dead-drop account and repository observed returning 404 | [S2](references.md#s2); observation, not a release-removal time or universal cutoff |
| By 13:51 | Affected GHCR tags unavailable; Docker Hub still affected | [S15](references.md#s15), [S9](references.md#s9) |
| 14:19 | Maintainers identify the release-workflow compromise and remove GitHub permissions | [S15](references.md#s15); publisher containment, not downstream recovery |
| 14:20 | Affected Docker Hub tags removed/repointed | [S9](references.md#s9) |
| 2026-10-23 | Maintainers publish the corrected attack-chain account | [S15](references.md#s15); current authority where earlier maintainer hypotheses conflict |

The artifact distribution times above are not execution cutoffs: cached packages,
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
