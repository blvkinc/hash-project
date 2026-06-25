# Evaluation Plan

This file turns the dissertation aims into concrete experiments and evidence.

## Evaluation Questions

1. Can IntegrityGuard detect meaningful file changes that indicate reverse-shell,
   RCE, persistence, or dependency compromise behavior?
2. Can it reduce notification volume compared with a naive hash-mismatch FIM?
3. Can the system preserve useful context across renames, rescans, and baseline
   memory construction?
4. Can the agent layer provide useful explanation without creating a processing
   bottleneck?
5. Can the system be deployed and operated on a new host without hidden local
   state?

## Baseline Comparison

Use a simple comparator throughout the evaluation:

- Naive FIM baseline: every hash mismatch is treated as an equal alert.
- IntegrityGuard: hash mismatch is enriched with file identity, registry tier,
  content analysis, MemPalace context, and notification policy.

This makes the dissertation claim measurable. The project is not only trying to
detect more events; it is trying to produce fewer low-value notifications while
preserving high-risk alerts.

## Test Groups

### Group A: Baseline Integrity Capture

Purpose:

Prove that the system captures a clean baseline before analysis.

Evidence:

- Number of files discovered.
- Hash rate and files per second.
- Database row counts for file records, directory nodes, registry entries, and
  scan sessions.
- Scan progress screenshots or API JSON.

Metrics:

- Total files.
- Total bytes hashed.
- MB/s hash rate.
- Files/s.
- Database commit count and total commit latency.

### Group B: Benign Change Suppression

Purpose:

Measure whether routine changes are silently recorded or batched instead of
creating unnecessary critical alerts.

Scenarios:

- Text file modification.
- Log file append.
- Browser profile cache update.
- Normal package install/update in a monitored project.

Metrics:

- Total changes.
- Immediate notifications.
- Batched notifications.
- Silent/recorded events.
- Notification reduction ratio.

### Group C: Reverse Shell and RCE Payload Detection

Purpose:

Evaluate the core motivation: files that introduce reverse-shell or RCE behavior
should be detected and explained.

What this represents:

This group models the author's original observation that simple reverse-shell
payloads can be created more easily than expected and may not always be stopped
by antivirus tooling. The dissertation should present this as a defensive
motivation, not as exploit guidance.

Safe scenario design:

- Use inert laboratory files containing representative strings and API patterns.
- Do not connect to a live command-and-control server.
- Do not run malware or uncontrolled exploit code.
- Use comments or disabled code where possible while preserving detectable
  indicators.

Example indicators:

- `cmd.exe`, `/bin/sh`, `powershell`, or `bash -i` execution.
- `child_process` in JavaScript.
- `socket.connect`, `WSAConnect`, `WinHTTP`, or `WinINet`.
- `curl`, `wget`, or encoded PowerShell payload patterns.
- Persistence hints such as startup folders, services, cron, scheduled tasks,
  or registry Run keys.

Expected outcome:

- Content analysis detects suspicious behavior.
- File registry role influences severity.
- MemPalace agent explains why the content is risky.
- The user receives a high or critical notification when warranted.

### Group D: Dependency/Supply-Chain Compromise Simulation

Purpose:

Evaluate whether the system can detect developer-library compromise effects,
especially npm-style install-time compromise.

What this represents:

This group models cases where trust is inherited through package managers. The
system should show that local file monitoring can identify the host-level effects
of dependency compromise: changed manifests, lockfiles, install scripts,
generated files, source-code modifications, and suspicious execution/network
patterns.

Safe scenario design:

- Create a local test project.
- Add a benign dependency update scenario.
- Add a synthetic local package with a disabled or inert `postinstall` script
  containing suspicious patterns.
- Modify package files to include network callback or command execution strings.
- Do not publish packages and do not execute harmful payloads.

Evidence:

- Changes to `package.json`, lockfiles, and package directories.
- Timeline entries showing file creation/modification.
- Analysis showing dependency role, content findings, and notification priority.
- Agent drawer evidence: content inspection, memory search, trusted-change
  evaluation, and recommended actions.

Expected outcome:

- Benign dependency changes should not flood alerts.
- Suspicious install-time behavior should produce meaningful notification
  context.

### Group E: Rename and Timeline Continuity

Purpose:

Prove that a file rename updates the same timeline rather than creating an
unrelated file record.

Scenarios:

- Rename a monitored file.
- Modify the renamed file.
- Compare the file timeline before and after rename.

Metrics:

- Stable file identity count.
- Number of timeline events on the same record.
- Whether duplicate file cards appear.

### Group F: Agent and MemPalace Context

Purpose:

Prove that the agent is not just a label. It should retrieve memory, inspect
content, and add useful contextual reasoning.

Scenarios:

- Baseline scan builds SQL records.
- Build MemPalace baseline memory.
- Trigger a high-risk change.
- Inspect `/api/agent/activity` and UI drawer output.

Metrics:

- Agent investigations run.
- Agent investigations skipped due to policy.
- Memory hits.
- Tools used.
- Backlog depth at investigation time.

### Group G: Deployability

Purpose:

Prove that the artefact can be installed on a new host.

Evidence:

- `scripts/bootstrap.ps1 -Dev`
- `scripts/bootstrap.sh --dev`
- `scripts/run.ps1`
- `scripts/run.sh`
- Docker build through GitHub Actions.
- `/api/health`, `/api/stats`, and `/api/agent/activity` responses.

## Dissertation Metrics Table

| Metric | Formula or collection method | Used in chapter |
| --- | --- | --- |
| Notification reduction ratio | 1 - immediate alerts / total changes | Evaluation |
| True positive rate | Detected malicious scenarios / total malicious scenarios | Evaluation |
| False negative rate | Missed malicious scenarios / total malicious scenarios | Evaluation |
| False positive rate | Benign scenarios escalated / total benign scenarios | Evaluation |
| Hash throughput | MB hashed / hash time | Evaluation |
| Scan throughput | Files discovered / elapsed time | Evaluation |
| Agent investigation rate | Investigations run / eligible events | Evaluation |
| Memory usefulness | Memory hits and qualitative explanation quality | Discussion |
| Deployment success | Fresh clone reaches health endpoint | Evaluation |

## Ethics and Safety

All adversarial tests must be defensive, local, and controlled. The dissertation
should describe reverse shells and malicious package behavior at a conceptual
level. Test files should be inert, disabled, or synthetic. No live malware, live
credential theft, live command-and-control infrastructure, or uncontrolled
propagation should be used.

Record enough detail for reproducibility without publishing operational payloads.
For example, record which indicators were present, which files changed, and how
the system classified them, but avoid publishing runnable attack chains.
