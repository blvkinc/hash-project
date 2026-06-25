# Expanded Dissertation Table of Contents

This document is a detailed structure map for the final MSc dissertation. It is
designed to be used as the main writing scaffold before converting the work into
the university dissertation template.

Working title:

IntegrityGuard: Context-Aware File Integrity Monitoring for Developer
Workstations

Target length:

Approximately 15,000 words, excluding references, appendices, and front matter.
The word counts below are guidance, not strict limits.

## Dissertation Argument in One Line

Traditional file integrity monitoring can show that a file changed, but modern
developer environments need a system that can explain why a change matters,
especially when the change resembles reverse-shell, RCE, persistence, or
software supply-chain compromise behaviour.

## Full Table of Contents

### Front Matter

#### Title Page

Purpose:

Identify the project, author, programme, institution, supervisor, and submission
date.

Expected content:

- Dissertation title.
- Student name and number.
- Programme: MSc Ethical Hacking.
- Institution: Abertay University.
- Supervisor details if required.
- Submission date.

#### Declaration

Purpose:

Confirm academic ownership and compliance with university requirements.

Expected content:

- Standard declaration text from the dissertation template.
- Confirmation that the work is original except where referenced.
- Confirmation that generative AI use is declared where required.

#### Acknowledgements

Purpose:

Briefly acknowledge academic, technical, or personal support.

Suggested length:

100 to 200 words.

#### Abstract

Suggested length:

250 to 350 words.

Purpose:

Summarise the entire dissertation as a standalone academic overview.

Recommended structure:

1. State the problem: traditional FIM detects change but often lacks context.
2. State the motivation: reverse-shell/RCE payloads and software dependency
   compromise can affect developer workstations before users notice.
3. State the artefact: IntegrityGuard, a local-first context-aware FIM system.
4. State the approach: hash-first baseline, tiered registry, content analysis,
   MemPalace context, agent investigation, and notification design.
5. State the evaluation: performance, benign changes, suspicious payload
   indicators, dependency compromise simulation, rename continuity, and
   deployability.
6. State the contribution: fewer low-value notifications and more meaningful
   high-risk alerts.

#### Table of Contents

Purpose:

Generated from final chapter headings.

#### List of Figures

Suggested figures:

- Figure 1: High-level system architecture.
- Figure 2: Baseline scan and hashing pipeline.
- Figure 3: File-change analysis pipeline.
- Figure 4: MemPalace agent investigation flow.
- Figure 5: Notification severity and batching model.
- Figure 6: Database and file identity model.
- Figure 7: UI dashboard and agent drawer.
- Figure 8: Evaluation scenario workflow.

#### List of Tables

Suggested tables:

- Table 1: Objectives mapped to chapters and evaluation evidence.
- Table 2: Functional and non-functional requirements.
- Table 3: Literature review source matrix.
- Table 4: Threat model and in-scope behaviours.
- Table 5: File tier model.
- Table 6: Hashing strategy comparison.
- Table 7: Evaluation scenario matrix.
- Table 8: Notification reduction results.
- Table 9: Reverse-shell/RCE indicator results.
- Table 10: Dependency compromise simulation results.
- Table 11: Deployability checklist.

#### Abbreviations, Symbols, and Notation

Suggested entries:

- API: Application Programming Interface.
- AV: Antivirus.
- BLAKE3: Cryptographic hash function used for verification.
- C2: Command and control.
- DB: Database.
- EDR: Endpoint Detection and Response.
- FIM: File Integrity Monitoring.
- LLM: Large Language Model.
- RCE: Remote Code Execution.
- SOC: Security Operations Centre.
- SQL: Structured Query Language.
- UI: User Interface.
- XXH3: High-speed non-cryptographic hash function.

## Chapter 1: Introduction

Suggested length:

1,500 to 1,800 words.

Chapter purpose:

Introduce the security problem, the project motivation, the research aim,
objectives, research questions, and the dissertation structure.

### 1.1 Background and Context

Suggested length:

250 to 350 words.

What to write:

Explain that modern systems are not static. Developer machines constantly change
because of package managers, build tools, scripts, dependency updates, browser
profiles, logs, caches, and operating system activity. Traditional FIM is useful
because it records file changes, but raw file-change evidence is not enough.

Key points:

- File changes can be benign, suspicious, or critical.
- Developer workstations are attractive targets because they store source code,
  secrets, tokens, SSH keys, and build credentials.
- Package managers and build scripts can introduce code through normal workflow.
- Monitoring file content and file identity provides a different signal from
  antivirus alone.

Evidence to cite:

- Kim and Spafford for foundational FIM.
- OSSEC/Wazuh or Microsoft FIM for modern host monitoring.
- MITRE ATT&CK for persistence and execution behaviours.

### 1.2 Practical Motivation

Suggested length:

250 to 350 words.

What to write:

Explain the personal and practical motivation in academic language. The key idea
is that controlled ethical-hacking experimentation showed how simple
reverse-shell or RCE-like behaviours can be introduced into files and may not
always be stopped by antivirus. The second motivation is the rise of compromised
developer libraries and dependency-chain attacks.

Tone:

Keep this defensive. Do not describe how to build a payload. Focus on what a
defender needs to detect: command execution, network callbacks, persistence,
credential access, and suspicious install-time scripts.

Key points:

- Antivirus is necessary but not sufficient.
- A file may become risky before it is executed.
- Local file monitoring can catch changes earlier in the attack chain.
- Supply-chain compromise can arrive through trusted workflows.

Evidence to cite:

- MITRE ATT&CK execution and persistence techniques.
- Ohm et al. on malicious OSS packages.
- Zimmermann et al. on npm ecosystem risk.
- NVD CVE-2024-3094 and XZ Utils analysis as a case study.

### 1.3 Problem Statement

Suggested length:

250 to 300 words.

What to write:

Define the exact problem the project addresses.

Recommended framing:

Traditional FIM answers "did the file change?" but not "does this change matter
to the user?" Naive systems can create alert fatigue by reporting too many
low-value changes. At the same time, purely path-based or hash-based monitoring
can miss why a file change is security-relevant. The problem is therefore a
combined integrity, context, analysis, and notification problem.

Problem dimensions:

- Scale: many files can be scanned and monitored.
- Context: file path, role, tier, and history matter.
- Content: source code, scripts, and configs can contain risky behaviours.
- Notification: alerts must be meaningful and readable.
- Deployment: the system should work on a new host without fragile local setup.

### 1.4 Aim

Suggested length:

100 to 150 words.

Recommended aim:

This project aims to design, implement, and evaluate a local-first,
context-aware file integrity monitoring system that detects and explains
meaningful security-relevant file changes, particularly reverse-shell/RCE,
persistence, and software dependency compromise indicators, while reducing
notification fatigue.

### 1.5 Objectives

Suggested length:

250 to 350 words.

Recommended objectives:

O1. Implement a cross-platform file integrity monitor that can scan directories,
hash files, and create a baseline in SQLite.

O2. Optimise baseline scanning so large directory trees can be captured quickly
using metadata-first reconciliation and hybrid XXH3/BLAKE3 hashing.

O3. Preserve file identity across modifications, deletions, and renames so the
timeline remains meaningful.

O4. Build a tiered file registry that classifies files by semantic role,
criticality, and expected change behaviour.

O5. Add content-aware analysis for suspicious source code, scripts,
configuration changes, reverse-shell indicators, RCE indicators, persistence
signals, and dependency compromise patterns.

O6. Integrate MemPalace-backed contextual memory and an embedded agent that can
investigate high-risk events using file history, role, content, and related
memory.

O7. Design professional notification handling that prioritises urgent events,
batches lower-risk events, and presents explanations in readable form.

O8. Evaluate the system through controlled benign, suspicious, dependency
compromise, performance, usability, and deployment scenarios.

### 1.6 Research Questions

Suggested length:

250 to 350 words.

Recommended research questions:

RQ1. Can a tiered, context-aware FIM pipeline reduce notification volume compared
with a naive hash-mismatch monitor while preserving high-risk alerts?

RQ2. Can local content analysis identify file changes that resemble
reverse-shell, RCE, persistence, or dependency compromise behaviours?

RQ3. Does persistent file identity improve the quality of file timelines,
especially after renames and repeated scans?

RQ4. Does MemPalace-backed agent context improve the explanation quality of
high-risk file-change alerts?

RQ5. Can the system remain usable and performant when scanning large directory
trees?

RQ6. Can the artefact be deployed on a new system using documented scripts,
Docker, and reproducible setup steps?

### 1.7 Contributions

Suggested length:

250 to 300 words.

What to write:

List what the project contributes as an artefact and as a dissertation.

Suggested contributions:

- A working local FIM application.
- A hash-first baseline approach using fast comparison and verification hashes.
- A file identity model that preserves timeline continuity across renames.
- A persistent file registry that classifies files by role and criticality.
- Content-aware detection for suspicious code and dependency compromise
  patterns.
- A MemPalace-backed agent investigation layer.
- Notification handling designed around alert fatigue and readability.
- An evaluation framework for measuring detection, notification reduction,
  performance, and deployability.

### 1.8 Dissertation Structure

Suggested length:

150 to 200 words.

What to write:

Briefly describe what each chapter contains.

## Chapter 2: Literature Review and Background

Suggested length:

2,500 to 3,000 words.

Chapter purpose:

Build the academic foundation for the project and identify the research gap. The
chapter should not be a list of summaries. Each section should lead toward the
argument that IntegrityGuard is needed.

### 2.1 File Integrity Monitoring

Suggested length:

400 to 500 words.

What to cover:

- Trusted baselines.
- Hash comparison.
- File policies.
- Critical paths.
- Host-based intrusion detection.
- Compliance uses such as PCI DSS.

Argument to make:

FIM is mature and valuable, but traditional systems often stop at detecting
change rather than explaining risk.

Sources:

- Kim and Spafford.
- Bray, Cid and Hay.
- Open Source Tripwire.
- Microsoft Defender for Cloud FIM.
- PCI DSS and Qualys.

### 2.2 Hashing and Integrity Evidence

Suggested length:

300 to 400 words.

What to cover:

- Why hashes are useful for integrity.
- Difference between cryptographic and non-cryptographic hashes.
- Why fast hashing matters for large baselines.
- Why verification hashes still matter when security assurance is needed.

Argument to make:

The system's hybrid XXH3/BLAKE3 design is a practical engineering compromise:
fast enough for usability, but still able to retain verification value.

Sources:

- Forensic hashset literature.
- BLAKE3 and XXH3 technical documentation where appropriate.

### 2.3 Alert Fatigue and Warning Design

Suggested length:

450 to 600 words.

What to cover:

- Alert fatigue in SOCs and security tools.
- Why too many alerts can reduce security.
- Human factors in security monitoring.
- Warning quality: specificity, actionability, timing, and explanation.

Argument to make:

Notification design is not cosmetic. If the user cannot understand or trust the
alert, the technical detection is weakened.

Sources:

- Sundaramurthy et al.
- Vielberth et al.
- Tariq et al.
- Bauer et al.
- Zhao et al.

### 2.4 Reverse Shells, RCE, and Endpoint Detection Gaps

Suggested length:

450 to 600 words.

What to cover:

- Reverse shells as a remote-control pattern.
- RCE as attacker-controlled execution.
- File-level indicators: shell invocation, process creation, network callbacks,
  encoded commands, persistence hooks, and suspicious API calls.
- Why antivirus or EDR may not catch every newly created or obfuscated file.

Argument to make:

FIM cannot replace antivirus, but content-aware file monitoring can catch a
different layer of evidence: risky content being written or modified before or
around execution.

Safety note:

Keep the discussion conceptual. Do not include operational payloads.

Sources:

- MITRE ATT&CK.
- Endpoint detection literature.
- Project evaluation results.

### 2.5 Open Source Software Supply-Chain Compromise

Suggested length:

600 to 750 words.

What to cover:

- Dependency trees and transitive trust.
- Package manager install scripts.
- Maintainer compromise.
- Typosquatting and malicious package publication.
- Lockfile and manifest changes.
- Case studies such as npm compromise and XZ Utils.

Argument to make:

Developer workstations are directly exposed to supply-chain compromise because
normal package installation can create or modify local files. IntegrityGuard
therefore monitors the local host effects of compromise rather than trying to
replace registry-side malware scanning.

Sources:

- Ohm et al.
- Zimmermann et al.
- Ladisa et al.
- Sejfia and Schafer.
- Zhang et al.
- OSCAR.
- XZ Utils CVE-2024-3094.

### 2.6 LLM-Assisted and Agentic Security Analysis

Suggested length:

350 to 450 words.

What to cover:

- LLMs as explanation and triage tools.
- Risks of relying on LLM output.
- Local-first analysis and privacy.
- Bounded agent execution.
- Why deterministic heuristics and SQL state remain important.

Argument to make:

The LLM and agent should not be the only decision-maker. They add explanation
and contextual reasoning on top of deterministic evidence.

Sources:

- Thapa et al.
- Security triage and LLM literature to be added.
- Project implementation evidence.

### 2.7 Research Gap

Suggested length:

250 to 350 words.

What to write:

Synthesize the literature into a clear gap.

Recommended gap statement:

Existing FIM tools detect changes, package-security tools classify packages,
and SOC tools manage alert queues, but there is a gap for a local developer
workstation tool that combines file integrity baselines, semantic file identity,
content-aware change analysis, persistent contextual memory, and user-friendly
notifications.

## Chapter 3: Methodology

Suggested length:

1,800 to 2,200 words.

Chapter purpose:

Explain how the project was designed, implemented, and evaluated in a way that
is academically defensible.

### 3.1 Research Method: Design Science

Suggested length:

350 to 450 words.

What to cover:

- The artefact is the IntegrityGuard system.
- The problem is practical and security-focused.
- The evaluation tests whether the artefact addresses the stated problem.

Source:

- Hevner et al.

### 3.2 Requirements Gathering

Suggested length:

300 to 400 words.

Functional requirements:

- Baseline scanning.
- Real-time watching.
- Hash comparison.
- File identity tracking.
- Directory tree storage.
- Tiered file registry.
- Content analysis.
- Agent investigation.
- Notification handling.
- Dashboard.
- Deployment scripts.

Non-functional requirements:

- Performance.
- Reliability.
- Cross-platform support.
- Local-first privacy.
- Usability.
- Safe testing.
- Reproducibility.

### 3.3 Threat Model and Scope

Suggested length:

350 to 450 words.

In scope:

- Suspicious source-code changes.
- Reverse-shell and RCE indicators.
- Persistence-related file changes.
- Compromised dependency effects.
- Unexpected changes to critical or high-value files.
- Developer workstation monitoring.

Out of scope:

- Automatic malware removal.
- Network IDS.
- Multi-host SOC orchestration.
- Guaranteeing prevention of execution.
- Running live malware.

### 3.4 System Design Method

Suggested length:

300 to 400 words.

What to write:

Explain that the system was built iteratively. Each iteration responded to a
technical or usability limitation discovered during development.

Important iteration themes:

- Basic FIM prototype.
- Heuristic and LLM analysis.
- Backlog and scalability problems.
- WizTree-inspired scan optimisation.
- Hybrid hashing.
- Tree navigation.
- Notification redesign.
- File identity and rename handling.
- MemPalace and agent context.
- Deployment hardening.

### 3.5 Evaluation Design

Suggested length:

450 to 600 words.

Evaluation groups:

- Baseline capture.
- Benign change suppression.
- Reverse-shell/RCE indicator detection.
- Dependency compromise simulation.
- Rename continuity.
- MemPalace agent explanation.
- Deployment.

Metrics:

- Files per second.
- Hash throughput.
- Notification reduction ratio.
- True positive rate for controlled suspicious scenarios.
- False positive rate for benign scenarios.
- Agent investigation rate.
- Memory hit usefulness.
- Deployment success.

### 3.6 Ethics and Safety Method

Suggested length:

200 to 300 words.

What to write:

Explain that adversarial scenarios are synthetic, controlled, and defensive.
Tests should contain indicators but not live payloads. No live C2, credential
theft, destructive payloads, or uncontrolled propagation should be used.

## Chapter 4: Design and Implementation

Suggested length:

3,000 to 3,500 words.

Chapter purpose:

Explain the artefact in enough technical depth that a marker can see what was
built and why each design decision was made.

### 4.1 System Overview

Suggested length:

300 to 400 words.

What to cover:

- FastAPI backend.
- SQLite database.
- Scanner and watcher.
- Background analysis worker.
- Registry and MemPalace components.
- Notification system.
- Static dashboard.

Figure:

High-level architecture diagram.

### 4.2 Baseline Scanner and Hashing Pipeline

Suggested length:

450 to 600 words.

What to cover:

- Initial slow baseline problem.
- Hash-first state capture.
- Metadata-first reconciliation.
- XXH3 fast comparison hash.
- BLAKE3 verification hash.
- Worker count tuning.
- Scan progress and performance metrics.

Table:

Hashing strategy comparison.

### 4.3 Database Model and Tree Structure

Suggested length:

400 to 500 words.

What to cover:

- SQLite as local operational storage.
- File records.
- Directory nodes.
- Scan sessions.
- Analysis cache.
- Registry entries.
- File logs.
- Why tree-backed storage improves navigation and performance.

Figure:

Database relationship diagram.

### 4.4 File Identity and Rename Continuity

Suggested length:

300 to 400 words.

What to cover:

- Problem with path-only tracking.
- Rename appearing as delete/create.
- Identity fingerprints and metadata.
- Timeline continuity.
- User-facing value.

Evaluation link:

Group E rename continuity test.

### 4.5 Tiered File Registry

Suggested length:

350 to 450 words.

What to cover:

- Tier 1 critical files.
- Tier 2 high-value config and service files.
- Tier 3 application/source files.
- Tier 4 logs, caches, and temporary files.
- Windows and Linux file identity handling.
- Semantic roles such as source code, dependency manifest, binary, config,
  credential material, startup item, log, or cache.

Table:

File tier model with examples and expected notification behaviour.

### 4.6 Content-Aware Analysis

Suggested length:

450 to 600 words.

What to cover:

- File content capture.
- Diff or snippet handling.
- Suspicious indicators.
- Reverse-shell/RCE behaviour patterns.
- Dependency compromise indicators.
- Heuristic analysis.
- LLM-assisted explanation.
- Backlog guard and fallback behaviour.

Important distinction:

The system should not depend on LLM output alone. Deterministic evidence should
be collected first.

### 4.7 MemPalace Context Layer

Suggested length:

350 to 450 words.

What to cover:

- SQL baseline as operational truth.
- MemPalace as derived contextual memory.
- Drawers or memories for file role, path, previous verdict, and related events.
- Why memory helps later analysis.
- Difference between raw logs and contextual memory.

Figure:

Baseline SQL to MemPalace memory flow.

### 4.8 Agent Investigation Layer

Suggested length:

400 to 550 words.

What to cover:

- When the agent runs.
- Why high-risk events receive deeper analysis.
- Agent inputs: file record, registry context, content findings, hash change,
  memory hits, trusted-change evidence.
- Agent outputs: verdict, risk, reasoning, recommended action, notification
  summary.
- Why this is bounded and embedded rather than a separate uncontrolled agent.

### 4.9 Notification System and User Interface

Suggested length:

450 to 600 words.

What to cover:

- Immediate alerts for critical/high events.
- Batching for medium events.
- Silent logging for low/info events.
- Toasts, alert centre, timeline, and agent drawer.
- Professional notification wording.
- Readability improvements: bullet points, grouped context, verdict, indicators,
  recommended action.

Figure:

Notification flow or UI screenshot.

### 4.10 Deployment Design

Suggested length:

300 to 400 words.

What to cover:

- README quick start.
- Bootstrap scripts.
- Run scripts.
- Docker and Compose.
- GitHub Actions.
- Windows scheduled task and Linux systemd helpers if included.

Table:

Deployment checklist.

## Chapter 5: Evaluation and Results

Suggested length:

2,500 to 3,000 words.

Chapter purpose:

Present evidence. This chapter should contain measurements, screenshots, tables,
and scenario outcomes rather than only descriptions.

### 5.1 Test Environment

Suggested length:

250 to 350 words.

What to record:

- Operating system.
- CPU and RAM.
- Storage type if known.
- Python version.
- Browser.
- Hashing algorithm configuration.
- LLM provider configuration.
- Dataset/directories scanned.

### 5.2 Baseline Scan Performance

Suggested length:

350 to 450 words.

Evidence:

- Number of files scanned.
- Total data hashed.
- Elapsed time.
- Hash throughput.
- Files per second.
- Worker count.
- Database commit timing.

Table:

Baseline performance results.

### 5.3 Notification Reduction

Suggested length:

350 to 450 words.

Evidence:

- Naive FIM alert count.
- IntegrityGuard immediate alert count.
- Batched notification count.
- Silent logged event count.
- Notification reduction ratio.

Argument:

The system is successful only if it reduces low-value noise without hiding
security-relevant events.

### 5.4 Benign Change Scenarios

Suggested length:

300 to 400 words.

Scenarios:

- Log append.
- Cache file update.
- Normal text edit.
- Normal package install/update.
- Browser or temp directory changes.

Expected result:

Most benign changes should be logged or batched, not escalated as critical.

### 5.5 Reverse-Shell/RCE Indicator Scenarios

Suggested length:

400 to 550 words.

Scenarios:

- Inert source file containing process execution indicators.
- Inert source file containing network callback indicators.
- Inert script containing encoded command indicators.
- Persistence-related path or startup-related modification.

Evidence:

- Timeline event.
- Content analysis findings.
- Agent reasoning.
- Notification priority.

Safety:

Make clear that files were synthetic and not executed as live malware.

### 5.6 Dependency Compromise Simulation

Suggested length:

400 to 550 words.

Scenarios:

- Benign dependency update.
- Synthetic local package with inert suspicious install-script indicators.
- Modified package manifest or lockfile.
- Suspicious JavaScript or script content in dependency folder.

Evidence:

- File changes recorded.
- Registry/tier classification.
- Content findings.
- Agent memory/context output.
- Notification result.

### 5.7 Rename and Timeline Continuity

Suggested length:

250 to 350 words.

Evidence:

- Original file.
- Rename event.
- Modification after rename.
- Same timeline retained.
- No duplicate unrelated file card.

### 5.8 Agent and MemPalace Evaluation

Suggested length:

350 to 450 words.

Evidence:

- MemPalace baseline status.
- Number of memories/drawers.
- Memory search hits.
- Agent investigations run.
- Agent investigations skipped.
- Example before/after alert explanation.

Key question:

Does the agent add useful context beyond the heuristic result?

### 5.9 Deployability Evaluation

Suggested length:

250 to 350 words.

Evidence:

- Fresh setup steps.
- Bootstrap script result.
- Docker build result.
- API health check.
- UI loads.
- Scan can be started.

### 5.10 Summary Against Objectives

Suggested length:

250 to 350 words.

Table:

Objective, evidence, result, limitations.

## Chapter 6: Discussion

Suggested length:

1,700 to 2,000 words.

Chapter purpose:

Interpret the results. Explain what they mean, what trade-offs were discovered,
and where the system is still limited.

### 6.1 Interpretation of Results

Suggested length:

350 to 450 words.

What to write:

Discuss whether the evidence supports the research questions. Avoid repeating
all results. Explain what the results mean.

### 6.2 What IntegrityGuard Adds Beyond Traditional FIM

Suggested length:

300 to 400 words.

Argument:

IntegrityGuard extends FIM by adding identity, role, content, memory, agent
reasoning, and notification design.

### 6.3 Trade-Offs

Suggested length:

300 to 400 words.

Trade-offs to discuss:

- Speed vs security-grade verification.
- Local analysis vs cloud model quality.
- Agent depth vs backlog and latency.
- Sensitivity vs false positives.
- Synthetic safety vs realism.

### 6.4 Limitations

Suggested length:

300 to 450 words.

Limitations:

- Single-host system.
- SQLite local database.
- LLM inconsistency.
- Synthetic adversarial scenarios.
- Cannot prevent every execution.
- File monitoring does not replace EDR, antivirus, or network monitoring.
- Docker requires mounted host paths.

### 6.5 Ethical and Safety Considerations

Suggested length:

250 to 350 words.

What to write:

Explain why tests were controlled and defensive. Emphasise that the dissertation
does not include operational malware instructions and does not use live
malicious infrastructure.

### 6.6 Generative AI Use

Suggested length:

150 to 250 words in main chapter, full record in appendix.

What to write:

Summarise how generative AI was used for planning, wording, code assistance, or
debugging if applicable. Explain verification and student ownership.

## Chapter 7: Conclusion and Future Work

Suggested length:

900 to 1,100 words.

Chapter purpose:

Close the dissertation by returning to the aim, objectives, and contribution.

### 7.1 Conclusion

Suggested length:

450 to 550 words.

What to write:

Summarise the problem, artefact, evaluation, and contribution. State clearly
whether the project met its aim.

### 7.2 Future Work

Suggested length:

350 to 450 words.

Possible future work:

- SBOM and lockfile intelligence.
- Direct package-manager event integration.
- Stronger Windows registry event streaming.
- Code signing and binary trust verification.
- Multi-host enterprise dashboard.
- Installer packaging.
- Broader user study.
- Safer remediation suggestions.
- Better model benchmarking.

## References

Purpose:

Provide all cited sources in Harvard format.

Writing advice:

Only include sources cited in the dissertation body. Keep "Bibliography" separate
only if the university template requires sources that were consulted but not
cited.

## Appendices

Appendices should support the dissertation without interrupting the main
argument. They should not contain essential explanation that the marker needs in
order to understand the system.

### Appendix A: Development Chronology

Source:

`docs/DISSERTATION_DEVELOPMENT_LOG.md`

Purpose:

Show how the system evolved and demonstrate project ownership.

### Appendix B: Architecture Diagrams

Purpose:

Include larger versions of diagrams that are too detailed for the main body.

### Appendix C: Database Schema

Purpose:

Document key tables and relationships.

### Appendix D: Evaluation Scenarios

Purpose:

Provide exact benign and controlled suspicious test procedures at a safe,
non-operational level.

### Appendix E: Raw Results

Purpose:

Include detailed measurements, API outputs, or screenshots used to support
Chapter 5.

### Appendix F: Notification Examples

Purpose:

Show before/after examples of low-quality vs readable notification output.

### Appendix G: Agent Investigation Examples

Purpose:

Show MemPalace memory retrieval, agent reasoning, and final alert formatting.

### Appendix H: Deployment Instructions

Purpose:

Include setup commands, bootstrap scripts, Docker instructions, and health-check
commands.

### Appendix I: Generative AI Use Statement

Purpose:

Satisfy the project brief requirement to declare generative AI use. Include tool
names, purposes, verification steps, and a summary of interactions if required.

## Chapter-to-Marking Mapping

| Marking area | Dissertation location | Evidence to include |
| --- | --- | --- |
| Abstract | Abstract | Concise problem, artefact, method, evaluation, contribution. |
| Introduction | Chapter 1 | Motivation, problem, aim, objectives, research questions. |
| Literature Review | Chapter 2 | FIM, alert fatigue, reverse-shell/RCE, supply chain, LLM triage. |
| Methodology | Chapter 3 | Design science, requirements, threat model, evaluation method. |
| Results and Discussion | Chapters 5 and 6 | Measurements, scenario outcomes, interpretation, limitations. |
| Conclusion and Future Work | Chapter 7 | Aim/objective summary and realistic future work. |
| Structure and References | Whole dissertation | Clear chapter flow, Harvard references, figures, tables. |
| Product | Chapters 4 and 5, appendices | Implemented system, screenshots, deployment, tests, evaluation. |

## Objective-to-Evidence Mapping

| Objective | Where to describe it | Where to prove it |
| --- | --- | --- |
| O1 baseline monitor | Chapter 4.2 | Chapter 5.2 |
| O2 scalable hashing | Chapter 4.2 | Chapter 5.2 |
| O3 identity and rename continuity | Chapter 4.4 | Chapter 5.7 |
| O4 tiered registry | Chapter 4.5 | Chapter 5.4 to 5.6 |
| O5 content-aware analysis | Chapter 4.6 | Chapter 5.5 and 5.6 |
| O6 MemPalace agent | Chapter 4.7 and 4.8 | Chapter 5.8 |
| O7 notification handling | Chapter 4.9 | Chapter 5.3 |
| O8 deployability | Chapter 4.10 | Chapter 5.9 |

## Suggested Writing Order

1. Write Chapter 4 first because it describes the system that already exists.
2. Write Chapter 5 after collecting final screenshots and metrics.
3. Write Chapter 3 once the evaluation method is fixed.
4. Write Chapter 2 using the literature matrix.
5. Write Chapter 1 after the contribution is clear.
6. Write Chapter 6 once the results are known.
7. Write Chapter 7 and the abstract last.

## Minimum Evidence Checklist

- Architecture diagram.
- Database/schema diagram.
- Screenshot of dashboard.
- Screenshot of agent drawer.
- Screenshot of a readable alert.
- Baseline scan metrics.
- Hash throughput metrics.
- Notification reduction table.
- Reverse-shell/RCE indicator scenario table.
- Dependency compromise simulation table.
- Rename continuity evidence.
- MemPalace/agent evidence.
- Deployment smoke test evidence.
- Ethical testing statement.
- Generative AI use appendix.
