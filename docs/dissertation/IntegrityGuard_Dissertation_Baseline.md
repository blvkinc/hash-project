# IntegrityGuard: Context-Aware File Integrity Monitoring for Developer Workstations

Author: Dhanuja Siriwardhena  
Programme: MSc Ethical Hacking  
Institution: Abertay University  
Working document status: Baseline dissertation scaffold  

## Front Matter Checklist

- Title page
- Declaration
- Acknowledgements
- Abstract
- Table of Contents
- List of Figures
- List of Tables
- List of Listings
- Abbreviations, Symbols and Notation

For a full chapter-by-chapter table of contents with word targets, expected
evidence, figures, tables, and writing prompts, use
`docs/dissertation/expanded_table_of_contents.md`.

## Abstract Draft

File Integrity Monitoring (FIM) is a long-established security technique that
detects unauthorised file modification by comparing current file hashes against
a trusted baseline. Traditional FIM systems are effective at identifying that a
file has changed, but they often provide weak context about whether the change
matters. In real systems, operating system updates, package installations, log
growth, browser profiles, and application caches can generate large volumes of
benign hash mismatches. This creates alert fatigue and risks users ignoring the
small number of changes that indicate genuine compromise.

This project designs, implements, and evaluates IntegrityGuard, a local-first
file integrity monitoring system that combines fast hash-first baseline capture,
file identity tracking, tier-aware classification, content-aware analysis,
MemPalace-backed file memory, and an embedded agent investigation layer. The
system was motivated by two practical security concerns. First, during ethical
hacking experimentation it was possible to construct simple reverse-shell
payloads that were not reliably stopped by modern antivirus tools. Second,
recent developer-library compromises show that a user can become compromised by
installing or updating an apparently legitimate dependency. These incidents
suggest that defensive tooling should not only detect changed files, but should
also reason about what changed inside source code, dependency files, startup
locations, system binaries, and configuration files.

IntegrityGuard is implemented as a Python/FastAPI application with SQLite
storage, a static web dashboard, watchdog-based monitoring, hybrid XXH3/BLAKE3
hashing, optional Ollama/Gemini analysis, and a persistent MemPalace context
layer. The system records file baselines quickly, defers expensive analysis
where possible, and reserves deeper agent investigation for high-risk events.
Evaluation focuses on baseline performance, notification reduction, reverse
shell/RCE indicator detection, npm-style dependency compromise simulation,
rename continuity, agent explanation quality, and deployability.

## Core Dissertation Argument

The dissertation should argue that hash-based FIM remains valuable, but only
when it is adapted to modern developer environments. The key contribution is not
the hash comparison alone. The contribution is the combination of fast baseline
capture, semantic file identity, content-aware analysis, persistent contextual
memory, and notification design. This combination lets the system respond to the
local effects of reverse-shell/RCE payloads and compromised dependencies without
treating every changed cache file or log append as an emergency.

## Chapter 1: Introduction

### 1.1 Context

Modern security monitoring cannot assume that compromise appears only as a known
malware binary. Developer workstations routinely execute scripts from package
managers, build systems, browser tooling, language runtimes, and local test
environments. A malicious dependency can modify source files, add install-time
scripts, download secondary payloads, steal credentials, or create a reverse
shell before a user realises that a trusted library has changed.

Traditional antivirus and endpoint detection tools remain important, but they do
not remove the need for local integrity monitoring. A file integrity monitor can
observe a different layer of evidence: what changed on disk, which file role was
affected, whether the file belongs to a sensitive identity class, and whether the
new content contains suspicious execution or network behaviour.

### 1.2 Personal and Practical Motivation

The practical motivation for this project came from ethical-hacking
experimentation. It was unexpectedly easy to write simple payloads that opened
reverse shells and were not consistently blocked by modern antivirus products.
This experience highlighted a defensive gap: by the time a payload is executed,
the defender may already be dependent on signature or behavioural detection. A
local FIM system can provide an additional signal earlier in the chain by
detecting the creation or modification of files that contain suspicious network,
process-execution, persistence, or credential-access indicators.

A second motivation is the recent pattern of developer-library compromises.
Modern software projects rely on npm, PyPI, Cargo, Go modules, NuGet, and other
package ecosystems. When a maintainer account, dependency, or build artifact is
compromised, the malicious code may arrive through normal developer workflow.
The user sees a package install or update, while the host receives a modified
lockfile, new package files, install scripts, and sometimes command execution or
remote access behaviour. IntegrityGuard is intended to catch these local effects
and notify the user with context.

### 1.3 Problem Statement

Traditional FIM systems answer the question "did this file change?" but often do
not answer "does this change look like compromise?" Naive notification handling
can overwhelm users with low-value alerts, while purely static rules can miss
the meaning of file content. The problem is therefore a combined detection,
context, and notification problem:

- detect file changes quickly enough to establish useful evidence;
- classify the importance of the file identity, not only the file content;
- inspect file content for reverse-shell, RCE, persistence, and supply-chain
  compromise indicators;
- preserve context across renames and repeated scans;
- notify the user only when the change deserves attention;
- keep the system deployable for individuals and small organisations.

### 1.4 Aim

The aim of this project is to design, implement, and evaluate a local-first,
context-aware file integrity monitor that can detect and explain meaningful
security-relevant file changes, with particular focus on reverse-shell/RCE
payloads and compromised developer dependency scenarios, while reducing
notification fatigue.

### 1.5 Objectives

O1. Build a cross-platform file integrity monitor that can scan directories,
establish a baseline, hash files efficiently, and record results in SQLite.

O2. Preserve file identity and timeline continuity across modifications,
deletions, and renames.

O3. Implement a tiered file registry that classifies files by system importance,
semantic role, and expected change source.

O4. Add content-aware analysis that detects suspicious reverse-shell, RCE,
persistence, credential-access, and dependency compromise indicators.

O5. Integrate local-first LLM/heuristic analysis with MemPalace-backed contextual
memory and bounded agent investigation.

O6. Design notification handling that reduces alert fatigue through severity
prioritisation, batching, silent logging, and explanation-rich alerts.

O7. Evaluate the system using controlled benign, malicious, mixed, dependency
compromise, performance, usability, and deployment scenarios.

### 1.6 Research Questions

RQ1. To what extent can a tiered, context-aware FIM pipeline reduce notification
volume without missing high-risk file changes?

RQ2. Can local content analysis and agent memory identify reverse-shell/RCE
indicators and dependency compromise patterns that are not captured by simple
hash mismatch reporting?

RQ3. Does persistent file identity and MemPalace context improve the
explainability of file-change alerts?

RQ4. Can the system remain usable and performant when scanning large directory
trees?

RQ5. Can the artefact be deployed on a new system without hidden local state or
manual setup assumptions?

### 1.7 Working Hypothesis

Compared with a naive FIM that reports every hash mismatch equally,
IntegrityGuard should reduce low-value alerts while preserving or improving the
visibility of high-risk changes. High-risk changes include files that introduce
reverse-shell indicators, command execution, suspicious network callbacks,
persistence hooks, credential access patterns, or compromised dependency
behaviour.

### 1.8 Contributions

- A working local FIM artefact with hash-first baseline capture.
- A hybrid hashing approach using XXH3 for fast comparison and BLAKE3 for
  verification.
- Stable file identity and tree-backed navigation.
- A file registry that reasons about what a file is, not only what it contains.
- A MemPalace-backed context layer seeded from SQL baseline records.
- An embedded agent investigation layer for high-risk events.
- A notification model designed around alert fatigue reduction.
- A deployment package including scripts, Docker files, and CI.

### 1.9 Dissertation Structure

Chapter 2 reviews FIM, alert fatigue, supply-chain attacks, reverse-shell/RCE
behaviour, LLM-assisted triage, and design-science research. Chapter 3 describes
the methodology and evaluation design. Chapter 4 explains the system design and
implementation. Chapter 5 presents evaluation results. Chapter 6 discusses the
findings, limitations, and ethical considerations. Chapter 7 concludes and
identifies future work.

## Chapter 2: Literature Review and Background

### 2.1 File Integrity Monitoring

Writing target: Explain Tripwire, OSSEC/Wazuh, AIDE, Microsoft Defender FIM,
hash baselines, policy/severity models, and the compliance context.

Use sources:

- Kim and Spafford (1994)
- Bray, Cid and Hay (2008)
- Microsoft Defender for Cloud FIM documentation
- PCI DSS v4.0
- Qualys PCI DSS FIM discussion
- Ruback, Hoelz and Ralha (2012)

Argument:

FIM is mature, but its traditional output is too close to raw hash mismatch
reporting. IntegrityGuard keeps the baseline idea but adds file identity,
content interpretation, and notification control.

### 2.2 Alert Fatigue and Warning Quality

Writing target: Establish why notification design is a security requirement,
not only a UI concern.

Use sources:

- Atzeni and Lioy (2006)
- Sundaramurthy et al. (2016)
- Vielberth et al. (2020)
- Tariq et al. (2025)
- Zhao et al. (2024)
- Bauer et al. (2013)

Argument:

The system should be evaluated by quality of notification, not only by number of
file changes detected.

### 2.3 Reverse Shells, RCE Payloads, and Antivirus Limitations

Writing target: Explain the security behaviour the system is expected to catch.
Keep the description defensive and high level.

Topics:

- Reverse shells as remote control channels.
- RCE as execution of attacker-controlled code through software, scripts, or
  dependency workflows.
- Suspicious indicators in files: shell invocation, network callbacks,
  process creation, encoded commands, persistence paths, credential access.
- Why content-aware FIM provides complementary evidence to antivirus.

Use sources:

- MITRE ATT&CK techniques such as T1059, T1105, T1573, T1543, T1546, and T1554.
- Malware detection and endpoint security literature to be added.
- Practical evaluation results from the project.

### 2.4 Open Source Supply-Chain and Dependency Compromise

Writing target: Connect the project to recent developer-library compromises.

Use sources:

- Ohm et al. (2020), open source supply-chain attack review.
- Zimmermann et al. (2019), npm ecosystem risks.
- Sejfia and Schafer (2022), practical malicious npm package detection.
- Ladisa et al. (2023), taxonomy of open-source supply-chain attacks.
- Zhang et al. (2023), malicious package detection in npm and PyPI.
- OSCAR (2024), dynamic package poisoning detection.
- XZ Utils backdoor analysis and CVE-2024-3094 incident reports.
- npm compromise incident reports as case-study evidence.

Argument:

Supply-chain compromises affect local files before they become visible as broad
system compromise. Monitoring developer directories, lockfiles, package scripts,
source code, and generated executables is therefore a relevant defensive layer.
IntegrityGuard should be positioned as host-level evidence collection and
triage, not as a replacement for registry-side package scanning.

### 2.5 LLMs and Agentic Security Triage

Writing target: Explain why LLMs are useful but must be bounded.

Use sources:

- Thapa et al. (2022)
- local LLM/Ollama documentation
- prompt consistency and security triage literature to be added

Argument:

The LLM should not be the sole source of truth. IntegrityGuard uses deterministic
heuristics, registry context, and SQL state first; the LLM and agent provide
explanation and deeper contextual reasoning.

### 2.6 Research Gap

Current FIM tools detect changes, and package-security tools detect malicious
packages, but there is a gap for local developer-workstation monitoring that:

- records the integrity baseline;
- inspects what changed inside files;
- knows the semantic role of the file;
- reasons across previous memory;
- and notifies the user in a way that reduces alert fatigue.

IntegrityGuard addresses this gap by combining FIM, content-aware analysis,
file identity memory, and notification prioritisation.

## Chapter 3: Methodology

### 3.1 Research Method

This project follows a design science methodology. The artefact is the
IntegrityGuard system, and the evaluation measures whether the artefact solves
the practical problem identified in the literature and motivation.

Use source:

- Hevner et al. (2004)

### 3.2 Requirements

Functional requirements:

- baseline scanning;
- real-time watching;
- hash comparison;
- rename continuity;
- file registry;
- content analysis;
- agent investigation;
- notifications;
- dashboard;
- deployability.

Non-functional requirements:

- local-first privacy;
- performance on large directories;
- low alert noise;
- cross-platform design;
- safe evaluation;
- reproducible deployment.

### 3.3 Threat Model

In scope:

- malicious modification of source code;
- introduction of reverse-shell or RCE indicators;
- compromised dependency files;
- persistence-related file changes;
- suspicious modifications outside trusted update windows;
- developer workstation compromise indicators.

Out of scope:

- automatic malware removal;
- network-level detection;
- multi-host enterprise SOC orchestration;
- guaranteed prevention of execution;
- live offensive malware deployment.

### 3.4 Development Method

Summarise the iterative stages from `docs/DISSERTATION_DEVELOPMENT_LOG.md`,
including:

- basic FIM prototype;
- LLM/heuristic analysis;
- backlog redesign;
- notification improvements;
- UI redesign;
- tree-backed storage;
- WizTree-inspired scan optimisation;
- hybrid hashing;
- MemPalace integration;
- agent investigation;
- deployment tooling.

### 3.5 Evaluation Method

Use the test groups in `evaluation_plan.md`:

- baseline performance;
- benign change suppression;
- reverse-shell/RCE detection;
- dependency compromise simulation;
- rename continuity;
- agent/MemPalace context;
- deployability.

## Chapter 4: Design and Implementation

### 4.1 System Architecture

Describe:

- FastAPI backend;
- SQLite operational database;
- scanner and watcher;
- background analysis queue;
- file registry;
- MemPalace memory store;
- agent investigator;
- notification dispatcher;
- web dashboard.

Suggested figure:

Architecture flow from UI -> API -> scanner/watcher -> SQLite -> registry ->
analysis -> MemPalace/agent -> notification/UI.

### 4.2 Baseline and Hashing Design

Explain why the project moved from naive hashing to:

- hash-first baseline capture;
- metadata-first reconciliation;
- XXH3 comparison hashes;
- BLAKE3 verification hashes;
- worker tuning;
- scan progress metrics.

### 4.3 File Identity, Tree Storage, and Rename Handling

Explain:

- why a path-only database causes duplicate timelines;
- how file identity helps link renamed files;
- how the directory tree improves navigation for large scans.

### 4.4 File Registry and Tiered Context

Explain the MemPalace concept from the user's design:

- the SQL database is the operational truth;
- the registry classifies file identity;
- MemPalace stores derived contextual memory;
- the agent reasons over file role, history, content, memory, and trusted
  change evidence.

### 4.5 Content Analysis and Reverse-Shell Detection

Explain:

- heuristic indicators;
- LLM provider chain;
- content snippets and diffs;
- source-code and script analysis;
- MITRE mapping;
- risk scoring and priority levels.

### 4.6 Agent Investigation

Explain:

- why the agent is reserved for important events;
- risk thresholds and backlog guard;
- related memory search;
- trusted-change correlation;
- Windows signature check;
- notification summary generation;
- UI drawer evidence.

### 4.7 Notification Handling

Explain:

- immediate critical/high alerts;
- medium batching;
- low/info silent logging;
- in-app alert center;
- desktop/email optional dispatch;
- alert readability improvements.

### 4.8 Deployment

Explain:

- README quick start;
- PowerShell and shell bootstrap scripts;
- Windows scheduled task helper;
- Linux systemd helper;
- Dockerfile and Compose;
- GitHub Actions CI.

## Chapter 5: Evaluation and Results

Write this chapter after collecting final measurements.

Planned sections:

1. Test environment.
2. Baseline scan performance.
3. Hash throughput and worker tuning.
4. Notification reduction.
5. Reverse-shell/RCE scenario results.
6. Dependency compromise scenario results.
7. Rename continuity results.
8. Agent and MemPalace results.
9. Deployability results.
10. Summary against objectives.

Suggested tables:

- Scenario matrix.
- Metrics table.
- Notification comparison table.
- Performance comparison table.
- Agent investigation examples.

## Chapter 6: Discussion

### 6.1 Interpretation of Findings

Discuss whether the system met the aim and objectives.

### 6.2 What the System Adds Beyond Traditional FIM

Key argument:

Traditional FIM detects that a file changed. IntegrityGuard tries to explain
what the changed file is, what changed inside it, whether the change resembles a
compromise pattern, and whether the user should act immediately.

### 6.3 Limitations

- Local-only single-host deployment.
- SQLite is suitable for this scope but not an enterprise multi-host backend.
- LLM output can be inconsistent.
- Synthetic malicious tests do not perfectly represent live adversaries.
- File monitoring cannot prevent all execution.
- Some short-lived registry or filesystem changes may be missed.
- Docker deployments can only scan mounted host paths.

### 6.4 Ethical and Safety Considerations

The dissertation must be clear that adversarial tests are controlled,
synthetic, and defensive. Reverse-shell and RCE examples should be inert and
should not connect to live infrastructure. The project should not provide a
malware-building guide.

### 6.5 Generative AI Use

The project brief requires a record and summary of generative AI use. Include an
appendix with:

- tools used;
- purpose of use;
- how outputs were verified;
- which parts remained the student's own analysis;
- any prompts/transcripts required by the module policy.

## Chapter 7: Conclusion and Future Work

### 7.1 Conclusion

Summarise:

- the artefact built;
- the problem addressed;
- the evidence from evaluation;
- the contribution to FIM, alert triage, and developer workstation security.

### 7.2 Future Work

- deeper package-manager integration;
- SBOM and lockfile intelligence;
- stronger Windows registry event streaming;
- signed binary verification;
- enterprise multi-host mode;
- richer user study;
- packaged installer;
- broader model evaluation;
- automated but safe remediation suggestions.

## References Working List

Use Harvard style in the final dissertation.

- Atzeni, A. and Lioy, A. (2006) security metrics.
- Bauer, L. et al. (2013) warning design guidelines.
- Bray, R., Cid, D. and Hay, A. (2008) OSSEC Host-Based Intrusion Detection.
- Hevner, A.R. et al. (2004) design science in information systems research.
- Kim, G.H. and Spafford, E.H. (1994) Tripwire.
- Ladisa, P., Plate, H., Martinez, M. and Barais, O. (2023) SoK: Taxonomy of
  Attacks on Open-Source Software Supply Chains.
- Microsoft (2024) Defender for Cloud FIM.
- MITRE (2024) ATT&CK persistence/execution techniques.
- Ohm, M. et al. (2020) Backstabber's Knife Collection.
- Open Source Tripwire (2018) policy documentation.
- PCI SSC (2022) PCI DSS v4.0.
- Qualys (2023) PCI DSS FIM requirements.
- Ruback, M., Hoelz, B. and Ralha, C. (2012) forensic hashsets.
- Sejfia, A. and Schafer, M. (2022) Practical Automated Detection of Malicious
  npm Packages.
- Sundaramurthy, S.C. et al. (2016) security operations ethnography.
- Tariq, S. et al. (2025) alert fatigue in SOCs.
- Thapa, C. et al. (2022) transformer-based vulnerability detection.
- Vielberth, M. et al. (2020) SOC open challenges.
- Zhang, J. et al. (2023) Malicious Package Detection in NPM and PyPI using a
  Single Model of Malicious Behavior Sequence.
- Zhao, L. et al. (2024) AlertPro.
- Zimmermann, M. et al. (2019) npm ecosystem risks.
- NVD (2024) CVE-2024-3094.
- XZ Utils supply-chain attack software engineering analysis.

## Appendix Plan

Appendix A: Development chronology from `docs/DISSERTATION_DEVELOPMENT_LOG.md`.  
Appendix B: System architecture diagrams.  
Appendix C: Database schema and data model.  
Appendix D: Test scenarios and raw results.  
Appendix E: Notification examples.  
Appendix F: Agent investigation examples.  
Appendix G: Deployment instructions.  
Appendix H: Generative AI use statement and transcript summary.  
Appendix I: Ethics and safe testing protocol.
