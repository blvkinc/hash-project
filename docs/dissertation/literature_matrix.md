# Literature Matrix

This matrix maps the current proposal references and the expanded dissertation
literature areas to the argument they support.

## Existing Proposal Sources

| Source | Use in dissertation |
| --- | --- |
| Kim and Spafford (1994), Tripwire | Foundational FIM model: trusted baseline, hash comparison, policy-based integrity checking. |
| Bray, Cid and Hay (2008), OSSEC | Host-based intrusion detection and practical FIM deployment context. |
| Microsoft Defender for Cloud FIM documentation | Modern commercial FIM capability, including registry/file monitoring and recommended monitored paths. |
| MITRE ATT&CK (2024) | Maps monitored file identities to attacker tactics such as persistence, software binary compromise, service modification, and execution. |
| PCI SSC (2022), PCI DSS v4.0 | Compliance motivation for monitoring critical file and log integrity. |
| Qualys (2023), PCI DSS FIM guidance | Supports the argument that monitoring noisy files without prioritisation creates operational burden. |
| Atzeni and Lioy (2006) | Security metrics and why alert output should be meaningful rather than merely numerous. |
| Sundaramurthy et al. (2016) | Human factors and cognitive overload in security operations. |
| Vielberth et al. (2020) | SOC challenges and alert overload as an open problem. |
| Tariq et al. (2025) | Alert fatigue taxonomy and mitigation strategies: automation, augmentation, collaboration. |
| Zhao et al. (2024), AlertPro | Context-aware prioritisation as a stronger model than static severity. |
| Bauer et al. (2013) | Warning design: actionable, specific warnings improve user response. |
| Thapa et al. (2022) | Transformer models for software vulnerability detection; supports LLM/security analysis background. |
| Hevner et al. (2004) | Design science methodology for building and evaluating the artefact. |
| Ruback, Hoelz and Ralha (2012) | Forensic hashsets and the role of hashing in evidence triage. |

## Expanded Literature Areas

### 1. Developer Workstation Compromise and Reverse Shells

Motivation:

The project was motivated by practical ethical-hacking experimentation showing
that simple reverse-shell payloads can still bypass modern antivirus controls in
some contexts. This suggests a gap between malware signature detection and local
change-aware monitoring. IntegrityGuard should therefore be evaluated against
files that introduce reverse-shell behavior, command execution, suspicious
network callbacks, and persistence-related modifications.

Recommended concepts to cover:

- Reverse shells as post-exploitation control channels.
- Command and scripting interpreters in MITRE ATT&CK, especially shell,
  PowerShell, Python, JavaScript, and native API execution.
- Endpoint antivirus limitations when payloads are newly written, obfuscated, or
  embedded in apparently legitimate developer files.
- Why content-aware FIM can add value even when it does not replace antivirus.

Useful MITRE techniques:

- T1059 Command and Scripting Interpreter.
- T1105 Ingress Tool Transfer.
- T1095 Non-Application Layer Protocol.
- T1573 Encrypted Channel.
- T1543 Create or Modify System Process.
- T1546 Event Triggered Execution.
- T1554 Compromise Host Software Binary.

### 2. Open Source and Package Manager Supply-Chain Compromise

Motivation:

Recent library compromises show that a developer can execute malicious code by
installing or updating an apparently normal dependency. npm, PyPI, and similar
ecosystems are particularly relevant because install scripts can execute on the
developer workstation and because dependency trees create indirect trust.

Recommended academic sources:

- Ohm et al. (2020), "Backstabber's Knife Collection: A Review of Open Source
  Software Supply Chain Attacks". This is important because it analyses real
  malicious packages across npm, PyPI, and RubyGems and discusses injection and
  execution points in dependency trees.
- Zimmermann et al. (2019), "Small World with High Risks: A Study of Security
  Threats in the npm Ecosystem". This supports the claim that npm has structural
  dependency and maintainer concentration risks.
- Ladisa et al. (2023), "SoK: Taxonomy of Attacks on Open-Source Software
  Supply Chains". This gives a broader attack-tree view that can be used to
  justify the dissertation threat model.
- Sejfia and Schafer (2022), "Practical Automated Detection of Malicious npm
  Packages". This can be used to compare IntegrityGuard's local file-change
  approach with package-level malicious package classifiers.
- Zhang et al. (2023), "Malicious Package Detection in NPM and PyPI using a
  Single Model of Malicious Behavior Sequence". This supports the idea that
  malicious dependency behavior can be represented as behavioural sequences.
- OSCAR (2024), work on robust dynamic code poisoning detection for NPM and
  PyPI. This provides a useful comparison point for dynamic package analysis.

Recent incident examples to discuss as motivating case studies:

- XZ Utils backdoor, CVE-2024-3094: a sophisticated supply-chain attack that
  targeted a widely used Linux library and could enable SSH-related remote code
  execution under specific build/runtime conditions.
- npm ecosystem compromises involving phishing of maintainers and malicious
  package versions that execute install-time payloads.
- Axios npm package compromise reports in 2026 describing malicious dependency
  delivery and cross-platform remote access trojan behavior.

Dissertation angle:

IntegrityGuard does not try to decide whether an entire npm package ecosystem is
trustworthy. Instead, it watches the local effects of dependency installation:
new files, modified lockfiles, postinstall scripts, suspicious JavaScript, new
executables, credential access patterns, and network callback behavior.

Working source links to verify before final submission:

| Source | Link | Dissertation use |
| --- | --- | --- |
| Ohm et al. (2020), Backstabber's Knife Collection | https://arxiv.org/abs/2005.09535 | Real-world OSS supply-chain malicious package dataset and attack trees. |
| Zimmermann et al. (2019), Small World with High Risks | https://www.usenix.org/conference/usenixsecurity19/presentation/zimmerman | npm ecosystem dependency and maintainer risk. |
| Sejfia and Schafer (2022), Practical Automated Detection of Malicious npm Packages | https://doi.org/10.1145/3510003.3510104 | Comparison with automated malicious-package classifiers. |
| Ladisa et al. (2023), SoK: Taxonomy of Attacks on Open-Source Software Supply Chains | https://arxiv.org/abs/2204.04008 | Threat model and supply-chain attack taxonomy. |
| Zhang et al. (2023), Cerebro | https://arxiv.org/abs/2309.02637 | Behaviour-sequence modelling for malicious packages across npm and PyPI. |
| OSCAR (2024) | https://arxiv.org/abs/2409.09356 | Dynamic behaviour monitoring comparison for package poisoning detection. |
| NVD CVE-2024-3094 | https://nvd.nist.gov/vuln/detail/cve-2024-3094 | Authoritative vulnerability record for the XZ Utils case study. |
| Software engineering analysis of the XZ Utils attack | https://arxiv.org/html/2504.17473v1 | Case-study discussion of process and trust manipulation. |

### 3. Alert Fatigue, Notification Quality, and Human Response

Motivation:

The system should notify the user when the change means something. Alert fatigue
is not a side problem; it is one of the core design constraints.

Key claims to develop:

- Naive FIM creates too many hash mismatch notifications.
- Users learn to ignore alerts if the system cannot explain risk.
- Actionable warnings should state what changed, why it matters, and what the
  user should do.
- The MemPalace agent and notification drawer exist to improve explainability,
  not merely to raise scores.

### 4. Local LLMs, Agentic Analysis, and Security Privacy

Motivation:

File paths, diffs, hashes, package names, and source code snippets can be
sensitive. The dissertation should justify local-first analysis and bounded
agent execution.

Key claims to develop:

- Local Ollama avoids sending sensitive host context to cloud APIs by default.
- Heuristic analysis remains available when no LLM is installed.
- Agent analysis is bounded by risk thresholds and backlog guards.
- MemPalace stores derived file intelligence so later events can be reasoned
  about in context.

### 5. Hashing, Performance, and Scalable Baseline Capture

Motivation:

The project initially struggled with large scans and analysis backlog. This
became an important design finding.

Key claims to develop:

- Hash-first baseline capture is required before expensive analysis.
- XXH3/BLAKE3 hybrid hashing separates fast comparison from security-grade
  verification.
- Tree-backed directory storage improves navigation and incremental browsing.
- Metadata-first reconciliation reduces unnecessary re-hashing.

## Reference Expansion Checklist

- Verify final bibliographic details for all web/industry incident reports.
- Prefer peer-reviewed sources for literature review claims.
- Use incident reports as motivating case studies, not as sole academic
  evidence.
- Keep exploit details abstract and defensive.
- Include a generative AI use appendix as required by the project brief.
