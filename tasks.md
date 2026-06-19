

## Phase 1: Research & Requirement Analysis

*Before coding, you must define the "Ground Truth" of what constitutes a threat.*

* [ ] **Literature Review:** Read and summarize the Ruback (2012) paper. Focus on "Hashset" creation and how they handle "Known Goods" (NSRL databases).
* [ ] **Define Scope:** Identify which OS (Linux/Windows) you are monitoring. For a Master's project, **Linux** is often better due to transparent file system behavior.
* [ ] **Threat Modeling:** List 5 specific scenarios your monitor must catch (e.g., unauthorized SSH key addition, binary replacement, configuration tampering).
* [x] **Tech Stack Finalization:** Python 3.10+, SQLite (SQLAlchemy 2.x), watchdog for cross-platform FS events, threaded background pipeline (no external orchestrator — see Phase 3), Ollama-hosted LLM (qwen2.5-coder / mistral / llama3.2 selected at startup by `core.services.ollama_config`).

---

## Phase 2: Core Engine Development (The "Hashing" Logic)

*This is the "Forensics" layer where data integrity is paramount.*

* [ ] **Hashing Module:** Create a Python utility using `hashlib` to generate SHA-256/BLAKE3 hashes.
* [ ] **Metadata Extractor:** Capture `st_mode`, `st_uid`, `st_gid`, and `st_mtime` using Python’s `os.stat`.
* [ ] **Database Schema Design:** Design an SQLAlchemy model to store `FileRecord` (Path, Hash, LastSeen, IsBaseline).
* [ ] **Baseline Generator:** Build a "Golden Image" function that hashes a clean system and marks these as "Trusted."

---

## Phase 3: Orchestration (threaded pipeline, not Prefect)

*Deliberate scope choice: an external orchestrator (Prefect / Airflow) was rejected
in favour of an in-process threaded design. The target users are individuals and
small organisations who run the artefact on a single host; adding a 70 MB
orchestrator dependency and a separate Worker process would hurt both
installability and the dissertation's "practical, lightweight tool" framing.*

* [x] **Scanner stage:** `core/scanner.py` walks the filesystem and emits `FileLog(status='pending')` rows.
* [x] **Watcher stage:** `core/watcher.py` (watchdog) reacts to real-time `created/modified/deleted` events.
* [x] **Background analyser:** `core/background_analysis.py::run_analysis_loop` runs as a daemon thread; drains pending logs through Stage A (tier pre-filter) and Stage B (LLM / heuristic).
* [x] **Notification dispatcher:** `core/notification_dispatcher.py::dispatch_loop` runs as a second daemon thread; flushes the batch queue at `settings.batch_interval_seconds`.
* [x] **Noise reduction:** `core/platform_paths.py::get_noisy_dirs` and the Tier 4 pre-filter ignore temp/cache/log paths (Linux `/tmp`, Windows `Temp`, macOS caches).

---

## Phase 4: The Intelligence & LLM Layer

*This is the "Novelty" factor for your Master's degree.*

* [ ] **LLM Integration:** Set up a task that triggers *only* when a high-priority file changes.
* [ ] **Contextual Prompting:** Design a prompt template that sends the file path, metadata, and a "diff" of the file content to the LLM.
* [ ] **Classification Task:** Train/Prompt the LLM to return a JSON response: `{ "risk_score": 0-10, "is_malicious": boolean, "reasoning": "text" }`.
* [x] **Alerting:** `core/notification_dispatcher.py` dispatches via desktop (plyer) + SMTP email, with batching, escalation thresholds, and an in-memory history ring buffer surfaced via `/api/notifications/history`.

---

## Phase 5: Evaluation & Testing (The "Science")

*You cannot pass a Master's without data. You must prove your system works.*

* [ ] **Performance Benchmarking:** Measure the time/CPU usage for a 10GB vs. 100GB directory scan.
* [ ] **The "Red Team" Test:** Intentionally "attack" the system. Change a user password, add a cron job, and replace `/bin/ls` with a script.
* [ ] **Accuracy Metrics:** Calculate **False Positives** (updates flagged as attacks) and **False Negatives** (attacks missed).
* [ ] **Comparative Analysis:** Compare the threaded LLM-assisted pipeline against a basic tool like `AIDE` or `Tripwire`, focusing on notification volume rather than detection rate.

---

## Phase 6: Documentation & Dissertation

* [x] **Architecture Diagrams:** Use Mermaid.js or LucidChart to show the data flow: File System -> watchdog/scanner -> SQLite (FileLog pending) -> background analyser (Stage A tier pre-filter + Stage B LLM/heuristic) -> notification dispatcher (Stage C).
* [x] **Dissertation Development Log:** Added `docs/DISSERTATION_DEVELOPMENT_LOG.md` covering the full development chronology, design decisions, tradeoffs, observed performance findings, current limitations, and evaluation plan.
* [ ] **Code Quality:** Ensure all code is PEP8 compliant, typed, and documented with Docstrings.
* [ ] **Final Write-up:** Document your findings, specifically the effectiveness of using an LLM to reduce "alert fatigue."


## Phase 7: Debugging & Maintenance

* [x] **Debug Web Interface:** Investigated 2026-05-20 via `scripts/diagnose_phase7.py`. Pipeline (background_analysis, /api/baseline, /api/files/timeline) works end-to-end; the symptom was UX: benign modifications stayed at priority='info' and the sidebar gave no visual delta when the priority chip didn't change. Fix: `FileRecord.is_baseline` now flips to `False` on first modification (scanner + watcher), and `web/app.js` shows a `MODIFIED` pill on drifted files. Regression guarded by `tests/test_api_integration.py::test_modification_flips_is_baseline_and_increments_change_count`.

---

## Phase 8: Agentic MemPalace Upgrade

*Goal: make the agent visibly investigate important file changes, not merely attach registry wording to the system verdict.*

* [x] **Persistent Memory Layer:** Use the real `mempalace` package as a derived context store seeded from the SQL baseline.
* [x] **Baseline Memory Builder:** Build MemPalace identity memories from SQL registry entries after scans/watch initialization.
* [x] **Typed Agent Core:** Keep a local-first MemPalace agent with optional PydanticAI/Ollama typed verdicts and deterministic content inspection.
* [x] **Critical Event Investigation:** Add an agent investigation stage for high-risk events that checks current file state, trusted-change context, MemPalace related memories, content findings, and Windows signature status when relevant.
* [x] **Agent-Owned Notification Narrative:** Route the agent investigation title, summary, evidence, and recommended actions into desktop/email/dashboard notification history.
* [x] **Trusted Change Correlation:** Add first-class package-manager, installer, Windows Update, deployment, and maintenance-window correlation instead of relying only on metadata hints.
* [x] **Richer MemPalace Retrieval:** Query by role, tier, related path history, previous verdicts, and similar content indicators; show the retrieved evidence in the event timeline.
* [x] **UI Investigation Drawer:** Make each critical/high timeline event show agent observations, tool status, confidence, and next steps without requiring raw JSON inspection.
* [x] **Performance Isolation:** Ensure deep agent investigation is queue-limited and reserved for critical/high or policy-selected events so baseline scanning remains fast.
