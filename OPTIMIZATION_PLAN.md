# IntegrityGuard Optimization Plan

This plan tracks the feedback-driven optimization work for usability, notification handling, backlog control, and database scalability.

## Goals

- Make the UI clearer for non-expert users.
- Prevent large baseline scans from creating unbounded pending-analysis backlogs.
- Improve notification handling so only actionable events interrupt the user.
- Evolve storage toward a tree-backed file identity model for large directory sets.
- Keep rename/move timelines continuous across path changes.

## Phase 1 - Backlog-Safe Baseline Scanning

- [x] Stop treating every baseline file as a pending analysis job.
- [x] Store normal baseline files as cheap `FileRecord` rows only.
- [x] Queue baseline analysis only when fast heuristic triage finds suspicious content.
- [x] Expose local baseline context verdicts for recorded files without queueing them.
- [x] Cap explicit baseline reanalysis with `reanalyze_limit`.
- [x] Surface real pending-analysis backlog count in API/UI stats.

## Phase 2 - Queue And Database Performance

- [x] Add indexes for common queue, hash, path, and timeline queries.
- [ ] Add priority-aware analysis-job records separate from raw file events.
- [x] Coalesce duplicate rapid modified events by file identity/path while preserving ignored audit rows.
- [x] Cache analysis by content/change-context hash.
- [x] Add hard caps for low-priority pending jobs under load.

## Phase 3 - UI And Notification Workflow

- [ ] Replace raw timeline-first flow with an operational overview.
- [x] Add scan progress, backlog count, and current mode.
- [x] Add clearer severity counts, automatic first-file focus, and verdict-first analysis cards.
- [ ] Add an in-app notification center with alert states: `needs_review`, `resolved`, `muted`, `ignored`.
- [x] Restrict toasts/desktop notifications to critical/high alerts.
- [x] Make desktop alerts explicit opt-in instead of automatic permission prompting.
- [ ] Batch medium alerts and silently log low/info events.

## Phase 4 - Tree-Backed Storage Model

- [x] Add `DirectoryNode` with `parent_id`, `name`, `full_path`, and `depth`.
- [x] Attach `FileRecord` rows to `DirectoryNode` via `directory_id` and basename.
- [x] Populate directory tree metadata during scanner and watcher paths.
- [x] Add lazy `/api/tree` endpoint for directory-level browsing.
- [x] Add stable `FileIdentity` separate from current path.
- [x] Move timeline queries from `path` to stable `file_id`.
- [ ] Migrate existing `FileRecord`/`FileLog` rows into the tree model.

## Phase 5 - Scan Sessions

- [x] Add `ScanSession` records for scan progress, cancellation, and summaries.
- [x] Track total files discovered, hashed, skipped, suspicious queued, and errors.
- [x] Expose `/api/scan/status` for the current scan.
- [x] Expose persisted `/api/scans` history and `/api/scans/latest`.
- [ ] Add cancel/pause controls in the UI.

## Phase 6 - WizTree-Style Scan Path

WizTree is fast because it avoids opening every file. This project should follow
that pattern where it is safe: enumerate metadata first, identify files by stable
filesystem identity, and hash/analyze only the files that actually need content
inspection.

- [x] Add stable `FileIdentity` records so a file can move/rename without becoming a separate timeline.
- [x] Attach `FileRecord` and `FileLog` rows to `file_id` while keeping path fallback for legacy rows.
- [x] Use platform file IDs from `os.stat` where available before falling back to path/hash matching.
- [x] Make compare scans metadata-first: skip content hashing when size/mtime are unchanged.
- [x] Detect renames by platform file ID before doing same-hash fallback checks.
- [x] Add persisted `ScanSession` counters for discovered, skipped, hashed, renamed, queued, and errored files.
- [ ] Add a bounded hash/analysis work queue so large baseline scans do not block the UI or analysis loop.
- [x] Add content-hash analysis caching so identical file contents reuse prior verdicts.
- [ ] Add a Windows NTFS adapter for MFT/USN-journal enumeration when running with the required privileges.
- [ ] Expose scan mode/capability in the UI: standard walk, metadata-first, or NTFS fast path.

## Current Implementation Slice

Completed first implementation slice:

- quiet baseline scanning
- suspicious-only baseline analysis queueing
- database indexes for queue/path/hash queries
- header queue meter backed by real `FileLog.status='pending'` count
- scan progress API and UI strip
- local notification policy controls for toast and desktop alerts
- directory tree foundation and lazy tree API
- baseline context analysis now renders for recorded baseline events, including legacy rows
- plain operations dashboard UI baseline with neutral styling, pending-analysis stat, filter counts, compact stats, and clearer timeline verdicts

Active WizTree-style slice:

- stable file identity
- timeline queries by `file_id`
- metadata-first reconciliation for unchanged files
- platform file-ID rename detection before hash fallback
