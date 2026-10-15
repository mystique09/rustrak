# Native Crash and Symbols Implementation Plan

> Implement inline in this session; no subagents. User authorized implementation and commits on the fork. No upstream pull requests.

**Goal:** Accept Encore native crashes and Sentry CLI debug files, resolving Windows, macOS and Linux frames without losing SDK metadata.

**Architecture:** Persist event and native attachment together; enrich in asynchronous digest before grouping. Store validated symbols by project, debug identity and architecture; resolve native frames with existing Rust libraries. Isolate expensive stack walking from HTTP handlers.

**Tech Stack:** Rust, Actix, SQLx SQLite/PostgreSQL, rust-minidump, Symbolic.

**Spec:** `docs/native-crash-design.md`

## Global constraints

- Branch: `codex/native-crash-symbols` on `mystique09/rustrak` only.
- Never create an upstream PR. Keep production on GlitchTip.
- Preserve event identity, release, tags, breadcrumbs and existing SDK exceptions.
- No private crash dumps or source bundles in Git.
- Keep upload and event access isolated by project.

## Review focus

- Attachment ordering, duplicate delivery and restart before digest must preserve one event.
- Invalid dumps, missing symbols and failed workers must preserve SDK metadata with diagnostic status.
- Debug IDs with nonzero PDB age and overlapping module-relative addresses must never cross-resolve.
- Upload checksums, size bounds, authorization and concurrent retries must be checked.
- Existing JS processing and both database backends must continue to work.

## Tasks

- [x] Establish a compiling baseline and native regression tests.
- [x] Implement native symbol parsing, storage and Sentry CLI upload endpoints, with project-access tests.
- [x] Implement durable minidump envelope ingestion and asynchronous enrichment, with retry and metadata tests.
- [x] Verify native debug formats, source context and stack walking against public/synthetic fixtures.
- [x] Add fork-only verification workflow and operator documentation; record Windows/macOS/Linux evidence separately.
- [ ] Run formatting, lint and relevant suites; review the complete diff; commit and push only to the fork branch.

## Progress

- Fork created and isolated checkout at `F:/Dev/rustrak`. Upstream push URL disabled.
- iDate checkout updated to merged `main` at `e3e7846`; no iDate changes required.
- Installed repository-local Rust 1.98.1 using the existing Visual Studio build tools. Docker is unavailable locally; PostgreSQL tests run in fork CI.
- Baseline: 350 library tests. Fixed the existing Unix-only directory-fsync assumption so the durable spool works on Windows.
- Native regression coverage includes real PDB/PE/dSYM/ELF files, public Windows/macOS/Linux dumps, source bundles, PDB age, module/architecture isolation, upload ownership/checksums, duplicate delivery, recovery and failed-worker behavior.
- Windows 11 AMD64 smoke: a fresh native access violation, Sentry SDK 0.49.3, Sentry CLI 3.8.0, PE/PDB/source-bundle upload, resolved leaf/caller frames with source context, and preserved release/tags/breadcrumbs. This is synthetic server acceptance, not packaged Encore consent/UI acceptance.
- Broad parallel tests exposed a pre-existing bootstrap environment-variable race; rerunning serially avoids the shared-environment interference without changing unrelated bootstrap code.
- Production GlitchTip, Dokploy, hostname and iDate release workflows remain unchanged. Existing Windows uploads need the matching executable alongside the PDB for complete unwind data when staging Rustrak.
