# Native crash support in this fork

The `codex/native-crash-symbols` branch belongs to `mystique09/rustrak`.
Do not create an upstream pull request. Production iDate continues to use
GlitchTip at `glitchtip.fluffbeat.com`; this branch does not alter Dokploy,
DNS, the production DSN, release uploads or iDate deployment files.

## Build and run an isolated instance

Build the server with `cargo build --locked --features native --bin rustrak`
from `apps/server`. The default database is SQLite. For PostgreSQL use
`--no-default-features --features postgres,native`. The existing Dockerfile
accepts `--build-arg FEATURES=sqlite,native` or `postgres,native`.

Symbolic is pinned to `14.0.0-alpha.4` because 13.9 misreads sparse dSYM
section offsets. The [upstream fix](https://github.com/getsentry/symbolic/commit/54486a9661aa56b215022d9c9d9f712b51538697)
is covered by a public Apple Silicon dSYM regression fixture here. This
prerelease dependency is an additional reason to retain the staging gate.

Set `NATIVE_STORAGE_PATH` to a persistent writable directory (default
`/data/native`). Persist `INGEST_DIR` as well: accepted events and their
minidumps share a durable spool record until the digest commits. Back up the
database, native storage and ingest spool together. Native files are immutable
and organized by project and SHA-256; the database indexes their debug IDs and
architectures. Deleting a project removes database references, but currently
leaves its native files on disk. Remove such files only during a planned,
backed-up maintenance window; native symbol retention is not yet integrated
with the dashboard storage cleanup controls.

For a separate local Docker instance, set `NATIVE_QA_SESSION_SECRET` to 128
random hexadecimal characters and `NATIVE_QA_SUPERUSER` to disposable
`email:password` credentials, then run
`docker compose -f docker-compose.native-qa.yml up --build`.
It binds only to loopback port 8089 and uses its own volume. Build the existing
dashboard bundle before the Docker build if the QA instance needs its UI.

## Upload and ingest

Use an authenticated token belonging to a project editor or administrator.
Keep it in CI or the development environment, never in a shipped client.
`sentry-cli` 3.8.0 can upload through the existing chunk protocol:

```sh
export SENTRY_URL=http://localhost:8089
export SENTRY_ORG=qa
export SENTRY_PROJECT=native-qa
export SENTRY_AUTH_TOKEN=<QA-token>
sentry-cli debug-files upload --wait path/to/symbols
```

Upload PDB **and executable** for Windows so unwind information is available;
upload the Mach-O executable and matching dSYM for macOS; upload ELF binaries
and matching split debug files for Linux. Fat Mach-O objects are indexed
separately by architecture. Breakpad symbols are also accepted. Add
`--include-sources` only when source upload is authorized. Embedded source
bundles supply frame context; the worker never fetches source URLs or reads
source files from the server host.

The organization slug is a compatibility placeholder, matching Rustrak's
existing source-map API. Project access is enforced by the authenticated
user's project membership. Uploaded chunks are owned by the uploading user;
knowing another user's SHA-1 does not grant native assembly access. Chunks
expire after 24 hours and are collected hourly once no source-map assembly
references them. Native metadata can be listed through the project-scoped
`/api/0/projects/{org}/{project}/files/difs/` endpoint.

The native Sentry SDK sends an envelope containing an event and an
`attachment` whose `attachment_type` is `event.minidump`. Either item order
works. A dump-only envelope creates a native event with the same envelope ID.
Existing SDK exceptions are preserved. Minidump enrichment preserves release,
tags, breadcrumbs and other SDK metadata before grouping the issue. Native
JSON frames with `debug_meta.images` can also be resolved without a dump.
Debug IDs retain the PDB age; frame lookup requires the matching loaded image
and architecture. Existing JavaScript source-map processing still runs.

Only minidump attachments are processed. General attachments, Apple `.ips`
reports, the multipart minidump endpoint, symbol servers and automatic
reprocessing after late symbol uploads are not implemented. Upload symbols
before generating verification crashes. Missing symbols leave addresses with
`symbolicator_status`; malformed dumps or processing timeouts retain the SDK
event with a `native_processing_error`. Database and spool failures remain
retryable. Native crash envelopes receive an explicit error on builds without
the `native` feature.

## Processing limits

The server accepts one minidump up to 20 MiB per envelope and debug files up to
512 MiB (at most 16 objects). Two child workers run concurrently, each with a
60-second deadline and 32 MiB JSON output limit. Symbol assembly and event
digest share two admission slots, acquired before reading large payloads.
This bounds active payload memory; during uploads, other events can wait in
the durable spool. Child processes receive no inherited credentials;
their temporary files stay in the native storage job directory. Linux workers
have a 2 GiB address-space limit and Windows workers have a 2 GiB process-memory
job limit. macOS verification uses the time, input and output limits without an
OS memory limit. These are process/resource boundaries, not a security sandbox.

Filesystem publication is atomic; files are synced before publication. On
Unix the parent directory is also synced. Windows cannot provide that same
directory-fsync guarantee through this implementation; process-restart tests
are distinct from sudden-power-loss guarantees.

## Verification and migration gate

Run `cargo test --locked --features native --lib --test native_crash_test` in
`apps/server`. Public fixtures cover PDB, PE, dSYM, ELF, source bundles and
Windows/macOS/Linux dumps. These are not packaged-client acceptance tests.

`tests/native-smoke` builds a synthetic crash executable using iDate's pinned
Sentry SDK 0.49.3. `scripts/verify-native.py` creates a disposable loopback
server, uploads native files and source bundles with Sentry CLI 3.8.0, causes
a real native fault, and checks resolved leaf/caller frames, file names, line
numbers, source context and preserved metadata. Its JSON evidence records OS,
architecture and executable SHA-256 hashes. It rejects non-loopback DSNs.

The `Native crash verification` workflow runs only in this fork, on Linux,
Windows, Apple Silicon and Intel Macs, plus PostgreSQL integration tests.
It does not publish binaries or deploy anything. Logs and dumps remain local
to each runner; only the synthetic verification summary is printed.

Production migration remains blocked until current packaged Encore clients
pass crash capture and confirmed ingestion on Windows, macOS Intel/Apple
Silicon and Linux, and the team has checked symbol coverage, UI stack display,
retention/backups and failure recovery in staging. Keep consent/UI acceptance
separate from this server's automated evidence. A later migration also needs
project/token provisioning and a deliberate DSN-key compatibility strategy;
keeping the hostname alone does not preserve GlitchTip's project keys.
