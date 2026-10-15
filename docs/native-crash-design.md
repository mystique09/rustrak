# Native crash support

Implement native crash ingestion and symbolication in the mystique09 fork. Keep all work on `codex/native-crash-symbols`; never create an upstream pull request. Production iDate remains on GlitchTip. Windows, macOS and Linux acceptance are separate gates before any later deployment decision.

Reuse the behavior and regression cases from iDate's GlitchTip integration: merge minidump crashes with SDK metadata, preserve event IDs and breadcrumbs, normalize debug IDs without truncating PDB age, and constrain symbol lookup to the matching module. Keep existing events if processing fails.

The source behavior is iDate commit `e3e7846`, specifically
`scripts/dockerfiles/glitchtip-native-stackwalk.py`,
`glitchtip-native-envelope.patch`, `test_glitchtip_native_envelope.py` and
`test_glitchtip_native_stacktrace.py`. The fork implements these behaviors in
Rust using the same rust-minidump 0.27 stack-walking engine, plus Symbolic 14.0.0-alpha.4
for native debug files, unwind data, inline frames and embedded source bundles.

The ingest path will persist native attachments with their event before acknowledging the request. Native enrichment runs in the existing asynchronous digest pipeline before issue grouping. Uploaded symbols are project-scoped and indexed by debug ID and architecture. Native uploads use the Sentry debug-file chunk/assemble protocol so the existing release commands remain usable. Symbolic handles debug formats and source bundles; rust-minidump supplies stack walking. Processing limits prevent crash parsing from occupying request workers indefinitely.

No iDate deployment configuration, production data or DNS is changed by this work. Native verification uses synthetic fixtures and local or CI builds. Captured real crash dumps are never committed or uploaded as public fixtures.
