# iDate integration

This fork's `codex/rustrak-integration` branch builds on native crash support.
The companion iDate branch owns staging Compose, identity mappings, symbol
uploads and deployment/acceptance instructions. Production stays on GlitchTip.
No upstream PR or upstream registry publication is part of this work.

Set `PROJECT_IMPORT_FILE` to a mounted manifest to import after migrations
and before workers/HTTP start. Or run `rustrak --import-projects projects.json`
with `DATABASE_URL` configured. The command migrates/imports without starting
the server, creating accounts or generating API tokens.

The schema is `{"version":1,"projects":[{"id":1,"name":"Client","slug":"client",
"sentry_key":"168719e89a3d4871b01c2958e71ea683"}]}`.
Unknown fields, invalid/duplicate identities, unsupported versions, more than
100 projects and inputs exceeding 64 KiB fail before writes. Inserts are one
transaction. Matching ID/slug/key tuples are preserved, including renamed
projects. Conflicts fail without overwriting projects. PostgreSQL's sequence
advances without rewinding. Subsequent normal project creation works.

These public keys preserve existing DSNs when the hostname is retained.
This does not migrate historical events, debug files, accounts or tokens.
Imported projects use platform `native`. Global administrators can access them;
other users need membership. Use a separate staging database.

`rustrak --healthcheck` checks loopback `/health/ready` on `PORT` (default 8080)
with a five-second timeout and no proxy/redirect. It needs no external tools
in the distroless image and fails if the database is unavailable.

`Native staging image` builds PostgreSQL/native and the bundled dashboard.
Its container check uploads a public Breakpad fixture and processes a Windows
minidump inside the Linux image, checks resolved frames, both imported identities,
project isolation and restart persistence. This is separate from the four-platform
fresh-crash workflow and actual Encore acceptance. Manual `publish=true` publishes
only the tested image to `ghcr.io/mystique09/rustrak-native` and reports its digest.
The upstream Docker Hub/npm workflow is not invoked.

Run `cargo test --locked --features native --test project_import_test
--test native_crash_test`, then the native smoke script with
`--project-manifest tests/fixtures/idate-projects.json`. PostgreSQL uses the same
import tests in the fork's native verification workflow.
