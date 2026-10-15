# Native crash verification

The implementation is on `mystique09/rustrak`, branch
`codex/native-crash-symbols`. The verified server code is
`d4d378d6478148277bcb21de420491d56a40b903`, based on Rustrak 0.16.4 at
`5c1304288550c4fe1a4f3b72052c77dda7578a40`. iDate main was updated to
`e3e7846`, including Mac Intel support. No production configuration changed.

## Local Windows acceptance

On Windows 11 10.0.22631 AMD64, Rust 1.98.1 built the server and the synthetic
Sentry SDK 0.49.3 client. Sentry CLI 3.8.0 uploaded the matching PE, PDB and
source bundle to a disposable loopback instance. The client then terminated
with native access violation `3221225477` (`0xc0000005`).

The event retained its release, tag and breadcrumb. Both
`native_crash_leaf` and `native_crash_middle` resolved to `main.rs`, with line
numbers and uploaded source context. Both caller frames had `trust: cfi`,
proving the uploaded executable's unwind information was used.

| Binary | SHA-256 |
| --- | --- |
| Server | `9b15ab03dda29ef8f400b45191f2f7914782c7b2ddcf2d47e39d26d68380ddd3` |
| Synthetic client | `7515aa33dd7bd12d95c3719344f3e87b3241c662a56f3bbb8038b723b20fd0be` |

The earlier smoke check accepted stack-scanned callers. Review exposed a
missing symbol provider during unwinding, an `amd64`/`x86_64` mismatch and a
duplicate module header in generated PE unwind files. The final regression
checks require symbols while walking the stack and require CFI caller frames
for the Windows smoke test.

## Automated checks

The [fork verification run](https://github.com/mystique09/rustrak/actions/runs/38796926699)
passed all five jobs: real synthetic crashes on Windows, Linux, macOS Apple
Silicon and macOS Intel, plus native integration tests against a real
temporary PostgreSQL database.

The complete local native-enabled server suite passed: 1,414 tests, zero
failures and 56 existing ignored tests, using
`cargo test --locked --features native --tests -- --test-threads=1`.
Serial execution avoids an existing bootstrap environment-variable race in
the upstream tests. Formatting and native Clippy with warnings denied passed.
The default non-native build and PostgreSQL/native build also compile.

PostgreSQL CI passed all ten native integration tests. Windows Server 2022
AMD64 CI passed the fresh access-violation test, including CFI caller frames.
Linux x86_64 and macOS Apple Silicon and Intel passed fresh segmentation-fault
tests. Each test checks file/line resolution,
uploaded source context, release, tag, breadcrumb and single-event ingestion.
Windows, Linux and Apple Silicon used CFI for the checked callers; Intel
macOS used frame pointers. Both are recorded per frame in the evidence.

The [machine-readable evidence](native-crash-evidence.json) records each
runner's exact OS, architecture, server/client SHA-256 hashes, crash exit,
uploaded formats and resolved caller frames. These are synthetic test events;
no private crash dumps or production source bundles are included.

Apple Silicon verification exposed Symbolic 13.9's sparse dSYM section-offset
bug. The public regression fixture failed with `BadDebugInfo/UnexpectedEof`
on 13.9 and passes with pinned `14.0.0-alpha.4`. See the
[upstream fix](https://github.com/getsentry/symbolic/commit/54486a9661aa56b215022d9c9d9f712b51538697).

## Remaining production gate

This evidence covers the server and a synthetic SDK client. Current packaged
Encore clients, consent and reporter startup UI, staging dashboard rendering,
retention/backups and operational recovery still need acceptance. Production
continues to use GlitchTip at `glitchtip.fluffbeat.com`. No upstream PR was
created, and the fork's upstream push URL is disabled.

Docker is not installed on the local Windows host. The Docker QA compose file
and release container build have not been exercised; native CI uses host
binaries. A staging container build and packaged-client acceptance remain
separate from the passing server tests.

See [operations and migration gate](native-crash-operations.md) for supported
formats, upload commands, resource limits and deliberately unsupported paths.
