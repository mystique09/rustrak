# Public native test fixtures

`windows.pdb`, `windows.exe`, `linux.debug`, and `macos.dwarf` come from
[Symbolic](https://github.com/getsentry/symbolic/tree/8ef7d6113b99d5c84f1091d093fab6945019f96f/symbolic-testutils/fixtures),
under the included `SYMBOLIC-LICENSE`. They exercise native debug formats and are
independent of the minidump fixtures.

The three `.dmp` files and two `.sym` files come from
[rust-minidump](https://github.com/rust-minidump/rust-minidump/tree/8ff3defb6b9fdb6d36b39d564a069242cdfc32ac/testdata),
under the included `MINIDUMP-LICENSE`. Windows uses `test.dmp` and its `test_app`
symbols; macOS uses `pipeline-inlines-macos-segv.dmp` and its `crash-client`
symbols; Linux uses `linux-mini.dmp` without matching symbols.

These public fixtures test processing. They are not evidence that an Encore
packaged client has passed native acceptance on any platform.
