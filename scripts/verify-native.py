import argparse
import hashlib
import http.cookiejar
import json
import os
from pathlib import Path
import platform
import secrets
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True, type=Path)
    parser.add_argument("--client", required=True, type=Path)
    parser.add_argument("--sentry-cli", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix="native-", dir=args.output.resolve()))
    server_binary, client_binary = args.server.resolve(), args.client.resolve()
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    base = f"http://127.0.0.1:{port}"
    password = secrets.token_urlsafe(32)
    environment = dict(os.environ, HOST="127.0.0.1", PORT=str(port), PUBLIC_URL=base,
                       DATABASE_URL=f"sqlite://{(root / 'rustrak.db').as_posix()}",
                       INGEST_DIR=str(root / "ingest"), NATIVE_STORAGE_PATH=str(root / "symbols"),
                       SOURCEMAP_STORAGE_PATH=str(root / "sourcemaps"),
                       SESSION_SECRET_KEY=secrets.token_hex(64),
                       CREATE_SUPERUSER=f"qa@example.invalid:{password}",
                       RUSTRAK_DASHBOARD="off", RUSTRAK_TELEMETRY="off", RUST_LOG="warn")
    environment.pop("RUSTRAK_BOOTSTRAP_TOKEN", None)
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    token = None

    def request(path, data=None):
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        body = None if data is None else json.dumps(data).encode()
        with opener.open(urllib.request.Request(base + path, data=body, headers=headers), timeout=30) as response:
            return json.load(response)

    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    with (root / "server.log").open("wb") as log:
        server = subprocess.Popen([str(server_binary)], cwd=root, env=environment,
                                  stdout=log, stderr=subprocess.STDOUT, creationflags=flags)
        try:
            deadline = time.monotonic() + 60
            while True:
                if server.poll() is not None:
                    raise RuntimeError(f"Server exited; inspect {root / 'server.log'}")
                try:
                    request("/auth/login", {"email": "qa@example.invalid", "password": password})
                    break
                except (urllib.error.URLError, ConnectionError):
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.2)
            token = request("/api/tokens", {"description": "Disposable native QA"})["token"]
            project = request("/api/projects", {"name": "Native QA", "slug": "native-qa", "platform": "native"})
            upload_env = dict(environment, SENTRY_URL=base, SENTRY_AUTH_TOKEN=token,
                              SENTRY_ORG="qa", SENTRY_PROJECT="native-qa")
            upload_env.pop("SENTRY_DSN", None)
            symbol_paths = [client_binary]
            if platform.system() == "Windows":
                symbol_paths.append(client_binary.with_name(client_binary.stem.replace("-", "_") + ".pdb"))
            elif platform.system() == "Darwin":
                dsym = root / "native-smoke.dSYM"
                subprocess.run(["dsymutil", str(client_binary), "-o", str(dsym)], check=True)
                symbol_paths.append(dsym)
            with (root / "upload.log").open("wb") as upload_log:
                command = [str(args.sentry_cli.resolve()), "debug-files", "upload", "--include-sources", "--wait"]
                subprocess.run(command + [str(path) for path in symbol_paths], cwd=root,
                               env=upload_env, stdout=upload_log, stderr=subprocess.STDOUT,
                               creationflags=flags, timeout=300, check=True)
            files = request("/api/0/projects/qa/native-qa/files/difs/")
            assert any("debug" in file["features"] for file in files), files
            assert any("sources" in file["features"] for file in files), "Source bundle was not uploaded"
            crash_env = dict(environment, SENTRY_DSN=project["dsn"], NATIVE_SMOKE_DIR=str(root / "crashes"))
            with (root / "client.log").open("wb") as client_log:
                crash = subprocess.run([str(client_binary)], cwd=root, env=crash_env,
                                       stdout=client_log, stderr=subprocess.STDOUT,
                                       creationflags=flags, timeout=60)
            assert crash.returncode != 0, "Client must terminate from a native crash"
            project_id = project["id"]
            deadline = time.monotonic() + 120
            while True:
                issues = request(f"/api/projects/{project_id}/issues")
                issues = issues["items"]
                if issues:
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError(f"Native event did not arrive; inspect {root}")
                time.sleep(0.5)
            assert len(issues) == 1, issues
            issue_id = issues[0]["id"]
            events = request(f"/api/projects/{project_id}/issues/{issue_id}/events")
            events = events["items"]
            assert len(events) == 1, events
            event = request(f"/api/projects/{project_id}/issues/{issue_id}/events/{events[0]['id']}")["data"]
            assert event["release"] == "rustrak-native-smoke@1", event
            assert event["tags"]["native_smoke"] == "true", event
            breadcrumbs = event["breadcrumbs"]
            if isinstance(breadcrumbs, dict):
                breadcrumbs = breadcrumbs["values"]
            assert any(item["message"] == "before native crash" for item in breadcrumbs), event
            assert not event.get("errors"), event.get("errors")
            exception = event["exception"]["values"][0]
            assert exception["mechanism"] == {"type": "minidump", "handled": False}, exception
            frames = exception["stacktrace"]["frames"]
            for function in ["native_crash_leaf", "native_crash_middle"]:
                matched = [frame for frame in frames if function in frame.get("function", "")]
                assert matched, f"Missing {function}: {frames}"
                assert any(frame.get("lineno", 0) > 0 and frame.get("filename", "").endswith("main.rs") for frame in matched), matched
                assert any(frame.get("context_line") for frame in matched), f"Missing uploaded source context: {matched}"
                if platform.system() == "Windows":
                    assert any(frame.get("trust") == "cfi" for frame in matched), f"Windows caller must use uploaded unwind data: {matched}"
            summary = {"os": platform.platform(), "architecture": platform.machine(),
                       "server_sha256": hashlib.sha256(server_binary.read_bytes()).hexdigest(),
                       "client_sha256": hashlib.sha256(client_binary.read_bytes()).hexdigest(),
                       "client_exit": crash.returncode, "event_id": event["event_id"],
                       "debug_formats": sorted({file["symbolType"] for file in files}),
                       "resolved_frames": [{key: frame[key] for key in ["function", "filename", "lineno", "context_line", "trust"] if key in frame}
                                           for frame in frames if "native_crash_" in frame.get("function", "")],
                       "production_changed": False}
            (args.output / "native-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
            print(json.dumps(summary, indent=2))
        except Exception:
            for filename in ["server.log", "upload.log", "client.log"]:
                path = root / filename
                if path.exists():
                    tail = path.read_text(errors="replace")[-8000:]
                    tail = tail.replace(password, "[redacted]")
                    if token:
                        tail = tail.replace(token, "[redacted]")
                    print(f"{filename}:\n{tail}", flush=True)
            raise
        finally:
            server.terminate()
            try:
                server.wait(timeout=15)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=10)


if __name__ == "__main__":
    main()
