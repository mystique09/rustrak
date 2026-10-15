import argparse
import http.cookiejar
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid


def docker(*arguments, check=True):
    return subprocess.run(["docker", *arguments], check=check, capture_output=True, text=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    manifest = root / "tests" / "fixtures" / "idate-projects.json"
    projects = json.loads(manifest.read_text())["projects"]
    suffix = secrets.token_hex(6)
    network, database, server = [f"rustrak-native-{kind}-{suffix}" for kind in ["net", "db", "app"]]
    password = secrets.token_urlsafe(32)
    token = None
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    base = f"http://127.0.0.1:{port}"
    docker("network", "create", network)
    try:
        with tempfile.TemporaryDirectory(prefix="rustrak-container-") as temporary:
            directory = Path(temporary)
            database_env = directory / "database.env"
            database_env.write_text(f"POSTGRES_PASSWORD={password}\nPOSTGRES_DB=rustrak\n")
            database_env.chmod(0o600)
            docker("run", "-d", "--name", database, "--network", network,
                   "--env-file", str(database_env), "postgres:18.3-alpine")
            for _ in range(90):
                if docker("exec", database, "pg_isready", "-h", "127.0.0.1", "-U", "postgres", check=False).returncode == 0:
                    break
                time.sleep(1)
            else:
                raise RuntimeError("PostgreSQL did not become ready")
            environment = directory / "server.env"
            environment.write_text(
                f"DATABASE_URL=postgres://postgres:{password}@{database}:5432/rustrak\n"
                f"SESSION_SECRET_KEY={secrets.token_hex(64)}\n"
                f"CREATE_SUPERUSER=qa@example.invalid:{password}\n"
                f"PUBLIC_URL={base}\n"
                "PROJECT_IMPORT_FILE=/run/projects.json\n"
                "NATIVE_STORAGE_PATH=/data/native\nINGEST_DIR=/data/ingest\n"
                "SOURCEMAP_STORAGE_PATH=/data/sourcemaps\n"
                "RUSTRAK_TELEMETRY=off\nRUST_LOG=warn\n")
            environment.chmod(0o600)
            docker("run", "-d", "--name", server, "--network", network,
                   "--memory", "2g", "--pids-limit", "256",
                   "--env-file", str(environment),
                   "--mount", f"type=bind,source={manifest},target=/run/projects.json,readonly",
                   "-p", f"127.0.0.1:{port}:8080", args.image)
            opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

            def request(path, value=None, payload=None, headers=None):
                request_headers = dict(headers or {})
                if token:
                    request_headers["Authorization"] = f"Bearer {token}"
                if value is not None:
                    payload = json.dumps(value).encode()
                    request_headers["Content-Type"] = "application/json"
                with opener.open(urllib.request.Request(base + path, data=payload, headers=request_headers), timeout=15) as response:
                    return response.read()

            def ready():
                for _ in range(120):
                    try:
                        if json.loads(request("/health/ready"))["status"] == "ready":
                            docker("exec", server, "/app/rustrak", "--healthcheck")
                            return
                    except (urllib.error.URLError, ConnectionError):
                        pass
                    time.sleep(1)
                raise RuntimeError("Native container did not become ready")

            ready()
            dashboard = request("/").decode()
            assert "<html" in dashboard and "<script" in dashboard, "Dashboard is absent from image"
            request("/auth/login", {"email": "qa@example.invalid", "password": password})
            token = json.loads(request("/api/tokens", {"description": "Container verification"}))["token"]
            for identity in projects:
                project = json.loads(request(f"/api/projects/{identity['id']}"))
                assert project["slug"] == identity["slug"]
                assert identity["sentry_key"] in project["dsn"].replace("-", "")
            upload_env = dict(os.environ, SENTRY_URL=base, SENTRY_AUTH_TOKEN=token,
                              SENTRY_ORG="idate-encore", SENTRY_PROJECT=projects[0]["slug"])
            upload_env.pop("SENTRY_DSN", None)
            fixture = root / "apps" / "server" / "tests" / "fixtures" / "native"
            subprocess.run(["npx", "--yes", "@sentry/cli@3.8.0", "debug-files", "upload", "--wait",
                            str(fixture / "windows.sym")], env=upload_env, check=True)
            event_id = uuid.uuid4().hex
            event = json.dumps({"event_id": event_id, "release": "container-check@1",
                                "breadcrumbs": [{"message": "before fixture crash"}]}).encode()
            dump = (fixture / "windows.dmp").read_bytes()
            envelope = b"\n".join([
                json.dumps({"event_id": event_id}).encode(),
                json.dumps({"type": "event", "length": len(event)}).encode(), event,
                json.dumps({"type": "attachment", "attachment_type": "event.minidump", "length": len(dump)}).encode(),
                dump, b""])
            path = f"/api/1/envelope/?sentry_key={projects[0]['sentry_key']}"
            request(path, payload=envelope)
            request(path, payload=envelope)
            for _ in range(90):
                issues = json.loads(request("/api/projects/1/issues"))["items"]
                if issues:
                    break
                time.sleep(1)
            assert len(issues) == 1, issues
            issue_id = issues[0]["id"]
            events_path = f"/api/projects/1/issues/{issue_id}/events"
            events = json.loads(request(events_path))["items"]
            assert len(events) == 1, events
            event_data = json.loads(request(f"{events_path}/{events[0]['id']}"))["data"]
            frames = event_data["exception"]["values"][0]["stacktrace"]["frames"]
            assert any(frame.get("function") for frame in frames), "Native worker did not resolve symbols"
            assert event_data["release"] == "container-check@1"
            assert not event_data.get("errors"), event_data.get("errors")
            try:
                request(f"/api/2/envelope/?sentry_key={projects[0]['sentry_key']}", payload=envelope)
                raise AssertionError("Client key was accepted for the server project")
            except urllib.error.HTTPError as error:
                assert error.code == 401, error.code
            docker("restart", server)
            ready()
            assert len(json.loads(request(events_path))["items"]) == 1
            next_project = json.loads(request("/api/projects", {"name": "After import", "platform": "native"}))
            assert next_project["id"] > 2
            print(json.dumps({"image": args.image, "database": "postgres",
                              "dashboard": True, "dsn_compatibility": True,
                              "resolved_native_frames": sum(bool(frame.get("function")) for frame in frames),
                              "restart_persistence": True, "production_changed": False}))
    except Exception:
        log = docker("logs", "--tail", "60", server, check=False)
        diagnostic = (log.stdout + log.stderr).replace(password, "[redacted]")
        if token:
            diagnostic = diagnostic.replace(token, "[redacted]")
        print(diagnostic)
        raise
    finally:
        for container in [server, database]:
            docker("rm", "-fv", container, check=False)
        docker("network", "rm", network, check=False)


if __name__ == "__main__":
    main()
