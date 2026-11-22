#!/usr/bin/env python3
from __future__ import annotations

import argparse
import html
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import threading
import time
from collections import deque
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlsplit

LIB_DIR = Path(__file__).resolve().parent
ROOT_DIR = LIB_DIR.parent
sys.path.insert(0, str(LIB_DIR))
import projects as pj
import report as rp

HOST = "127.0.0.1"
TOKEN = secrets.token_urlsafe(32)
MAX_BODY = 1024 * 1024
RUN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
SID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
DB_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
HTML_FILES = {"service.html", "report.html", "projects.html"}
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
APP_DIR = ROOT_DIR / "webapp"
MONGO_FIXTURE = ROOT_DIR / "config" / "mongo" / "sample-assessment.json"
PROC_KEYWORDS = (("nmap", "scanner"), ("lib/scan.sh", "scan"), ("nmap-toolkit.sh", "toolkit"), ("web.py", "web"), ("start.sh", "launcher"))
LOCK = threading.Lock()
EVENTS: deque[dict] = deque(maxlen=60)
SESSIONS: dict[str, dict] = {}
MONGO_CACHE: dict[str, object] = {"expires": 0.0, "value": None}


def esc(value: object) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def field(data: dict, key: str, default: str = "") -> str:
    value = data.get(key, default)
    if isinstance(value, list):
        value = value[0] if value else default
    if isinstance(value, str):
        return value
    return "" if value is None else str(value)


def lines_to_list(text: str) -> list[str]:
    return [item.strip() for item in text.splitlines() if item.strip()]


def read_json(path: Path) -> dict | None:
    try:
        with path.open(encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def iso_time(stamp: float) -> str:
    return datetime.fromtimestamp(stamp, timezone.utc).isoformat(timespec="seconds")


def log_event(message: str) -> None:
    with LOCK:
        EVENTS.appendleft({"at": time.time(), "message": str(message)[:300]})


def register_session(sid: str, route: str) -> str:
    if not SID_RE.fullmatch(sid or ""):
        raise ValueError("invalid session id")
    now = time.time()
    with LOCK:
        SESSIONS[sid] = {"id": sid, "route": str(route)[:256], "last_seen": now}
        stale = [key for key, value in SESSIONS.items() if now - value["last_seen"] > 45]
        for key in stale:
            SESSIONS.pop(key, None)
    return sid


def active_sessions() -> list[dict]:
    now = time.time()
    with LOCK:
        stale = [key for key, value in SESSIONS.items() if now - value["last_seen"] > 45]
        for key in stale:
            SESSIONS.pop(key, None)
        rows = []
        for value in SESSIONS.values():
            age = int(now - value["last_seen"])
            rows.append({"id": value["id"], "route": value["route"], "age": "now" if age < 5 else f"{age}s"})
    return sorted(rows, key=lambda item: item["id"])


def scan_rows(root: Path) -> list[dict]:
    rows = []
    if not root.is_dir():
        return rows
    for path in root.iterdir():
        name = path.name
        if name == "latest" or not path.is_dir() or not RUN_RE.fullmatch(name):
            continue
        report_path = path / "report.json"
        meta_path = path / "metadata.json"
        data = read_json(report_path)
        if data is None:
            continue
        meta = read_json(meta_path) or {}
        stats = data.get("stats") or {}
        findings = stats.get("findings") or {}
        warnings = sum(value for value in findings.values() if isinstance(value, int))
        rows.append({
            "name": name,
            "path": str(path),
            "generated": str(data.get("generated") or meta.get("started") or ""),
            "profile": str((data.get("meta") or {}).get("profile") or meta.get("profile") or "?"),
            "targets": str((data.get("meta") or {}).get("targets") or meta.get("targets") or ""),
            "hosts_up": stats.get("hosts_up", "-"),
            "hosts_total": stats.get("hosts_total", "-"),
            "ports": stats.get("open_ports", "-"),
            "warnings": warnings,
            "findings": data.get("findings") or [],
            "service": (path / "service.html").is_file(),
            "report": (path / "report.html").is_file(),
        })
    rows.sort(key=lambda item: item["generated"] or item["name"], reverse=True)
    return rows


def project_rows() -> list[dict]:
    rows = []
    for name in pj.all_projects():
        try:
            rows.append(pj.summary(pj.load_project(name)))
        except (OSError, ValueError, KeyError):
            continue
    return rows


def timeline_rows(scans: list[dict], projects: list[dict]) -> list[dict]:
    rows = []
    for item in scans:
        rows.append({
            "time": item["generated"],
            "source": "scan",
            "label": item["name"],
            "event": f"{item['profile']} scan",
            "detail": item["targets"],
            "status": f"{item['warnings']} warning(s)",
            "run": item["name"],
            "project": "",
        })
    for project in projects:
        for item in project.get("timeline", []):
            rows.append({
                "time": item.get("started", ""),
                "source": "project",
                "label": project["name"],
                "event": f"{item.get('profile') or 'scan'} · step {item.get('step') or '-'}",
                "detail": item.get("targets", ""),
                "status": item.get("status", ""),
                "run": Path(str(item.get("run", ""))).name if item.get("run") else "",
                "project": project["name"],
            })
    rows.sort(key=lambda item: item.get("time", ""), reverse=True)
    return rows


def warning_rows(scans: list[dict]) -> list[dict]:
    rows = []
    for item in scans:
        for finding in item["findings"]:
            if finding.get("suppressed"):
                continue
            port = finding.get("port")
            rows.append({
                "severity": str(finding.get("severity", "INFO")),
                "run": item["name"],
                "host": finding.get("host", ""),
                "port": f"{port}/{finding.get('proto') or 'tcp'}" if port else "-",
                "title": finding.get("title", ""),
                "detail": finding.get("detail", ""),
                "advice": finding.get("advice", ""),
                "source": finding.get("source", ""),
                "rule": finding.get("rule_id", ""),
            })
    rows.sort(key=lambda item: (SEV_ORDER.get(item["severity"], 9), item["run"], item["host"]))
    return rows


def process_snapshot() -> list[dict]:
    proc = Path("/proc")
    if not proc.is_dir():
        return []
    try:
        uptime = float((proc / "uptime").read_text(encoding="utf-8").split()[0])
    except (OSError, ValueError, IndexError):
        uptime = 0.0
    boot = time.time() - uptime
    ticks = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
    rows = []
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            raw = (entry / "cmdline").read_bytes().replace(b"\0", b" ").decode("utf-8", "replace").strip()
            stat = (entry / "stat").read_text(encoding="utf-8").split()
            start_time = boot + (int(stat[21]) / ticks if ticks else 0.0)
        except (OSError, ValueError, IndexError):
            continue
        if not raw:
            continue
        lowered = raw.lower()
        kind = next((label for needle, label in PROC_KEYWORDS if needle in lowered), "")
        if not kind:
            continue
        rows.append({
            "pid": int(entry.name),
            "kind": kind,
            "started": iso_time(start_time),
            "command": raw[:300],
        })
    rows.sort(key=lambda item: (item["kind"], item["pid"]))
    return rows


def active_runs(root: Path, scans: list[dict]) -> list[dict]:
    known = {item["name"] for item in scans if (root / item["name"] / "report.json").is_file()}
    rows = []
    if not root.is_dir():
        return rows
    for path in root.iterdir():
        if path.name in known or path.name == "latest" or not path.is_dir() or not RUN_RE.fullmatch(path.name):
            continue
        try:
            files = [item.name for item in path.iterdir() if item.is_file()]
            modified = max((item.stat().st_mtime for item in path.iterdir() if item.is_file()), default=path.stat().st_mtime)
        except OSError:
            continue
        rows.append({
            "name": path.name,
            "modified": iso_time(modified),
            "status": "incomplete",
            "detail": ", ".join(sorted(files)[:6]) or "empty run directory",
        })
    rows.sort(key=lambda item: item["modified"], reverse=True)
    return rows


def trim_json(value: object, depth: int = 0) -> object:
    if depth > 8:
        return "…"
    if isinstance(value, str):
        return value[:2000]
    if isinstance(value, list):
        return [trim_json(item, depth + 1) for item in value[:25]]
    if isinstance(value, dict):
        return {str(key)[:80]: trim_json(item, depth + 1) for key, item in list(value.items())[:60]}
    return value


def mongo_from_fixture() -> dict:
    try:
        with MONGO_FIXTURE.open(encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        data = {}
    collections = []
    for item in data.get("collections", []) if isinstance(data, dict) else []:
        if not isinstance(item, dict):
            continue
        documents = [doc for doc in item.get("documents", []) if isinstance(doc, dict)]
        collections.append({
            "name": str(item.get("name", "collection")),
            "note": str(item.get("note", "")),
            "count": len(documents),
            "documents": [trim_json(doc) for doc in documents[:25]],
        })
    return {
        "source": "fixture",
        "database": str(data.get("database", "sample_assessment")) if isinstance(data, dict) else "sample_assessment",
        "collections": collections,
    }


MONGO_SCRIPT = """
const out = { source: 'mongosh', database: db.getName(), collections: [] };
db.getCollectionNames().filter((name) => !name.startsWith('system.')).forEach((name) => {
  out.collections.push({ name, documents: db.getCollection(name).find({}).limit(25).toArray() });
});
print(JSON.stringify(out));
"""


def mongo_from_mongosh() -> dict | None:
    binary = shutil.which("mongosh")
    if not binary:
        return None
    uri = os.environ.get("XAMLTECH_MONGO_URI", "mongodb://127.0.0.1:27017").strip()
    database = os.environ.get("XAMLTECH_MONGO_DB", "sample_assessment").strip()
    if not DB_RE.fullmatch(database):
        return None
    try:
        result = subprocess.run(
            [binary, "--quiet", f"{uri.rstrip('/')}/{database}", "--eval", MONGO_SCRIPT],
            capture_output=True, text=True, timeout=5, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    start = result.stdout.find("{")
    if start < 0:
        return None
    try:
        payload = json.loads(result.stdout[start:])
    except ValueError:
        return None
    if not isinstance(payload, dict):
        return None
    collections = []
    for item in payload.get("collections", []):
        if not isinstance(item, dict):
            continue
        documents = [doc for doc in item.get("documents", []) if isinstance(doc, dict)]
        collections.append({
            "name": str(item.get("name", "collection")),
            "note": "read from mongosh",
            "count": len(documents),
            "documents": [trim_json(doc) for doc in documents[:25]],
        })
    return {
        "source": "mongosh",
        "database": str(payload.get("database", database)),
        "collections": collections,
    }


def mongo_data() -> dict:
    now = time.time()
    cached = MONGO_CACHE.get("value")
    expires = float(MONGO_CACHE.get("expires", 0.0))
    if cached is not None and expires > now:
        return cached
    value = mongo_from_mongosh() or mongo_from_fixture()
    MONGO_CACHE["value"] = value
    MONGO_CACHE["expires"] = now + 10
    return value


def mongo_summary(data: dict) -> dict:
    return {
        "source": data.get("source", "fixture"),
        "database": data.get("database", ""),
        "collections": [
            {"name": item.get("name", ""), "note": item.get("note", ""), "count": item.get("count", 0)}
            for item in data.get("collections", [])
        ],
    }


def activity_data(root: Path, scans: list[dict]) -> dict:
    with LOCK:
        events = list(EVENTS)
    return {
        "generated": iso_time(time.time()),
        "processes": process_snapshot(),
        "active_runs": active_runs(root, scans),
        "sessions": active_sessions(),
        "events": events,
    }


def state_data(root: Path, default_run: str) -> dict:
    scans = scan_rows(root)
    projects = project_rows()
    return {
        "generated": iso_time(time.time()),
        "version": rp.VERSION,
        "statuses": list(pj.STATUSES),
        "default_run": default_run,
        "reports": scans,
        "projects": projects,
        "timeline": timeline_rows(scans, projects),
        "warnings": warning_rows(scans),
        "activity": activity_data(root, scans),
        "mongo": mongo_summary(mongo_data()),
    }


def state_fingerprint(root: Path) -> tuple:
    seeds = []
    for base in (root, pj.storage_dir(), pj.bundled_dir()):
        if base.is_dir():
            for path in sorted(base.glob("*.json")):
                try:
                    seeds.append((str(path), path.stat().st_mtime_ns))
                except OSError:
                    continue
    seeds.append(tuple((item["pid"], item["started"]) for item in process_snapshot()))
    with LOCK:
        seeds.append(tuple(sorted((key, value["route"]) for key, value in SESSIONS.items())))
    try:
        seeds.append(MONGO_FIXTURE.stat().st_mtime_ns)
    except OSError:
        pass
    return tuple(seeds)


class Handler(BaseHTTPRequestHandler):
    server_version = "XamlTechWeb/2.5"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args) -> None:
        return

    def send_bytes(self, data: bytes, content_type: str, status: HTTPStatus = HTTPStatus.OK,
                   app: bool = False, head: bool = False) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        if app:
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; "
                             "form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
        self.end_headers()
        if not head:
            self.wfile.write(data)

    def send_json(self, payload: object, status: HTTPStatus = HTTPStatus.OK, head: bool = False) -> None:
        data = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_bytes(data, "application/json; charset=utf-8", status, head=head)

    def send_app(self, head: bool = False) -> None:
        try:
            markup = (APP_DIR / "index.html").read_text(encoding="utf-8")
        except OSError:
            self.not_found(head)
            return
        markup = markup.replace("__TOKEN__", TOKEN).replace("__VERSION__", rp.VERSION)
        self.send_bytes(markup.encode("utf-8"), "text/html; charset=utf-8", app=True, head=head)

    def redirect(self, location: str, head: bool = False) -> None:
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()

    def not_found(self, head: bool = False, api: bool = False) -> None:
        if api:
            self.send_json({"ok": False, "error": "not found"}, HTTPStatus.NOT_FOUND, head)
            return
        self.send_bytes(b"Not found\n", "text/plain; charset=utf-8", HTTPStatus.NOT_FOUND, head=head)

    def root(self) -> Path:
        return Path(self.server.root_dir)

    def wants_json(self) -> bool:
        return "application/json" in self.headers.get("Content-Type", "")

    def read_body(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return {}
        if length <= 0 or length > MAX_BODY:
            return {}
        raw = self.rfile.read(length)
        ctype = self.headers.get("Content-Type", "")
        try:
            if "application/json" in ctype:
                data = json.loads(raw.decode("utf-8"))
                return data if isinstance(data, dict) else {}
            return {key: values for key, values in parse_qs(raw.decode("utf-8"), keep_blank_values=True).items()}
        except (UnicodeDecodeError, ValueError):
            return {}

    def token_ok(self, data: dict) -> bool:
        supplied = self.headers.get("X-XamlTech-Token") or field(data, "csrf")
        return bool(supplied) and secrets.compare_digest(supplied, TOKEN)

    def serve_static(self, path: str, head: bool) -> bool:
        files = {"/static/app.css": ("app.css", "text/css; charset=utf-8"),
                 "/static/app.js": ("app.js", "text/javascript; charset=utf-8")}
        if path not in files:
            return False
        filename, content_type = files[path]
        try:
            data = (APP_DIR / filename).read_bytes()
        except OSError:
            return False
        self.send_bytes(data, content_type, head=head)
        return True

    def serve_run_file(self, path: str, head: bool) -> bool:
        match = re.fullmatch(r"/run/([^/]+)/([^/]+)", path)
        if not match:
            return False
        name, filename = match.group(1), match.group(2)
        if not RUN_RE.fullmatch(name) or filename not in HTML_FILES:
            return False
        target = (self.root() / name / filename).resolve()
        try:
            target.relative_to(self.root().resolve())
        except ValueError:
            return False
        try:
            data = target.read_bytes()
        except OSError:
            return False
        self.send_bytes(data, "text/html; charset=utf-8", head=head)
        return True

    def stream_event(self, name: str, payload: dict) -> None:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.wfile.write(f"event: {name}\n".encode("ascii"))
        self.wfile.write(b"data: " + body + b"\n\n")
        self.wfile.flush()

    def stream_events(self, head: bool) -> None:
        if head:
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()
            return
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()
        last = state_fingerprint(self.root())
        try:
            self.stream_event("hello", {"reason": "connected"})
            for tick in range(1, 10_000):
                time.sleep(2)
                current = state_fingerprint(self.root())
                if current != last:
                    self.stream_event("state", {"reason": "workspace changed"})
                    last = current
                if tick % 8 == 0:
                    self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError, ValueError):
            return

    def do_HEAD(self) -> None:
        self.route(head=True)

    def do_GET(self) -> None:
        self.route(head=False)

    def route(self, head: bool = False) -> None:
        parts = urlsplit(self.path)
        path = unquote(parts.path)
        if path.startswith("/api/"):
            self.route_api_get(path, head)
            return
        if path.startswith("/static/"):
            if not self.serve_static(path, head):
                self.not_found(head)
            return
        if path.startswith("/run/"):
            if not self.serve_run_file(path, head):
                self.not_found(head)
            return
        self.send_app(head)

    def route_api_get(self, path: str, head: bool) -> None:
        if path == "/api/state":
            self.send_json(state_data(self.root(), self.server.default_run), head=head)
            return
        if path == "/api/mongo":
            self.send_json(mongo_data(), head=head)
            return
        if path == "/api/events":
            self.stream_events(head)
            return
        self.not_found(head, api=True)

    def do_POST(self) -> None:
        data = self.read_body()
        if not self.token_ok(data):
            self.send_json({"ok": False, "error": "invalid session token"}, HTTPStatus.FORBIDDEN)
            return
        path = unquote(urlsplit(self.path).path)
        if path == "/api/session":
            self.session(data)
            return
        if path == "/api/projects":
            self.create_project(data)
            return
        if path == "/api/projects/assign":
            self.assign_report(data)
            return
        match = re.fullmatch(r"/api/projects/([^/]+)/step", path)
        if match:
            self.add_step(match.group(1), data)
            return
        match = re.fullmatch(r"/api/projects/([^/]+)", path)
        if match:
            self.update_project(match.group(1), data)
            return
        self.not_found(api=True)

    def session(self, data: dict) -> None:
        try:
            sid = register_session(field(data, "id").strip(), field(data, "route"))
        except ValueError as exc:
            self.fail(str(exc))
            return
        self.send_json({"ok": True, "id": sid})

    def fail(self, error: str, status: HTTPStatus = HTTPStatus.BAD_REQUEST) -> None:
        self.send_json({"ok": False, "error": error}, status)

    def created(self, name: str, location: str) -> None:
        log_event(f"Created project {name}")
        if self.wants_json():
            self.send_json({"ok": True, "name": name})
        else:
            self.redirect(location)

    def create_project(self, data: dict) -> None:
        try:
            name = pj.check_name(field(data, "name").strip())
            if any(item["name"] == name for item in project_rows()):
                raise ValueError("project already exists")
            goals = [goal.strip() for goal in field(data, "goals").split(",") if goal.strip()]
            stamp = pj.now()
            project = pj.Project(name, pj.check_text(field(data, "info"), "project info"),
                                 pj.string_list(goals, "goal"), [], [], stamp, stamp)
            pj.save_project(project)
        except (OSError, ValueError) as exc:
            self.fail(str(exc))
            return
        self.created(name, f"/project/{quote(name)}")

    def update_project(self, name: str, data: dict) -> None:
        try:
            project = pj.load_project(name)
            project.info = pj.check_text(field(data, "info"), "project info")
            project.goals = pj.string_list(lines_to_list(field(data, "goals")), "goal")
            for step in project.steps:
                step.goal = pj.check_text(field(data, f"step_goal_{step.id}", step.goal), "step goal", 500)
                step.status = pj.check_status(field(data, f"step_status_{step.id}", step.status))
                step.note = pj.check_text(field(data, f"step_note_{step.id}", step.note), "step note", 2000)
                step.updated = pj.now()
            project.updated = pj.now()
            pj.save_project(project)
        except (OSError, ValueError, KeyError) as exc:
            self.fail(str(exc))
            return
        log_event(f"Updated project {name}")
        self.send_json({"ok": True, "updated": project.updated})

    def add_step(self, name: str, data: dict) -> None:
        try:
            project = pj.load_project(name)
            step_id = pj.check_step(field(data, "step").strip())
            if any(step.id == step_id for step in project.steps):
                raise ValueError("step already exists")
            project.steps.append(pj.Step(step_id, pj.check_text(field(data, "goal"), "step goal", 500),
                                         updated=pj.now()))
            project.updated = pj.now()
            pj.save_project(project)
        except (OSError, ValueError) as exc:
            self.fail(str(exc))
            return
        log_event(f"Added step {step_id} to {name}")
        if self.wants_json():
            self.send_json({"ok": True, "step": step_id})
        else:
            self.redirect(f"/project/{quote(name)}")

    def assign_report(self, data: dict) -> None:
        try:
            name = pj.check_name(field(data, "project").strip())
            run_name = field(data, "run").strip()
            if not RUN_RE.fullmatch(run_name):
                raise ValueError("invalid run name")
            run = (self.root() / run_name).resolve()
            run.relative_to(self.root().resolve())
            if not run.is_dir():
                raise ValueError("run not found")
            project = pj.load_project(name)
            if any(item.run == str(run) for item in project.scans):
                if self.wants_json():
                    self.send_json({"ok": True, "already": True, "project": name, "run": run_name})
                else:
                    self.redirect(f"/project/{quote(name)}?already=1")
                return
            scan = next((item for item in scan_rows(self.root()) if item["name"] == run_name), None)
            if scan is None:
                raise ValueError("report not found")
            step_id = pj.check_step(field(data, "step").strip()) if field(data, "step").strip() else ""
            stamp = pj.now()
            project.scans.append(pj.Scan(
                run=str(run), profile=pj.check_text(scan["profile"], "profile", 100),
                targets=pj.check_text(scan["targets"], "targets", 2000), status="done", started=stamp,
                step=step_id, note=f"Assigned from web service run {run_name}"))
            step = pj.find_step(project, step_id) if step_id else pj.active_step(project)
            if step is not None:
                step.status = "done"
                step.run = str(run)
                step.updated = stamp
            project.updated = stamp
            pj.save_project(project)
        except (OSError, ValueError, KeyError) as exc:
            self.fail(str(exc))
            return
        log_event(f"Assigned run {run_name} to {name}")
        if self.wants_json():
            self.send_json({"ok": True, "project": name, "run": run_name})
        else:
            self.redirect(f"/project/{quote(name)}?assigned=1")


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, port: int, root_dir: Path, default_run: str, handler):
        self.root_dir = str(root_dir.resolve())
        self.default_run = default_run
        super().__init__((address, port), handler)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="web.py")
    parser.add_argument("--root", required=True)
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--run", default="latest")
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    root = Path(args.root).expanduser().resolve()
    if not root.is_dir():
        parser.error(f"output directory does not exist: {root}")
    server = Server(HOST, args.port, root, args.run, Handler)
    print(f"XamlTech web service running at http://{HOST}:{server.server_port}/activity", flush=True)
    print("Press Ctrl+C to stop.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
