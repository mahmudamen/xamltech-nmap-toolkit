#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import shlex
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

SCHEMA = 1
STATUSES = ("todo", "done", "failed", "needs-action")
NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
STEP_RE = re.compile(r"^[a-z][a-z0-9_-]{0,39}$")
MAX_BYTES = 1024 * 1024


def now() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def storage_dir() -> Path:
    raw = os.environ.get("XAMLTECH_NMAP_PROJECTS_DIR")
    if raw:
        return Path(raw).expanduser().resolve()
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base).expanduser().resolve() / "xamltech-nmap-toolkit" / "projects"


def bundled_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "config" / "projects"


def check_name(name: str) -> str:
    if not NAME_RE.fullmatch(name or ""):
        raise ValueError(f"invalid project name: {name!r}")
    return name


def check_step(step: str) -> str:
    if not STEP_RE.fullmatch(step or ""):
        raise ValueError(f"invalid step id: {step!r}")
    return step


def check_status(status: str) -> str:
    if status not in STATUSES:
        raise ValueError(f"status must be one of {', '.join(STATUSES)}")
    return status


def check_text(value: object, label: str, limit: int = 4000) -> str:
    if not isinstance(value, str) or len(value) > limit:
        raise ValueError(f"invalid {label}")
    if any(ord(ch) < 32 and ch not in "\t" for ch in value):
        raise ValueError(f"invalid control character in {label}")
    return value


def check_argv(value: object) -> list[str]:
    if not isinstance(value, list) or len(value) > 100:
        raise ValueError("invalid argument list")
    return [check_text(token, "argument", 4096) for token in value]


def string_list(value: object, label: str) -> list[str]:
    if not isinstance(value, list) or len(value) > 100:
        raise ValueError(f"invalid {label}")
    return [check_text(item, label, 500) for item in value]


@dataclass
class Step:
    id: str
    goal: str
    status: str = "todo"
    note: str = ""
    run: str = ""
    argv: list[str] = field(default_factory=list)
    updated: str = ""


@dataclass
class Scan:
    run: str
    profile: str
    targets: str
    status: str
    started: str
    argv: list[str] = field(default_factory=list)
    step: str = ""
    note: str = ""


@dataclass
class Project:
    name: str
    info: str
    goals: list[str]
    steps: list[Step]
    scans: list[Scan]
    created: str
    updated: str


def step_from_dict(data: object) -> Step:
    if not isinstance(data, dict):
        raise ValueError("invalid step record")
    return Step(
        id=check_step(data.get("id", "")),
        goal=check_text(data.get("goal", ""), "step goal", 500),
        status=check_status(data.get("status", "todo")),
        note=check_text(data.get("note", ""), "step note", 2000),
        run=check_text(data.get("run", ""), "step run", 1000),
        argv=check_argv(data.get("argv", [])),
        updated=check_text(data.get("updated", ""), "step timestamp", 60),
    )


def scan_from_dict(data: object) -> Scan:
    if not isinstance(data, dict):
        raise ValueError("invalid scan record")
    return Scan(
        run=check_text(data.get("run", ""), "scan run", 1000),
        profile=check_text(data.get("profile", ""), "scan profile", 100),
        targets=check_text(data.get("targets", ""), "scan targets", 2000),
        status=check_status(data.get("status", "todo")),
        started=check_text(data.get("started", ""), "scan timestamp", 60),
        argv=check_argv(data.get("argv", [])),
        step=check_text(data.get("step", ""), "scan step", 100),
        note=check_text(data.get("note", ""), "scan note", 2000),
    )


def project_from_dict(data: object, expected: str) -> Project:
    if not isinstance(data, dict) or data.get("schema_version") != SCHEMA:
        raise ValueError("unsupported project schema")
    name = check_name(data.get("name", ""))
    if name != expected:
        raise ValueError("project name does not match file")
    steps = data.get("steps", [])
    scans = data.get("scans", [])
    if not isinstance(steps, list) or len(steps) > 100:
        raise ValueError("invalid step list")
    if not isinstance(scans, list) or len(scans) > 500:
        raise ValueError("invalid scan list")
    return Project(
        name=name,
        info=check_text(data.get("info", ""), "project info"),
        goals=string_list(data.get("goals", []), "goal"),
        steps=[step_from_dict(item) for item in steps],
        scans=[scan_from_dict(item) for item in scans],
        created=check_text(data.get("created", ""), "created timestamp", 60),
        updated=check_text(data.get("updated", ""), "updated timestamp", 60),
    )


def project_to_dict(project: Project) -> dict:
    return {
        "schema_version": SCHEMA,
        "name": project.name,
        "info": project.info,
        "goals": project.goals,
        "steps": [step.__dict__ for step in project.steps],
        "scans": [scan.__dict__ for scan in project.scans],
        "created": project.created,
        "updated": project.updated,
    }


def atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".project.", dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def project_path(name: str) -> Path:
    check_name(name)
    user_path = storage_dir() / f"{name}.json"
    if user_path.is_file():
        return user_path
    sample = bundled_dir() / f"{name}.json"
    if sample.is_file():
        return sample
    raise FileNotFoundError(f"unknown project: {name}")


def load_project(name: str) -> Project:
    path = project_path(name)
    if path.stat().st_size > MAX_BYTES:
        raise ValueError("project file is too large")
    with path.open(encoding="utf-8") as fh:
        data = json.load(fh)
    return project_from_dict(data, name)


def save_project(project: Project) -> None:
    path = storage_dir() / f"{check_name(project.name)}.json"
    atomic_write(path, json.dumps(project_to_dict(project), indent=2, sort_keys=True))


def all_projects() -> list[str]:
    names: set[str] = set()
    for directory in (storage_dir(), bundled_dir()):
        if not directory.is_dir():
            continue
        for path in directory.glob("*.json"):
            try:
                names.add(check_name(path.stem))
            except ValueError:
                continue
    return sorted(names)


def find_step(project: Project, step_id: str) -> Step:
    for step in project.steps:
        if step.id == step_id:
            return step
    raise ValueError(f"unknown step: {step_id}")


def active_step(project: Project) -> Step | None:
    for step in project.steps:
        if step.status != "done":
            return step
    return None


def overall_status(project: Project) -> str:
    statuses = {step.status for step in project.steps}
    if "failed" in statuses:
        return "failed"
    if "needs-action" in statuses:
        return "needs-action"
    if project.steps and statuses == {"done"}:
        return "done"
    return "in-progress"


def summary(project: Project) -> dict:
    counts = {status: 0 for status in STATUSES}
    for step in project.steps:
        counts[step.status] += 1
    plan = [
        {"order": index, "id": step.id, "goal": step.goal, "status": step.status,
         "note": step.note, "run": step.run}
        for index, step in enumerate(project.steps, 1)
    ]
    timeline = [
        {"order": index, "started": scan.started, "profile": scan.profile,
         "status": scan.status, "targets": scan.targets, "run": scan.run, "step": scan.step}
        for index, scan in enumerate(sorted(project.scans, key=lambda item: item.started), 1)
    ]
    nxt = active_step(project)
    return {
        "name": project.name,
        "info": project.info,
        "goals": project.goals,
        "status": overall_status(project),
        "counts": counts,
        "plan": plan,
        "timeline": timeline,
        "next_action": {"step": nxt.id, "goal": nxt.goal, "status": nxt.status} if nxt else None,
    }


def cmd_exists(args: argparse.Namespace) -> int:
    try:
        load_project(args.name)
    except FileNotFoundError:
        return 1
    return 0


def cmd_create(args: argparse.Namespace) -> int:
    name = check_name(args.name)
    try:
        project_path(name)
    except FileNotFoundError:
        pass
    else:
        raise ValueError(f"project already exists: {name}")
    goals = [goal.strip() for goal in args.goals.split(",") if goal.strip()]
    stamp = now()
    project = Project(name, check_text(args.info, "project info"), goals, [], [], stamp, stamp)
    save_project(project)
    print(f"Created project {name} with {len(goals)} goal(s).")
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    for name in all_projects():
        project = load_project(name)
        data = summary(project)
        print(f"{name}\t{data['status']}\t{data['counts']['done']}/{len(project.steps)}\t{len(project.scans)}")
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    data = summary(load_project(args.name))
    print(f"Project: {data['name']}  [{data['status']}]")
    print(f"Info: {data['info'] or '-'}")
    print("Goals:")
    for goal in data["goals"]:
        print(f"  - {goal}")
    print("Plan:")
    for item in data["plan"]:
        print(f"  {item['order']}. {item['id']} [{item['status']}] {item['goal']}")
        if item["note"]:
            print(f"     note: {item['note']}")
    print("Timeline:")
    for item in data["timeline"]:
        print(f"  {item['order']}. {item['started']} {item['profile']} [{item['status']}] {item['targets']}")
    nxt = data["next_action"]
    print(f"Next action: {nxt['step']} - {nxt['goal']}" if nxt else "Next action: none")
    return 0


def cmd_summary(args: argparse.Namespace) -> int:
    print(json.dumps(summary(load_project(args.name)), indent=2, sort_keys=True))
    return 0


def cmd_summaries(args: argparse.Namespace) -> int:
    data = [summary(load_project(name)) for name in all_projects()]
    print(json.dumps(data, indent=2, sort_keys=True))
    return 0


def cmd_add_step(args: argparse.Namespace) -> int:
    project = load_project(args.name)
    step_id = check_step(args.step)
    if any(step.id == step_id for step in project.steps):
        raise ValueError(f"step already exists: {step_id}")
    tokens = shlex.split(args.project_args) if args.project_args else []
    project.steps.append(Step(step_id, check_text(args.goal, "step goal", 500), argv=check_argv(tokens), updated=now()))
    project.updated = now()
    save_project(project)
    print(f"Added step {step_id} to {project.name}.")
    return 0


def cmd_set_step(args: argparse.Namespace) -> int:
    project = load_project(args.name)
    step = find_step(project, check_step(args.step))
    step.status = check_status(args.status)
    step.note = check_text(args.note or "", "step note", 2000)
    step.updated = now()
    project.updated = now()
    save_project(project)
    print(f"Step {step.id}: {step.status}")
    return 0


def cmd_active_step(args: argparse.Namespace) -> int:
    step = active_step(load_project(args.name))
    if step:
        print(step.id)
    return 0


def cmd_record_scan(args: argparse.Namespace) -> int:
    project = load_project(args.name)
    raw_argv = os.environ.get("XAMLTECH_PROJECT_ARGV", "")
    argv = raw_argv.split("\n") if raw_argv else []
    step_id = check_step(args.step) if args.step else ""
    scan = Scan(
        run=check_text(args.run, "run path", 1000),
        profile=check_text(args.profile, "profile", 100),
        targets=check_text(args.targets, "targets", 2000),
        status=check_status(args.status),
        started=now(),
        argv=check_argv(argv),
        step=step_id,
    )
    project.scans.append(scan)
    step = find_step(project, step_id) if step_id else active_step(project)
    if step is not None:
        step.status = scan.status
        step.run = scan.run
        step.updated = scan.started
    project.updated = scan.started
    save_project(project)
    print(f"Recorded {scan.status} scan for {project.name}.")
    return 0


def cmd_resume_args(args: argparse.Namespace) -> int:
    project = load_project(args.name)
    step = active_step(project)
    tokens = list(step.argv) if step and step.argv else (list(project.scans[-1].argv) if project.scans else [])
    tokens = [token for token in tokens if token != "--project-resume"]
    if f"--project" not in tokens:
        tokens.extend(["--project", project.name])
    run = step.run if step and step.run else (project.scans[-1].run if project.scans else "")
    if run and Path(run).is_dir() and "--resume" not in tokens:
        tokens.extend(["--resume", run])
    for token in tokens:
        print(token)
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="projects.py")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("exists")
    p.add_argument("name")
    p.set_defaults(func=cmd_exists)
    p = sub.add_parser("create")
    p.add_argument("name")
    p.add_argument("--info", required=True)
    p.add_argument("--goals", default="")
    p.set_defaults(func=cmd_create)
    p = sub.add_parser("list")
    p.set_defaults(func=cmd_list)
    p = sub.add_parser("show")
    p.add_argument("name")
    p.set_defaults(func=cmd_show)
    p = sub.add_parser("summary")
    p.add_argument("name")
    p.set_defaults(func=cmd_summary)
    p = sub.add_parser("summaries")
    p.set_defaults(func=cmd_summaries)
    p = sub.add_parser("add-step")
    p.add_argument("name")
    p.add_argument("step")
    p.add_argument("--goal", required=True)
    p.add_argument("--project-args", default="")
    p.set_defaults(func=cmd_add_step)
    p = sub.add_parser("set-step")
    p.add_argument("name")
    p.add_argument("step")
    p.add_argument("status")
    p.add_argument("--note", default="")
    p.set_defaults(func=cmd_set_step)
    p = sub.add_parser("active-step")
    p.add_argument("name")
    p.set_defaults(func=cmd_active_step)
    p = sub.add_parser("record-scan")
    p.add_argument("name")
    p.add_argument("--run", required=True)
    p.add_argument("--profile", required=True)
    p.add_argument("--targets", default="")
    p.add_argument("--status", required=True)
    p.add_argument("--step", default="")
    p.set_defaults(func=cmd_record_scan)
    p = sub.add_parser("resume-args")
    p.add_argument("name")
    p.set_defaults(func=cmd_resume_args)
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args) or 0)
    except FileNotFoundError as exc:
        print(f"projects: {exc}", file=sys.stderr)
        return 1
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"projects: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
