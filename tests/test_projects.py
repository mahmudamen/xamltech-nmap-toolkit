import contextlib
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("projects", ROOT / "lib" / "projects.py")
projects = importlib.util.module_from_spec(SPEC)
sys.modules["projects"] = projects
SPEC.loader.exec_module(projects)


class ProjectTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.previous = os.environ.get("XAMLTECH_NMAP_PROJECTS_DIR")
        os.environ["XAMLTECH_NMAP_PROJECTS_DIR"] = str(self.dir)

    def tearDown(self):
        self.tmp.cleanup()
        if self.previous is None:
            os.environ.pop("XAMLTECH_NMAP_PROJECTS_DIR", None)
        else:
            os.environ["XAMLTECH_NMAP_PROJECTS_DIR"] = self.previous

    def run_cli(self, *argv, scan_argv=None):
        out, err = io.StringIO(), io.StringIO()
        previous = os.environ.pop("XAMLTECH_PROJECT_ARGV", None)
        if scan_argv is not None:
            os.environ["XAMLTECH_PROJECT_ARGV"] = "\n".join(scan_argv)
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = projects.main(list(argv))
        finally:
            os.environ.pop("XAMLTECH_PROJECT_ARGV", None)
            if previous is not None:
                os.environ["XAMLTECH_PROJECT_ARGV"] = previous
        return code, out.getvalue(), err.getvalue()

    def make_project(self):
        self.assertEqual(self.run_cli("create", "lab", "--info", "Authorized lab", "--goals", "Inventory,Harden")[0], 0)

    def test_create_and_summary(self):
        self.make_project()
        code, out, _ = self.run_cli("summary", "lab")
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(data["name"], "lab")
        self.assertEqual(data["goals"], ["Inventory", "Harden"])
        self.assertEqual(data["status"], "in-progress")
        self.assertIsNone(data["next_action"])

    def test_plan_order_and_next_action(self):
        self.make_project()
        self.run_cli("add-step", "lab", "discover", "--goal", "Find hosts", "--project-args", "-t 127.0.0.1 -p discovery")
        self.run_cli("add-step", "lab", "ports", "--goal", "Find ports", "--project-args", "-t 127.0.0.1 -p quick")
        code, out, _ = self.run_cli("summary", "lab")
        data = json.loads(out)
        self.assertEqual([item["id"] for item in data["plan"]], ["discover", "ports"])
        self.assertEqual(data["next_action"]["step"], "discover")
        self.assertEqual(data["counts"]["todo"], 2)

    def test_record_scan_completes_active_step_and_orders_timeline(self):
        self.make_project()
        self.run_cli("add-step", "lab", "discover", "--goal", "Find hosts", "--project-args", "-t 127.0.0.1 -p discovery")
        self.run_cli("record-scan", "lab", "--run", str(self.dir / "run1"), "--profile", "discovery",
                     "--targets", "127.0.0.1", "--status", "done",
                     scan_argv=["-t", "127.0.0.1", "-p", "discovery"])
        self.run_cli("add-step", "lab", "ports", "--goal", "Find ports", "--project-args", "-t 127.0.0.1 -p quick")
        self.run_cli("record-scan", "lab", "--run", str(self.dir / "run2"), "--profile", "quick",
                     "--targets", "127.0.0.1", "--status", "failed",
                     scan_argv=["-t", "127.0.0.1", "-p", "quick"])
        code, out, _ = self.run_cli("summary", "lab")
        data = json.loads(out)
        self.assertEqual([item["order"] for item in data["timeline"]], [1, 2])
        self.assertEqual(data["plan"][0]["status"], "done")
        self.assertEqual(data["plan"][1]["status"], "failed")
        self.assertEqual(data["next_action"]["step"], "ports")
        self.assertEqual(data["status"], "failed")

    def test_resume_uses_next_step_and_keeps_project(self):
        self.make_project()
        self.run_cli("add-step", "lab", "discover", "--goal", "Find hosts", "--project-args", "-t 127.0.0.1 -p discovery")
        code, out, _ = self.run_cli("resume-args", "lab")
        tokens = out.splitlines()
        self.assertEqual(code, 0)
        self.assertEqual(tokens, ["-t", "127.0.0.1", "-p", "discovery", "--project", "lab"])

    def test_resume_adds_workflow_resume_when_run_exists(self):
        self.make_project()
        run = self.dir / "run1"
        run.mkdir()
        self.run_cli("record-scan", "lab", "--run", str(run), "--profile", "recon", "--status", "failed",
                     scan_argv=["-t", "127.0.0.1", "-p", "recon"])
        code, out, _ = self.run_cli("resume-args", "lab")
        tokens = out.splitlines()
        self.assertEqual(code, 0)
        self.assertIn("--resume", tokens)
        self.assertEqual(tokens[tokens.index("--resume") + 1], str(run))

    def test_needs_action_is_reported(self):
        self.make_project()
        self.run_cli("add-step", "lab", "review", "--goal", "Review findings")
        self.run_cli("set-step", "lab", "review", "needs-action", "--note", "Waiting for operator")
        code, out, _ = self.run_cli("show", "lab")
        self.assertEqual(code, 0)
        self.assertIn("Next action: review", out)
        self.assertIn("Waiting for operator", out)

    def test_hostile_names_and_files_are_rejected(self):
        for name in ("../escape", "a/b", "", "x" * 65):
            code, _, _ = self.run_cli("create", name, "--info", "x")
            self.assertNotEqual(code, 0)
        path = self.dir / "bad.json"
        path.write_text('{"schema_version": 1, "name": "bad", "goals": "not a list"}', encoding="utf-8")
        code, _, err = self.run_cli("show", "bad")
        self.assertEqual(code, 2)
        self.assertIn("goal", err)

    def test_bundled_sample_project(self):
        code, out, _ = self.run_cli("summary", "sample-assessment")
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(data["name"], "sample-assessment")
        self.assertTrue(data["goals"])
        self.assertTrue(data["plan"])


if __name__ == "__main__":
    unittest.main()
