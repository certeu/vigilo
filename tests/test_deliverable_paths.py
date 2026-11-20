"""Path rules of ``save-deliverable`` and ``vigilo-record --file/--evidence-file``.

Agents write named deliverables under ``deliverables/`` (often a symlink to the
run's output directory, outside the checkout) and scratch files under ``/tmp``.
Both must be accepted; everything else must be rejected, and a stray ``cd`` into
a sub-directory must still hit the repository's ``deliverables/``.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SAVE = ROOT / "scripts" / "save_deliverable.py"
RECORD = ROOT / "scripts" / "vigilo_record.py"


def _run(script: Path, cwd: Path, *args: str, stdin: str | None = None):
    env = {k: v for k, v in os.environ.items() if k != "VIGILO_REPO_PATH"}
    proc = subprocess.run([sys.executable, str(script), *args], cwd=cwd, input=stdin,
                          capture_output=True, text=True, env=env)
    return proc.returncode, json.loads(proc.stdout)


@pytest.fixture
def base(tmp_path: Path):
    """Working dir for a test, guaranteed to be outside /tmp.

    The scripts accept anything under /tmp as agent scratch space, so files
    meant to be "outside" must not live there. pytest's tmp_path is under /tmp
    on Linux (CI) but not on macOS; fall back to a dir under $HOME there.
    """
    tmp_root = os.path.realpath("/tmp") + os.sep
    if not os.path.realpath(tmp_path).startswith(tmp_root):
        yield tmp_path
        return
    with tempfile.TemporaryDirectory(prefix=".vigilo-test-", dir=Path.home()) as d:
        yield Path(d)


@pytest.fixture
def repo(base: Path) -> Path:
    """A checkout whose ``deliverables`` is a symlink to a directory outside it."""
    repo = base / "repo"
    (repo / ".git").mkdir(parents=True)
    out = base / "out" / "deliverables"
    out.mkdir(parents=True)
    (repo / "deliverables").symlink_to(out)
    return repo


@pytest.fixture
def scratch():
    with tempfile.TemporaryDirectory(dir="/tmp") as d:
        yield Path(d)


def test_save_from_deliverables_symlink_outside_checkout(repo):
    (repo / "deliverables" / "code_analysis_deliverable.md").write_text("# Survey\n")
    code, out = _run(SAVE, repo, "--type", "CODE_ANALYSIS",
                     "--file-path", "deliverables/code_analysis_deliverable.md")
    assert code == 0 and out["status"] == "success"
    assert (repo / "deliverables" / "code_analysis_deliverable.md").read_text() == "# Survey\n"


def test_save_from_tmp(repo, scratch):
    src = scratch / "report.md"
    src.write_text("# Report\n")
    code, out = _run(SAVE, repo, "--type", "REPORT", "--file-path", str(src))
    assert code == 0 and out["status"] == "success"
    assert (repo / "deliverables" / "comprehensive_security_assessment_report.md").read_text() == "# Report\n"


def test_save_from_repository_file(repo):
    (repo / "notes.md").write_text("n")
    code, _ = _run(SAVE, repo, "--type", "REPORT", "--file-path", "notes.md")
    assert code == 0


def test_save_rejects_other_locations(repo, base):
    outside = base / "secret.txt"
    outside.write_text("secret")
    (repo / "escape").symlink_to(outside)
    for path in (str(outside), "../secret.txt", "escape", "/etc/hosts",
                 "deliverables/../../secret.txt"):
        code, out = _run(SAVE, repo, "--type", "REPORT", "--file-path", path)
        assert code == 1 and "traversal" in out["message"], path
    assert not (repo / "deliverables" / "comprehensive_security_assessment_report.md").exists()


def test_save_from_subdirectory_writes_to_repo_deliverables(repo):
    sub = repo / "src" / "app"
    sub.mkdir(parents=True)
    (repo / "deliverables" / "draft.md").write_text("# D\n")
    code, out = _run(SAVE, sub, "--type", "REPORT", "--file-path", "deliverables/draft.md")
    assert code == 0, out
    assert (repo / "deliverables" / "comprehensive_security_assessment_report.md").is_file()
    assert not (sub / "deliverables").exists()


def test_record_file_from_deliverables_tmp_and_repo(repo, scratch):
    lead = json.dumps({"title": "a", "hypothesis": "h"})
    (repo / "deliverables" / "lead.json").write_text(lead)
    (scratch / "lead2.json").write_text(json.dumps({"title": "b", "hypothesis": "h"}))
    (repo / "lead3.json").write_text(json.dumps({"title": "c", "hypothesis": "h"}))
    for rel in ("deliverables/lead.json", str(scratch / "lead2.json"), "lead3.json"):
        code, out = _run(RECORD, repo, "lead", "--file", rel)
        assert code == 0 and out["status"] == "ok", (rel, out)


def test_record_file_rejects_other_locations(repo, base):
    outside = base / "lead.json"
    outside.write_text(json.dumps({"title": "a", "hypothesis": "h"}))
    for path in (str(outside), "/etc/hosts"):
        code, out = _run(RECORD, repo, "lead", "--file", path)
        assert code == 1 and "must be inside" in out["problems"][0], path


def test_record_evidence_file_from_deliverables(repo):
    _run(RECORD, repo, "finding", "--json", json.dumps({
        "title": "t", "description": "d", "severity": "low", "location": "a.py:1"}))
    (repo / "deliverables" / "w.md").write_text("walkthrough")
    code, out = _run(RECORD, repo, "verdict", "--evidence-file", "deliverables/w.md", "--json",
                     json.dumps({"finding_id": "VG-001", "verdict": "exploited", "summary": "s"}))
    assert code == 0, out
    assert (repo / "deliverables" / "evidence" / "VG-001.md").read_text() == "walkthrough"
