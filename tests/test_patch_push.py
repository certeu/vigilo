"""Patch delivery: push fix branches + open MRs, just-in-time token, idempotency, rebuild.

Uses real local git repositories under tmp_path (a bare "origin" the fix branches are
pushed to, reached through an ``insteadOf`` rewrite of the trusted https remote) and a
mocked GitLab HTTP layer + secret redemption. Nothing touches the network.
"""
from __future__ import annotations

import asyncio
import json
import os
import subprocess

import pytest

# Some grey-box test modules replace temporalio / aiofiles in sys.modules at import
# time; reuse the white-box suite's isolation so the activity tests see the real ones.
from tests.test_whitebox_engine import (  # noqa: F401
    ActivityInput,
    ApplicationError,
    _real_temporal_modules,
    acts,
)

from src.services import git_push, gitlab_mr, run_secrets
from src.services.git_push import git_auth_env

TOKEN = "glpat-SUPERSECRET-123"
REMOTE = "https://gitlab.corp.example/team/app.git"
SECRETS = {"ref": "11111111-1111-1111-1111-111111111111", "key": "k" * 32}


def git(cwd, *args):
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
    r = subprocess.run(["git", *args], cwd=cwd, env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


class NS:
    def __init__(self, **kw):
        self.__dict__.update(kw)


@pytest.fixture
def world(tmp_path, monkeypatch):
    """origin.git (bare) + data_dir/repo cloned from it, with fix branches + manifest.
    The trusted remote REMOTE is rewritten to the local bare repo by a global gitconfig."""
    seed = tmp_path / "seed"
    seed.mkdir()
    git(seed, "init", "-b", "main")
    (seed / "app.py").write_text("print('v1')\n")
    git(seed, "add", ".")
    git(seed, "commit", "-m", "init")
    origin = tmp_path / "origin.git"
    git(tmp_path, "clone", "--bare", str(seed), str(origin))
    gcfg = tmp_path / "gitconfig"
    gcfg.write_text(f'[url "file://{origin}"]\n\tinsteadOf = {REMOTE}\n')
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(gcfg))
    # git_push ignores the ambient environment: hand it the trusted config explicitly.
    monkeypatch.setattr(git_push, "_TRUSTED_GIT_CONFIG", str(gcfg))
    monkeypatch.setattr(git_push, "_ALLOW_FILE_PROTOCOL", True)

    data = tmp_path / "data"
    repo = data / "repo"
    git(tmp_path, "clone", str(origin), str(repo))
    scanned = git(repo, "rev-parse", "HEAD")
    git(repo, "checkout", "-b", "fix/VG-001", "main")
    (repo / "app.py").write_text("print('v2 fixed')\n")
    git(repo, "commit", "-am", "fix(VG-001)")
    git(repo, "checkout", "-b", "fix/VG-002", "main")
    git(repo, "checkout", "main")
    deliv = repo / "deliverables"
    deliv.mkdir()
    (deliv / "remediation_manifest.json").write_text(json.dumps({"branches": [
        {"branch": "fix/VG-001", "finding_ids": ["VG-001"], "files_changed": ["app.py"],
         "pushed": True, "diff_nonempty": True, "mr_url": "https://liar/1", "verified": "pass"},
        {"branch": "fix/VG-002", "finding_ids": ["VG-002"], "files_changed": [],
         "pushed": True, "diff_nonempty": False},
    ]}))
    return NS(tmp=tmp_path, data=str(data), repo=str(repo), origin=str(origin), scanned=scanned,
              source={"remote_url": REMOTE, "commit": scanned})


def manifest(world):
    return json.loads(open(os.path.join(world.repo, "deliverables", "remediation_manifest.json")).read())


def entry(world, branch):
    return next(b for b in manifest(world)["branches"] if b["branch"] == branch)


@pytest.fixture
def gitlab(monkeypatch):
    calls = []

    def fake(gitlab_url, token, method, endpoint, data=None):
        calls.append(NS(url=gitlab_url, token=token, method=method, endpoint=endpoint, data=data))
        if method == "GET":
            return {"default_branch": "main"}
        return {"web_url": f"{gitlab_url}/team/app/-/merge_requests/7", "iid": 7}

    monkeypatch.setattr(gitlab_mr, "_gitlab_api_request", fake)
    return calls


@pytest.fixture
def redeemed(monkeypatch):
    """Fake secret redemption; records what was asked for."""
    calls = []

    async def fake(secrets, want, **kw):
        calls.append((secrets, list(want)))
        return {"forge_token": TOKEN}

    monkeypatch.setattr(run_secrets, "redeem", fake)
    return calls


@pytest.fixture
def git_spy(monkeypatch):
    """Record argv + env of every git subprocess."""
    seen = []
    real = asyncio.create_subprocess_exec

    async def spy(*args, **kw):
        seen.append(NS(argv=list(args), env=dict(kw.get("env") or {}), cwd=kw.get("cwd")))
        return await real(*args, **kw)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", spy)
    return seen


def origin_branches(world):
    return git(world.origin, "for-each-ref", "--format=%(refname:short)", "refs/heads/").split()


PUSH = {"enabled": True}


async def deliver(world, push=PUSH, source="default", secrets=SECRETS):
    return await git_push.deliver_patches(
        world.repo, "sess", push,
        source=world.source if source == "default" else source, secrets=secrets)


class TestDeliver:
    async def test_pushes_and_opens_mr_and_records_manifest(self, world, gitlab, redeemed):
        res = await deliver(world)

        assert res["status"] == "delivered"
        assert res["pushed"] == ["fix/VG-001"]
        assert "fix/VG-001" in origin_branches(world)
        assert "fix/VG-002" not in origin_branches(world)  # empty diff is not pushed
        assert redeemed == [(SECRETS, ["forge_token", "cookie_header"])]   # once (cookie only to mask it)

        posts = [c for c in gitlab if c.method == "POST"]
        assert len(posts) == 1
        assert posts[0].url == "https://gitlab.corp.example"  # derived from the trusted remote
        assert posts[0].token == TOKEN
        assert posts[0].endpoint == "/projects/team%2Fapp/merge_requests"
        assert posts[0].data["source_branch"] == "fix/VG-001"
        assert posts[0].data["target_branch"] == "main"

        one, two = entry(world, "fix/VG-001"), entry(world, "fix/VG-002")
        assert one["pushed"] is True and one["mr_url"].endswith("/merge_requests/7")
        assert one["verified"] == "pass"  # existing fields preserved
        assert two["pushed"] is False and "mr_url" not in two
        assert manifest(world)["delivery"]["status"] == "delivered"

    async def test_token_never_in_argv_files_or_process_env(self, world, gitlab, redeemed, git_spy):
        await deliver(world)
        assert TOKEN not in os.environ.values()
        for call in git_spy:
            assert TOKEN not in " ".join(call.argv)
        # the token reaches exactly the authenticated git subprocess, via its env only
        with_token = [c for c in git_spy if TOKEN in c.env.values()]
        assert with_token and all("push" in c.argv[:12] for c in with_token)
        # ... and never from inside the agent-writable checkout
        assert all(c.cwd != world.repo for c in with_token)
        for root, _d, files in os.walk(world.tmp):
            for f in files:
                p = os.path.join(root, f)
                try:
                    assert TOKEN not in open(p, errors="ignore").read(), p
                except OSError:
                    pass
        assert git(world.repo, "remote", "get-url", "origin") == world.origin

    async def test_not_enabled_pushes_nothing_and_clears_agent_claims(self, world, gitlab, redeemed):
        res = await deliver(world, push=None)
        assert res["status"] == "skipped"
        assert origin_branches(world) == ["main"]
        assert gitlab == [] and redeemed == []
        one = entry(world, "fix/VG-001")
        assert one["pushed"] is False and "mr_url" not in one  # agent's claims overwritten
        assert manifest(world)["delivery"]["status"] == "skipped"

    async def test_enabled_without_secret_reference_skips(self, world, gitlab, redeemed):
        res = await deliver(world, secrets=None)
        assert res["status"] == "skipped" and "credential" in res["reason"]
        assert origin_branches(world) == ["main"]
        assert entry(world, "fix/VG-001")["pushed"] is False

    async def test_upload_source_has_no_remote(self, world, gitlab, redeemed):
        res = await deliver(world, source=None)
        assert res["status"] == "skipped" and "upload" in res["reason"]
        assert origin_branches(world) == ["main"] and gitlab == []

    async def test_remote_comes_from_platform_not_from_checkout_files(self, world, gitlab, redeemed):
        """A prompt-injected agent rewrites .vigilo-remote-url and .git/config; the push
        and the MR still go to the repository record's remote."""
        evil = world.tmp / "evil.git"
        git(world.tmp, "init", "--bare", str(evil))
        (world.tmp / "data" / "repo" / ".vigilo-remote-url").write_text("https://evil.example/x/y.git\n")
        git(world.repo, "remote", "set-url", "origin", str(evil))
        res = await deliver(world)
        assert res["status"] == "delivered"
        assert "fix/VG-001" in origin_branches(world)
        assert git(str(evil), "for-each-ref", "refs/heads/") == ""
        posts = [c for c in gitlab if c.method == "POST"]
        assert posts[0].url == "https://gitlab.corp.example"

    async def test_userinfo_in_remote_is_refused(self, world, gitlab, redeemed):
        res = await deliver(world, source={"remote_url": "https://u:p@gitlab.corp.example/team/app.git",
                                           "commit": world.scanned})
        assert res["status"] == "skipped" and "credentials" in res["reason"]
        assert redeemed == []

    async def test_redemption_refused_skips_without_pushing(self, world, gitlab, monkeypatch):
        async def refuse(*a, **k):
            raise run_secrets.RedemptionRefused("HTTP 403")
        monkeypatch.setattr(run_secrets, "redeem", refuse)
        res = await deliver(world)
        assert res["status"] == "skipped" and "no longer available" in res["reason"]
        assert origin_branches(world) == ["main"]

    async def test_push_failure_is_recorded_not_raised(self, world, gitlab, redeemed, monkeypatch, tmp_path):
        gcfg = tmp_path / "gitconfig2"
        gcfg.write_text(f'[url "file://{tmp_path}/missing.git"]\n\tinsteadOf = {REMOTE}\n')
        monkeypatch.setattr(git_push, "_TRUSTED_GIT_CONFIG", str(gcfg))
        res = await deliver(world)
        assert res["status"] == "failed"
        one = entry(world, "fix/VG-001")
        assert one["pushed"] is False and one["push_error"]
        assert gitlab == []  # no MR for an unpushed branch

    async def test_mr_failure_keeps_pushed_true(self, world, redeemed, monkeypatch):
        def boom(*a, **k):
            if a[2] == "GET":
                return {"default_branch": "main"}
            raise RuntimeError(f"GitLab API error 409 using {TOKEN}")

        monkeypatch.setattr(gitlab_mr, "_gitlab_api_request", boom)
        res = await deliver(world)
        assert res["status"] == "delivered"
        one = entry(world, "fix/VG-001")
        assert one["pushed"] is True and "mr_url" not in one
        assert one["mr_error"] and TOKEN not in one["mr_error"]

    async def test_existing_remote_branch_is_not_force_pushed(self, world, gitlab, redeemed):
        other = world.tmp / "other"
        git(world.tmp, "clone", world.origin, str(other))
        git(other, "checkout", "-b", "fix/VG-001")
        (other / "x.txt").write_text("diverged")
        git(other, "add", ".")
        git(other, "commit", "-m", "diverge")
        git(other, "push", "origin", "fix/VG-001")
        res = await deliver(world)
        assert res["failed"] == ["fix/VG-001"]
        assert entry(world, "fix/VG-001")["pushed"] is False

    async def test_checkout_without_upstream_history_is_not_pushed(self, world, gitlab, redeemed):
        res = await deliver(world, source={"remote_url": REMOTE, "commit": "0" * 40})
        assert res["status"] == "skipped" and "history" in res["reason"]
        assert origin_branches(world) == ["main"]


class TestIdempotency:
    async def test_second_run_skips_pushed_branch_and_keeps_result(self, world, gitlab, redeemed, git_spy):
        await deliver(world)
        pushes_before = len([c for c in git_spy if "push" in c.argv[:12]])
        res = await deliver(world)
        assert res["status"] == "delivered" and res["already_delivered"] == ["fix/VG-001"]
        assert len([c for c in git_spy if "push" in c.argv[:12]]) == pushes_before
        assert len([c for c in gitlab if c.method == "POST"]) == 1     # no duplicate MR
        assert len(redeemed) == 1                                       # nothing to redeem the 2nd time
        one = entry(world, "fix/VG-001")
        assert one["pushed"] is True and one["mr_url"].endswith("/merge_requests/7")

    async def test_later_skipped_attempt_never_downgrades_success(self, world, gitlab, redeemed):
        await deliver(world)
        for kw in ({"push": None}, {"secrets": None}, {"source": None}):
            res = await deliver(world, **kw)
            assert res["status"] == "delivered", kw
            one = entry(world, "fix/VG-001")
            assert one["pushed"] is True and one["mr_url"], kw
            assert manifest(world)["delivery"]["status"] == "delivered"

    async def test_refused_redemption_after_success_keeps_success(self, world, gitlab, redeemed, monkeypatch):
        await deliver(world)

        async def refuse(*a, **k):
            raise run_secrets.RedemptionRefused("x")
        monkeypatch.setattr(run_secrets, "redeem", refuse)
        # a moved branch tip needs a new push; redemption is refused, success for the old tip stays recorded
        res = await deliver(world)
        assert res["status"] == "delivered" and entry(world, "fix/VG-001")["pushed"] is True

    async def test_mr_is_retried_when_only_the_mr_failed(self, world, redeemed, monkeypatch):
        calls = {"n": 0}

        def flaky(gitlab_url, token, method, endpoint, data=None):
            if method == "GET":
                return {"default_branch": "main"}
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("502")
            return {"web_url": "https://gitlab.corp.example/team/app/-/merge_requests/9", "iid": 9}

        monkeypatch.setattr(gitlab_mr, "_gitlab_api_request", flaky)
        await deliver(world)
        assert entry(world, "fix/VG-001")["pushed"] is True and "mr_url" not in entry(world, "fix/VG-001")
        res = await deliver(world)
        assert res["already_delivered"] == ["fix/VG-001"]
        assert entry(world, "fix/VG-001")["mr_url"].endswith("/9")

    async def test_overlapping_retry_waits_and_does_not_overwrite(self, world, gitlab, redeemed, monkeypatch):
        """Attempt A is mid-push (Temporal timed it out without heartbeats and started B):
        B waits for A's lock, then sees A's success instead of recording 'skipped'."""
        gate, entered = asyncio.Event(), asyncio.Event()
        real = git_push._run_git

        async def slow(args, cwd, token=None, timeout=300, **kw):
            if args[:2] == ["git", "push"]:
                entered.set()
                await gate.wait()
            return await real(args, cwd, token=token, timeout=timeout, **kw)

        monkeypatch.setattr(git_push, "_run_git", slow)
        a = asyncio.create_task(deliver(world))
        await entered.wait()
        # B would be a no-credential attempt: without the lock it would write 'skipped'.
        b = asyncio.create_task(deliver(world, secrets=None))
        await asyncio.sleep(0.8)
        assert not b.done()                      # B is waiting for A
        gate.set()
        ra, rb = await asyncio.gather(a, b)
        assert ra["status"] == "delivered"
        assert rb["status"] == "delivered"      # preserved, not downgraded
        one = entry(world, "fix/VG-001")
        assert one["pushed"] is True and one["mr_url"]
        assert manifest(world)["delivery"]["status"] == "delivered"
        assert len([c for c in gitlab if c.method == "POST"]) == 1

    async def test_cancelled_attempt_releases_lock_and_records_nothing(self, world, gitlab, redeemed, monkeypatch):
        entered = asyncio.Event()
        real = git_push._run_git

        async def hang(args, cwd, token=None, timeout=300, **kw):
            if args[:2] == ["git", "push"]:
                entered.set()
                await asyncio.sleep(3600)
            return await real(args, cwd, token=token, timeout=timeout, **kw)

        monkeypatch.setattr(git_push, "_run_git", hang)
        t = asyncio.create_task(deliver(world))
        await entered.wait()
        t.cancel()
        with pytest.raises(asyncio.CancelledError):
            await t
        monkeypatch.setattr(git_push, "_run_git", real)
        res = await asyncio.wait_for(deliver(world), 5)   # lock is free again
        assert res["status"] == "delivered" and res["pushed"] == ["fix/VG-001"]

    async def test_run_git_kills_subprocess_on_cancel(self, tmp_path):
        t = asyncio.create_task(git_push._run_git(["sleep", "30"], str(tmp_path)))
        await asyncio.sleep(0.3)
        t.cancel()
        with pytest.raises(asyncio.CancelledError):
            await t


@pytest.fixture
def hb(monkeypatch):
    beats = []
    monkeypatch.setattr(acts.activity, "heartbeat", lambda *a, **k: beats.append(a))
    monkeypatch.setattr(acts, "HEARTBEAT_INTERVAL_S", 0.05)
    return beats


class TestActivity:
    async def test_activity_delivers_with_heartbeats_and_no_secret_on_disk(self, world, gitlab, redeemed, hb):
        ai = ActivityInput(repo_path=world.repo, workflow_id="w", session_id="s", push=PUSH,
                           source=world.source, secrets=SECRETS)
        res = await acts.deliver_patches(ai)
        assert res["status"] == "delivered"
        assert hb  # heartbeats were sent while delivering
        assert not os.path.exists(os.path.join(world.data, ".vigilo-secrets"))

    async def test_activity_never_raises(self, tmp_path, hb):
        ai = ActivityInput(repo_path=str(tmp_path / "nope" / "repo"), workflow_id="w",
                           session_id="s", push=PUSH, source={"remote_url": REMOTE}, secrets=SECRETS)
        res = await acts.deliver_patches(ai)
        assert res["status"] in ("skipped", "failed")

    async def test_platform_outage_is_retryable_and_pushes_nothing(self, world, gitlab, hb, monkeypatch):
        async def down(*a, **k):
            raise run_secrets.RedemptionUnavailable("URLError")
        monkeypatch.setattr(run_secrets, "redeem", down)
        ai = ActivityInput(repo_path=world.repo, workflow_id="w", session_id="s", push=PUSH,
                           source=world.source, secrets=SECRETS)
        with pytest.raises(ApplicationError) as e:
            await acts.deliver_patches(ai)
        assert not e.value.non_retryable
        assert origin_branches(world) == ["main"]

    def test_input_carries_a_reference_never_the_token(self):
        from temporalio.converter import DataConverter

        conv = DataConverter.default
        ai = ActivityInput(repo_path="/r", workflow_id="w", session_id="s", push={"enabled": True},
                           source={"remote_url": REMOTE, "commit": "a" * 40},
                           auth={"cookie": True}, secrets=SECRETS)
        payloads = conv.payload_converter.to_payloads([ai])
        (back,) = conv.payload_converter.from_payloads(payloads, [ActivityInput])
        assert back.push == {"enabled": True} and back.secrets == SECRETS
        assert back.source["remote_url"] == REMOTE and back.auth == {"cookie": True}
        assert TOKEN not in repr(payloads)

    def test_timeouts_heartbeat(self):
        import importlib
        ec = importlib.import_module("src.temporal.engine_common")
        assert ec.REBUILD_GIT_HEARTBEAT and ec.DELIVER_HEARTBEAT

    def test_activity_input_built_from_workflow_input(self):
        import importlib
        ec = importlib.import_module("src.temporal.engine_common")
        ai = ec.build_activity_input({
            "repo_path": "/r", "workflow_id": "w", "session_id": "s", "push": {"enabled": True},
            "source": {"remote_url": REMOTE}, "auth": {"cookie": True}, "secrets": SECRETS})
        assert (ai.source, ai.auth, ai.secrets) == ({"remote_url": REMOTE}, {"cookie": True}, SECRETS)


def _upstream_commit(world, name="later.txt"):
    """Add a commit to origin/main after the scan."""
    clone = world.tmp / "pusher"
    git(world.tmp, "clone", world.origin, str(clone))
    (clone / name).write_text("new upstream work\n")
    git(clone, "add", ".")
    git(clone, "commit", "-m", "upstream moved on")
    git(clone, "push", "origin", "main")
    return git(clone, "rev-parse", "HEAD")


class TestRebuild:
    async def test_based_on_scanned_commit_and_origin_stays_clean(self, world):
        head = _upstream_commit(world)
        assert head != world.scanned
        res = await git_push.rebuild_git_from_remote(
            world.repo, remote_url=REMOTE, commit=world.scanned, token=TOKEN)
        assert res["ok"] and res["base"] == "scanned_commit" and res["commit"] == world.scanned
        assert git(world.repo, "rev-parse", "HEAD") == world.scanned
        assert git(world.repo, "branch", "--show-current") == "main"
        assert git(world.repo, "config", "--local", "remote.origin.url") == REMOTE
        assert TOKEN not in open(os.path.join(world.repo, ".git", "config")).read()
        assert not os.path.exists(os.path.join(world.repo, ".git.vigilo-old"))
        assert not os.path.exists(os.path.join(world.repo, ".git.vigilo-new"))
        state = json.load(open(os.path.join(world.repo, ".git", "vigilo-rebuild.json")))
        assert state["base"] == "scanned_commit"

    async def test_falls_back_to_upstream_head_and_says_so(self, world):
        head = _upstream_commit(world)
        res = await git_push.rebuild_git_from_remote(
            world.repo, remote_url=REMOTE, commit="deadbeef" * 5)
        assert res["ok"] and res["base"] == "upstream_head" and res["commit"] == head
        assert "not available upstream" in res["reason"]
        # ... and the manifest records it once delivery renders it
        await git_push.deliver_patches(world.repo, "s", None, source=world.source, secrets=None)
        gb = manifest(world)["git_base"]
        assert gb["base"] == "upstream_head" and gb["requested_commit"] == "deadbeef" * 5

    async def test_no_commit_uses_head(self, world):
        head = _upstream_commit(world)
        res = await git_push.rebuild_git_from_remote(world.repo, remote_url=REMOTE, commit=None)
        assert res["ok"] and res["base"] == "upstream_head" and res["commit"] == head

    async def test_clone_failure_leaves_git_untouched(self, world, monkeypatch, tmp_path):
        before = git(world.repo, "rev-parse", "HEAD")
        gcfg = tmp_path / "gc3"
        gcfg.write_text(f'[url "file://{tmp_path}/missing.git"]\n\tinsteadOf = {REMOTE}\n')
        monkeypatch.setattr(git_push, "_TRUSTED_GIT_CONFIG", str(gcfg))
        res = await git_push.rebuild_git_from_remote(world.repo, remote_url=REMOTE, commit=world.scanned)
        assert not res["ok"] and "clone failed" in res["reason"]
        assert git(world.repo, "rev-parse", "HEAD") == before
        assert git(world.repo, "branch", "--list", "fix/*")

    async def test_no_remote_and_credentials_in_url(self, world):
        assert not (await git_push.rebuild_git_from_remote(world.repo, remote_url=None))["ok"]
        res = await git_push.rebuild_git_from_remote(world.repo, remote_url="https://u:p@h/x.git")
        assert not res["ok"] and "credentials" in res["reason"]

    def test_swap_is_atomic_when_the_move_in_fails(self, world, monkeypatch):
        new = world.tmp / "newgit"
        git(world.tmp, "init", str(world.tmp / "n"))
        os.rename(world.tmp / "n" / ".git", new)
        real = os.rename

        def flaky(src, dst, *a, **k):
            if str(dst).endswith("/.git") and str(src).endswith(git_push.GIT_NEW):
                raise OSError("disk full")
            return real(src, dst, *a, **k)

        monkeypatch.setattr(os, "rename", flaky)
        with pytest.raises(OSError):
            git_push.swap_git_dir(world.repo, str(new))
        monkeypatch.undo()
        assert git(world.repo, "rev-parse", "HEAD")      # the old .git is back and intact
        assert git(world.repo, "branch", "--list", "fix/VG-001")

    def test_crash_between_the_two_renames_is_recovered(self, world):
        repo = world.repo
        os.rename(os.path.join(repo, ".git"), os.path.join(repo, git_push.GIT_OLD))
        os.makedirs(os.path.join(repo, git_push.GIT_NEW))     # half-staged new dir
        assert git_push.recover_git_dir(repo) is True
        assert git(repo, "rev-parse", "HEAD") == world.scanned
        assert not os.path.exists(os.path.join(repo, git_push.GIT_NEW))

    async def test_vigilo_files_can_never_be_committed(self, world):
        await git_push.rebuild_git_from_remote(world.repo, remote_url=REMOTE, commit=world.scanned)
        (world.tmp / "data" / "repo" / ".vigilo-remote-url").write_text("https://x/y.git\n")
        os.makedirs(os.path.join(world.repo, ".vigilo", "s"), exist_ok=True)
        open(os.path.join(world.repo, ".vigilo", "s", "a"), "w").write("x")
        (world.tmp / "data" / "repo" / "real.py").write_text("print(1)\n")
        git(world.repo, "add", "-A")
        staged = git(world.repo, "diff", "--cached", "--name-only").split()
        assert staged == ["real.py"]

    def test_exclude_helper_is_idempotent(self, world):
        from src.services.git_manager import VIGILO_EXCLUDES, ensure_vigilo_excludes
        assert ensure_vigilo_excludes(world.repo) and ensure_vigilo_excludes(world.repo)
        lines = open(os.path.join(world.repo, ".git", "info", "exclude")).read().splitlines()
        for pat in VIGILO_EXCLUDES:
            assert lines.count(pat) == 1

    async def test_activity_returns_result_dict_and_heartbeats(self, world, redeemed, hb):
        ai = ActivityInput(repo_path=world.repo, workflow_id="w", session_id="s", push=PUSH,
                           source=world.source, secrets=SECRETS)
        res = await acts.rebuild_git(ai)
        assert res["ok"] and res["base"] == "scanned_commit"
        assert redeemed == [(SECRETS, ["forge_token"])]     # private repos need it to clone
        # no push -> no token requested
        redeemed.clear()
        res = await acts.rebuild_git(ActivityInput(repo_path=world.repo, workflow_id="w", session_id="s",
                                              source=world.source, secrets=SECRETS))
        assert res["ok"] and redeemed == []


class TestAskpass:
    def test_askpass_serves_user_and_token_from_subprocess_env_only(self):
        with git_auth_env(TOKEN) as env:
            full = {**os.environ, **env}
            user = subprocess.run([env["GIT_ASKPASS"], "Username for 'https://h':"],
                                  env=full, capture_output=True, text=True).stdout.strip()
            pw = subprocess.run([env["GIT_ASKPASS"], "Password for 'https://oauth2@h':"],
                                env=full, capture_output=True, text=True).stdout.strip()
            assert (user, pw) == ("oauth2", TOKEN)
            assert TOKEN not in open(env["GIT_ASKPASS"]).read()   # the script itself holds no secret
            script = env["GIT_ASKPASS"]
        assert not os.path.exists(script)
        assert TOKEN not in os.environ.values()


class TestResolveTarget:
    def test_derived_from_remote(self, monkeypatch):
        monkeypatch.delenv("GITLAB_URL", raising=False)
        assert gitlab_mr.resolve_gitlab_target("https://gl.example/a/b/c.git") == (
            "https://gl.example", "a/b/c")

    def test_ssh_remote_and_port(self, monkeypatch):
        monkeypatch.delenv("GITLAB_URL", raising=False)
        assert gitlab_mr.resolve_gitlab_target("git@gl.example:a/b.git") == ("https://gl.example", "a/b")
        assert gitlab_mr.resolve_gitlab_target("https://u:p@gl.example:8443/a/b") == (
            "https://gl.example:8443", "a/b")

    def test_env_hint_only_for_subpath_installs(self, monkeypatch):
        monkeypatch.setenv("GITLAB_URL", "https://gl.example/gitlab")
        assert gitlab_mr.resolve_gitlab_target("https://gl.example/gitlab/a/b.git") == (
            "https://gl.example/gitlab", "a/b")
        # an unrelated GITLAB_URL does not override the repository's own host
        assert gitlab_mr.resolve_gitlab_target("https://other.example/a/b.git") == (
            "https://other.example", "a/b")
