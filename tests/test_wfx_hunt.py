"""Offline tests for wfx_hunt.py. Run: python3 -m unittest discover -s tests -v"""
from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import wfx_hunt as wh  # noqa: E402

PAYLOAD_SHA = "a" * 40
CLEAN_SHA = "b" * 40
RESTORE_SHA = "c" * 40
HIDDEN_SHA = "d" * 40


def commit(sha, msg, when, login="mallory"):
    return {"sha": sha, "html_url": f"https://github.com/x/y/commit/{sha}", "author": {"login": login},
            "commit": {"message": msg, "author": {"name": login}, "committer": {"date": when}}}


def run(num, title, when, status="completed", wf=1):
    return {"workflow_id": wf, "run_number": num, "display_title": title, "created_at": when, "name": "ci",
            "status": status, "conclusion": "success", "head_sha": PAYLOAD_SHA, "actor": {"login": "mallory"},
            "html_url": f"https://github.com/x/y/actions/runs/{num}"}


class FakeGitHub(wh.GitHub):
    """Serves canned API responses keyed by path."""

    def __init__(self, routes, raw=None, token="t"):
        super().__init__(token)
        self.routes, self.raw_files, self.requested = routes, raw or {}, []

    def get(self, path, params=None):
        self.calls += 1
        self.requested.append((path, params))
        for key, value in self.routes.items():
            if path == key or (key.endswith("*") and path.startswith(key[:-1])):
                data = value(params) if callable(value) else value
                return data, ""
        return None, ""

    def paged(self, path, params=None, key=None, cap=1000):
        data, _ = self.get(path, params)
        if data is None:
            return []
        return (data.get(key, []) if key else data)[:cap]

    def raw(self, full, ref, path):
        return self.raw_files.get(path, "")


def affected_routes(private=False):
    r = "/repos/victim/app"
    return {
        r: {"full_name": "victim/app", "default_branch": "main", "private": private},
        f"{r}/branches": [{"name": "main"}, {"name": "wfx-docs"}, {"name": "ci-77-build-4242"}],
        f"{r}/pulls": [{"number": 27, "title": "docs: dependency audit notes", "head": {"ref": "wfx-docs"},
                        "user": {"login": "mallory"}, "state": "open", "merged_at": None,
                        "created_at": "2026-11-11T09:00:00Z", "html_url": "https://github.com/victim/app/pull/27"}],
        f"{r}/commits": [commit(RESTORE_SHA, "ci: restore", "2026-11-11T09:17:35Z"),
                         commit(PAYLOAD_SHA, "ci: refresh build cache\n\nbody", "2026-11-11T09:17:23Z")],
        f"{r}/commits/{PAYLOAD_SHA}/statuses": [{"context": "build", "state": "success", "description": "wfx"}],
        f"{r}/activity": [{"activity_type": "force_push", "ref": "refs/heads/main", "after": HIDDEN_SHA,
                           "before": PAYLOAD_SHA, "timestamp": "2026-11-11T09:18:00Z", "actor": {"login": "drubot"}}],
        f"{r}/commits/{HIDDEN_SHA}": {"commit": {"message": "chore: add ci helper"}},
        f"{r}/actions/runs": {"workflow_runs": [run(1963, "build", "2026-11-11T08:00:00Z"),
                                                run(1965, "ci: restore", "2026-11-11T09:18:00Z")]},
        f"{r}/git/trees/main": {"tree": [{"type": "blob", "path": ".ci-ab12cd.sh"},
                                         {"type": "blob", "path": ".github/workflows/build-audit-x9y8z7.yml"},
                                         {"type": "blob", "path": "package.json"}]},
        f"{r}/contents/*": {"content": "V0ZfQ1RPS0VOOiB4"},
    }


AFFECTED_RAW = {".github/workflows/build-audit-x9y8z7.yml": "env:\n  WF_CTOKEN: abc\n",
                "package.json": '{"scripts": {"postinstall": "bash .ci-ab12cd.sh"}}'}


def clean_routes():
    r = "/repos/good/lib"
    return {
        r: {"full_name": "good/lib", "default_branch": "main", "private": False},
        f"{r}/branches": [{"name": "main"}, {"name": "dependabot/npm/x"}],
        f"{r}/pulls": [{"number": 3, "title": "fix typo", "head": {"ref": "fix"}, "user": {"login": "a"},
                        "state": "closed", "created_at": "2026-11-11T00:00:00Z", "html_url": ""}],
        f"{r}/commits": [commit(CLEAN_SHA, "fix: typo", "2026-11-11T00:00:00Z", "alice")],
        f"{r}/activity": [],
        f"{r}/actions/runs": {"workflow_runs": [run(10, "fix: typo", "2026-11-11T00:00:00Z"),
                                                run(11, "fix: more", "2026-11-11T01:00:00Z")]},
        f"{r}/git/trees/main": {"tree": [{"type": "blob", "path": "README.md"}]},
    }


def titles(h, level=None):
    return [f.title for f in h.findings if level is None or f.level == level]


class ParseTargetTests(unittest.TestCase):
    def test_forms(self):
        self.assertEqual(wh.parse_target("owner/repo"), ("owner", "repo"))
        self.assertEqual(wh.parse_target("https://github.com/Owner/Repo.git"), ("Owner", "Repo"))
        self.assertEqual(wh.parse_target("https://github.com/o/r/pull/27?x=1"), ("o", "r"))
        self.assertEqual(wh.parse_target("@my-org"), ("my-org", None))
        self.assertIsNone(wh.parse_target("-bad"))
        self.assertIsNone(wh.parse_target("o/r e p o"))
        self.assertIsNone(wh.parse_target(""))


class RepoScanTests(unittest.TestCase):
    def test_affected_repo_finds_every_indicator(self):
        gh = FakeGitHub(affected_routes(), AFFECTED_RAW)
        h = wh.Hunter(gh)
        h.scan_repo("victim/app")
        got = titles(h)
        self.assertEqual(h.verdict(), "affected")
        for expected in [
            "Probe branch wfx-docs is still there",
            "Encrypted loot fallback branch",
            "Probe pull request #27 by mallory",
            'Payload commit "ci: refresh build cache"',
            'Forged commit status "build"',
            'Activity log shows payload commit "chore: add ci helper"',
            'Deleted run #1964 in "ci"',
            "Hidden payload script is still on main",
            "Injected Dependency Audit workflow is still on main",
            "Live wfx payload markers in .github/workflows/build-audit-x9y8z7.yml",
            "An npm script runs a hidden .ci-*.sh",
            "Force push to the default branch",
            'Cleanup-style commit "ci: restore"',
        ]:
            self.assertIn(expected, got)
        gap = next(f for f in h.findings if f.title.startswith("Deleted run"))
        self.assertEqual(gap.level, "affected")
        self.assertIn("cover-up", gap.detail)

    def test_private_repo_reads_files_through_the_api(self):
        gh = FakeGitHub(affected_routes(private=True))
        h = wh.Hunter(gh)
        h.scan_repo("victim/app")
        self.assertTrue(any(p.startswith("/repos/victim/app/contents/") for p, _ in gh.requested))
        self.assertIn("Live wfx payload markers in package.json", titles(h))

    def test_clean_repo(self):
        h = wh.Hunter(FakeGitHub(clean_routes()))
        h.scan_repo("good/lib")
        self.assertEqual(h.verdict(), "info")
        self.assertEqual(titles(h), ["No wfx indicators found"])

    def test_gap_without_suspicious_commit_is_review(self):
        routes = clean_routes()
        routes["/repos/good/lib/actions/runs"] = {"workflow_runs": [run(10, "a", "2026-11-11T00:00:00Z"),
                                                                    run(13, "b", "2026-11-11T05:00:00Z")]}
        h = wh.Hunter(FakeGitHub(routes))
        h.scan_repo("good/lib")
        self.assertEqual(h.verdict(), "review")
        self.assertIn('Deleted runs #11, #12 in "ci"', titles(h, "review"))

    def test_held_payload_run_is_probed_not_affected(self):
        routes = clean_routes()
        routes["/repos/good/lib/actions/runs"] = {"workflow_runs": [
            run(10, "chore: add dependency audit workflow", "2026-11-11T00:00:00Z", status="action_required")]}
        h = wh.Hunter(FakeGitHub(routes))
        h.scan_repo("good/lib")
        self.assertEqual(h.verdict(), "probed")
        self.assertIn("Payload run is waiting for approval", titles(h))

    def test_old_probe_before_window_is_ignored(self):
        routes = clean_routes()
        routes["/repos/good/lib/pulls"] = [{"number": 1, "title": "docs: dependency audit notes", "head": {"ref": "x"},
                                            "user": {"login": "a"}, "state": "closed",
                                            "created_at": "2026-10-01T00:00:00Z", "html_url": ""}]
        h = wh.Hunter(FakeGitHub(routes))
        h.scan_repo("good/lib")
        self.assertEqual(h.verdict(), "info")

    def test_invisible_repo(self):
        h = wh.Hunter(FakeGitHub({}, token=""))
        h.scan_repo("ghost/repo")
        self.assertEqual(titles(h), ["Repository not visible"])
        self.assertIn("GITHUB_TOKEN", h.findings[0].detail)


class OwnerScanTests(unittest.TestCase):
    def routes(self):
        routes = affected_routes()
        routes.update(clean_routes())
        routes.update({
            "/users/victim": {"login": "victim", "type": "Organization"},
            "/search/issues": lambda p: {"items": [{"number": 27, "repository_url": "https://api.github.com/repos/victim/app",
                                                    "user": {"login": "mallory"}, "state": "open",
                                                    "created_at": "2026-11-11T09:00:00Z", "html_url": "u"}]}
            if "wfx-docs" in p["q"] else {"items": []},
            "/search/commits": lambda p: {"items": [{"sha": PAYLOAD_SHA, "repository": {"full_name": "victim/app"},
                                                     "author": {"login": "mallory"}, "html_url": "c",
                                                     "commit": {"message": "ci: refresh build cache",
                                                                "author": {"name": "m"},
                                                                "committer": {"date": "2026-11-11T09:17:23Z"}}}]}
            if "refresh build cache" in p["q"] else {"items": []},
            "/orgs/victim/repos": [
                {"full_name": "victim/app", "pushed_at": "2026-11-11T09:18:00Z"},
                {"full_name": "good/lib", "pushed_at": "2026-11-11T01:00:00Z"},
                {"full_name": "victim/old", "pushed_at": "2025-01-01T00:00:00Z"},
                {"full_name": "victim/archived", "pushed_at": "2026-11-11T00:00:00Z", "archived": True},
            ],
        })
        return routes

    def test_org_scan_searches_then_deep_checks(self):
        gh = FakeGitHub(self.routes(), AFFECTED_RAW)
        h = wh.Hunter(gh)
        h.scan_owner("victim", "org", workers=1)
        self.assertEqual(sorted(h.scanned), ["good/lib", "victim/app"])
        self.assertEqual(h.verdict(), "affected")
        queries = [p["q"] for path, p in gh.requested if path.startswith("/search/")]
        self.assertIn("org:victim is:pr head:wfx-docs", queries)
        self.assertEqual(len(queries), 5)

    def test_cap_moves_rest_to_skipped(self):
        h = wh.Hunter(FakeGitHub(self.routes(), AFFECTED_RAW))
        h.scan_owner("victim", "org", max_repos=1, workers=1)
        self.assertEqual(h.scanned, ["victim/app"])
        self.assertEqual(h.skipped, ["good/lib"])

    def test_all_repos_includes_old_but_not_archived(self):
        gh = FakeGitHub(self.routes(), AFFECTED_RAW)
        h = wh.Hunter(gh)
        h.scan_owner("victim", "org", all_repos=True, workers=1)
        asked = {path for path, _ in gh.requested}
        self.assertIn("/repos/victim/old", asked)
        self.assertNotIn("/repos/victim/archived", asked)
        self.assertNotIn("victim/archived", h.skipped)

    def test_cap_keeps_strongest_evidence_then_newest_push(self):
        routes = self.routes()
        routes["/search/issues"] = lambda p: {"items": [
            {"number": n, "repository_url": f"https://api.github.com/repos/{repo}", "user": {"login": "bot"},
             "state": "open", "created_at": "2026-11-11T09:00:00Z", "html_url": "u"}
            for n, repo in ((1, "victim/stale"), (2, "victim/fresh"))] if "wfx-docs" in p["q"] else []}
        routes["/orgs/victim/repos"] = routes["/orgs/victim/repos"] + [
            {"full_name": "victim/stale", "pushed_at": "2026-11-10T01:00:00Z"},
            {"full_name": "victim/fresh", "pushed_at": "2026-11-12T07:39:00Z"},
        ]
        gh = FakeGitHub(routes, AFFECTED_RAW)
        h = wh.Hunter(gh)
        h.scan_owner("victim", "org", max_repos=2, workers=1)
        asked = [path for path, _ in gh.requested if path.count("/") == 3 and path.startswith("/repos/")]
        self.assertEqual(asked, ["/repos/victim/app", "/repos/victim/fresh"])
        self.assertEqual(h.skipped, ["good/lib", "victim/stale"])

    def test_recent_unflagged_push_beats_older_probe(self):
        routes = self.routes()
        routes["/search/issues"] = lambda p: {"items": [
            {"number": 1, "repository_url": "https://api.github.com/repos/victim/stale", "user": {"login": "bot"},
             "state": "closed", "created_at": "2026-11-10T09:00:00Z", "html_url": "u"}] if "wfx-docs" in p["q"] else []}
        routes["/search/commits"] = lambda p: {"items": []}
        routes["/orgs/victim/repos"] = routes["/orgs/victim/repos"] + [
            {"full_name": "victim/stale", "pushed_at": "2026-11-10T01:00:00Z"}]
        h = wh.Hunter(FakeGitHub(routes, AFFECTED_RAW))
        h.scan_owner("victim", "org", max_repos=1, workers=1)
        self.assertEqual(h.scanned, ["victim/app"])
        self.assertIn("victim/stale", h.skipped)
        self.assertTrue(any(f.repo == "victim/stale" and f.level == "probed" for f in h.findings))

    def test_unknown_owner(self):
        with self.assertRaises(ValueError):
            wh.Hunter(FakeGitHub({})).scan_owner("nobody")


class CliTests(unittest.TestCase):
    def cli(self, argv, routes, raw=None):
        fake = FakeGitHub(routes, raw)
        out = io.StringIO()
        with mock.patch.object(wh, "GitHub", lambda token: fake), redirect_stdout(out):
            code = wh.main(argv + ["--no-color", "-q"])
        return code, out.getvalue()

    def test_exit_codes_and_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            js, md = os.path.join(tmp, "r.json"), os.path.join(tmp, "r.md")
            code, text = self.cli(["victim/app", "--json", js, "--markdown", md], affected_routes(), AFFECTED_RAW)
            self.assertEqual(code, 3)
            self.assertIn("VERDICT: AFFECTED", text)
            report = json.loads(Path(js).read_text())
            self.assertEqual(report["verdict"], "affected")
            self.assertEqual(report["repos_scanned"], ["victim/app"])
            self.assertIn("**Verdict:** AFFECTED", Path(md).read_text())
        code, text = self.cli(["good/lib"], clean_routes())
        self.assertEqual(code, 0)
        self.assertIn("VERDICT: NO INDICATORS", text)

    def test_json_to_stdout_is_pure_json(self):
        code, text = self.cli(["good/lib", "--json", "-"], clean_routes())
        self.assertEqual(json.loads(text)["verdict"], "info")

    def test_rate_limit_gives_partial_report_and_exit_4(self):
        routes = affected_routes()

        def boom(_):
            raise wh.RateLimited(0)
        routes["/repos/victim/app/activity"] = boom
        code, text = self.cli(["victim/app"], routes, AFFECTED_RAW)
        self.assertEqual(code, 4)
        self.assertIn("INCOMPLETE", text)

    def test_bad_input(self):
        with self.assertRaises(SystemExit):
            with redirect_stdout(io.StringIO()), mock.patch("sys.stderr", io.StringIO()):
                wh.main(["not a repo!"])
        with self.assertRaises(SystemExit):
            with mock.patch("sys.stderr", io.StringIO()):
                wh.main([])


if __name__ == "__main__":
    unittest.main()
