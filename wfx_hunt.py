#!/usr/bin/env python3
"""wfx_hunt - check GitHub orgs, users, and repos for the November 2026 wfx CI secret stealer.

Read-only. Python 3.8+ standard library only. Nothing is sent anywhere except api.github.com
and raw.githubusercontent.com.

Examples:
  python3 wfx_hunt.py zerosoul/rc-bullets                   # one repo
  python3 wfx_hunt.py https://github.com/owner/repo         # URLs work too
  python3 wfx_hunt.py --org my-org                          # search the org, deep-check hits
  python3 wfx_hunt.py --user some-dev --json report.json    # every repo a user owns
  GITHUB_TOKEN=github_pat_... python3 wfx_hunt.py --org my-org --all-repos --markdown report.md
  GITHUB_TOKEN=github_pat_... python3 wfx_hunt.py --mine    # everything the token can reach

A token is optional for public repos (GitHub allows about 60 anonymous requests an hour,
roughly three repos). Set GITHUB_TOKEN or GH_TOKEN to a fine-grained token with read-only
Metadata, Contents, Pull requests, Actions, and Commit statuses for private repos and big orgs.

Exit codes: 0 no indicators, 1 needs review, 2 probed, 3 affected, 4 scan incomplete.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone

__version__ = "2.0.0"

API = "https://api.github.com"
RAW = "https://raw.githubusercontent.com"
DEFAULT_SINCE = "2026-11-10T00:00:00Z"

PROBE_TITLE = "docs: dependency audit notes"
PAYLOAD_MSGS = ("ci: refresh build cache", "chore: add ci helper",
                "chore: add dependency audit workflow", "ci: cache")
SEARCHABLE_PAYLOAD = PAYLOAD_MSGS[:3]
CLEANUP_MSGS = ("ci: restore", "ci: cleanup")  # noisy alone, only meaningful next to a payload commit

BRANCH_RULES = [
    (re.compile(r"^wfx-docs$"), "probed", "Probe branch wfx-docs is still there"),
    (re.compile(r"^ci-\d+-[A-Za-z0-9_-]+-\d+$"), "affected", "Encrypted loot fallback branch"),
    (re.compile(r"^chore/[a-z0-9]{8}$"), "review", "Throwaway chore/xxxxxxxx branch (payload workflow pattern)"),
    (re.compile(r"^ci-check-\d{4}$"), "review", "October GhostAction-style branch"),
]
FILE_RULES = [
    (re.compile(r"(^|/)\.ci-[a-z0-9]{6}\.sh$"), "affected", "Hidden payload script"),
    (re.compile(r"^\.github/workflows/build-audit-[a-z0-9]{6}\.ya?ml$"), "affected", "Injected Dependency Audit workflow"),
    (re.compile(r"^docs/wfx-audit\.md$"), "probed", "Probe file docs/wfx-audit.md"),
    (re.compile(r"^\.ci/\d+-\d+\.bin$"), "affected", "Encrypted loot file"),
]
MARKERS = re.compile(r"WF_CTOKEN|WF_CALLBACK|WF_TG_BOTS|WF_MEMSCAN|WFXLOG-BEGIN|"
                     r"194\.150\.166\.244|18\.143\.168\.96|153\.75\.82\.159")
HOOK_RE = re.compile(r'"\w+"\s*:\s*"[^"]*\.ci-[a-z0-9]{6}\.sh')

LEVELS = ("info", "review", "probed", "affected")
RANK = {lvl: i for i, lvl in enumerate(LEVELS)}

VERDICTS = {
    "affected": "The wfx payload reached code here. Assume every secret and cloud role those "
                "workflows could read is stolen, and that a backdoor may be left behind.",
    "probed": "An account with write access opened a wfx probe. That account's token is in "
              "attacker hands even if no payload ran.",
    "review": "Nothing conclusive, but there are signs worth checking by hand against the audit log.",
    "info": "No wfx indicators in what GitHub let us see. Deleted run logs, private repos you "
            "cannot read, and cloud backdoors are out of reach from here.",
}
NEXT_STEPS = {
    "affected": [
        "Revoke tokens, OAuth apps, SSH keys, and sessions for every account named above, and turn on 2FA.",
        "Rotate every Actions secret and variable on the hit repos, plus org secrets they can read and any registry or AI API keys.",
        "Hunt cloud persistence: AWS roles whose trust policy allows \"AWS\": \"*\", new IAM access keys, "
        "sessions named wfx-*, and Azure federated credentials named wfx-ci-*.",
        "Remove payload files and hooks, then treat any laptop that ran npm install on a payload commit as compromised.",
        "Pull the org audit log for workflows.delete_workflow_run and save surviving run logs as evidence.",
    ],
    "probed": [
        "Revoke every token, OAuth app, SSH key, and session of the account that opened the probe, then enable 2FA.",
        "List every repo that account can write to and run this tool on each one.",
        "Close the probe PR and delete the wfx-docs branch after saving the evidence.",
    ],
    "review": [
        "Compare each run-number gap with the audit log (workflows.delete_workflow_run) to see who deleted what.",
        "Check force pushes to the default branch against your team's own history.",
        "If anything lines up with 10 to 12 November 2026, treat the repo as affected.",
    ],
    "info": [
        "Run again with a read-only token to cover private repos.",
        "Move production secrets into environments with branch policies and required reviewers.",
        "Pin OIDC trust policies to a specific repository, environment, and branch.",
    ],
}


@dataclass
class Finding:
    level: str
    repo: str
    title: str
    detail: str
    url: str = ""


class RateLimited(Exception):
    pass


class AuthError(Exception):
    pass


def fmt(iso: str) -> str:
    try:
        return datetime.strptime(iso[:19], "%Y-%m-%dT%H:%M:%S").strftime("%Y-%m-%d %H:%M UTC")
    except (TypeError, ValueError):
        return str(iso)


def ts(iso: str) -> float:
    try:
        return datetime.strptime(iso[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc).timestamp()
    except (TypeError, ValueError):
        return 0.0


def enc(path: str) -> str:
    return "/".join(urllib.parse.quote(p, safe="") for p in path.split("/"))


def first_line(msg: str) -> str:
    return (msg or "").split("\n", 1)[0].strip()


def parse_target(text: str):
    """Return (owner, repo_or_None) or None for input that is not a GitHub target."""
    t = re.sub(r"^https?://(www\.)?github\.com/", "", text.strip(), flags=re.I).lstrip("@")
    parts = [p for p in re.split(r"[?#]", t)[0].split("/") if p]
    if not parts or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})", parts[0]):
        return None
    if len(parts) == 1:
        return parts[0], None
    repo = re.sub(r"\.git$", "", parts[1])
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,100}", repo):
        return None
    return parts[0], repo


class GitHub:
    """Tiny read-only GitHub REST client with rate-limit awareness."""

    def __init__(self, token: str = "", timeout: int = 30, opener=None):
        self.token = token
        self.timeout = timeout
        self.calls = 0
        self.remaining = None
        self.reset = None
        self._lock = threading.Lock()
        self._open = opener or urllib.request.urlopen

    def _headers(self, api: bool) -> dict:
        h = {"User-Agent": f"wfx-hunt/{__version__}"}
        if api:
            h["Accept"] = "application/vnd.github+json"
            h["X-GitHub-Api-Version"] = "2022-11-28"
            if self.token:
                h["Authorization"] = f"Bearer {self.token}"
        return h

    def _track(self, headers) -> None:
        if not headers or headers.get("x-ratelimit-resource") == "search":
            return
        rem = headers.get("x-ratelimit-remaining")
        if rem is not None:
            with self._lock:
                self.remaining = int(rem)
                self.reset = int(headers.get("x-ratelimit-reset") or 0) or None

    def get(self, path: str, params: dict | None = None):
        """Return (json, link_header). Missing or forbidden resources return (None, "")."""
        url = path if path.startswith("http") else API + path
        if params:
            url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params)
        for attempt in range(4):
            with self._lock:
                self.calls += 1
            try:
                with self._open(urllib.request.Request(url, headers=self._headers(True)), timeout=self.timeout) as r:
                    self._track(r.headers)
                    body = r.read()
                    return (json.loads(body) if body else None), (r.headers.get("Link") or "")
            except urllib.error.HTTPError as e:
                self._track(e.headers)
                text = e.read().decode(errors="ignore").lower()
                if e.code == 401:
                    raise AuthError("GitHub rejected the token (401). Check GITHUB_TOKEN or unset it.")
                if e.code in (403, 429):
                    hdr = e.headers or {}
                    if hdr.get("x-ratelimit-remaining") == "0":
                        reset = int(hdr.get("x-ratelimit-reset") or 0)
                        wait = reset - time.time()
                        if hdr.get("x-ratelimit-resource") == "search" and 0 < wait < 70:
                            time.sleep(wait + 1)
                            continue
                        raise RateLimited(reset)
                    if "secondary rate limit" in text or e.code == 429:
                        time.sleep(min(int(hdr.get("retry-after") or 15 * (attempt + 1)), 60))
                        continue
                    return None, ""
                if e.code in (404, 409, 410, 422, 451):
                    return None, ""
                if e.code >= 500 and attempt < 3:
                    time.sleep(2 * (attempt + 1))
                    continue
                raise
            except urllib.error.URLError:
                if attempt < 3:
                    time.sleep(2 * (attempt + 1))
                    continue
                raise
        return None, ""

    def paged(self, path: str, params: dict | None = None, key: str | None = None, cap: int = 1000) -> list:
        out: list = []
        page = 1
        while len(out) < cap:
            data, link = self.get(path, dict(params or {}, per_page=100, page=page))
            if data is None:
                break
            items = data.get(key, []) if key else data
            if not isinstance(items, list):
                break
            out.extend(items)
            if len(items) < 100 or 'rel="next"' not in link:
                break
            page += 1
        return out[:cap]

    def raw(self, full: str, ref: str, path: str) -> str:
        url = f"{RAW}/{enc(full)}/{enc(ref)}/{enc(path)}"
        try:
            with self._open(urllib.request.Request(url, headers=self._headers(False)), timeout=self.timeout) as r:
                return r.read().decode(errors="ignore")
        except (urllib.error.HTTPError, urllib.error.URLError):
            return ""


class Hunter:
    def __init__(self, gh: GitHub, since: str = DEFAULT_SINCE, log=None):
        self.gh = gh
        self.since = since
        self.since_day = since[:10]
        self.runs_from = (datetime.strptime(self.since_day, "%Y-%m-%d") - timedelta(days=1)).strftime("%Y-%m-%d")
        self.findings: list[Finding] = []
        self.scanned: list[str] = []
        self.skipped: list[str] = []
        self.notes: list[str] = []
        self._seen: set = set()
        self._lock = threading.Lock()
        self.log = log or (lambda msg: None)

    def add(self, level: str, repo: str, title: str, detail: str, url: str = "") -> None:
        key = (level, repo, title, url or detail)
        with self._lock:
            if key in self._seen:
                return
            self._seen.add(key)
            self.findings.append(Finding(level, repo, title, detail, url))

    # ---- single repository -------------------------------------------------------------
    def scan_repo(self, full: str) -> None:
        gh = self.gh
        meta, _ = gh.get(f"/repos/{enc(full)}")
        if not meta:
            self.add("info", full, "Repository not visible",
                     "This token cannot read it." if gh.token else "It may be private. Set a read-only GITHUB_TOKEN that can read it.")
            return
        full = meta["full_name"]
        default = meta["default_branch"]
        base = f"https://github.com/{full}"
        api = f"/repos/{enc(full)}"
        token = bool(gh.token)
        self.log(f"deep check {full} ({'private' if meta.get('private') else 'public'}, default {default})")

        with ThreadPoolExecutor(max_workers=6) as pool:
            f_branches = pool.submit(gh.paged, f"{api}/branches", {}, None, 300 if token else 100)
            f_pulls = pool.submit(gh.paged, f"{api}/pulls", {"state": "all", "sort": "created", "direction": "desc"}, None, 100)
            f_commits = pool.submit(gh.paged, f"{api}/commits", {"since": self.since, "sha": default}, None, 300 if token else 100)
            f_acts = pool.submit(gh.paged, f"{api}/activity", {"time_period": "month"}, None, 100)
            f_runs = pool.submit(gh.paged, f"{api}/actions/runs", {"created": f">={self.runs_from}"}, "workflow_runs", 300 if token else 200)
            f_tree = pool.submit(gh.get, f"{api}/git/trees/{urllib.parse.quote(default, safe='')}", {"recursive": "1"})
            branches, pulls, commits = f_branches.result(), f_pulls.result(), f_commits.result()
            acts, runs, (tree, _) = f_acts.result(), f_runs.result(), f_tree.result()

        sus: list[tuple[str, str, str]] = []
        seen_sha: set = set()
        payload_shas: list[str] = []
        cleanups: list[tuple[str, str, str]] = []

        for b in branches:
            for rx, level, why in BRANCH_RULES:
                if rx.match(b["name"]):
                    self.add(level, full, why, f"Branch {b['name']}", f"{base}/tree/{enc(b['name'])}")

        for pr in pulls:
            if (pr.get("created_at") or "") < self.since:
                continue
            head = (pr.get("head") or {}).get("ref", "")
            if head == "wfx-docs" or (pr.get("title") or "").strip().lower() == PROBE_TITLE:
                who = (pr.get("user") or {}).get("login", "unknown")
                state = "Merged" if pr.get("merged_at") else ("Still open" if pr.get("state") == "open" else "Closed")
                self.add("probed", full, f"Probe pull request #{pr['number']} by {who}",
                         f"{state}, opened {fmt(pr['created_at'])}. Treat {who}'s GitHub account and every "
                         "token it owns as stolen, even if nothing else ran.", pr.get("html_url", ""))

        for c in commits:
            seen_sha.add(c["sha"])
            msg = first_line((c.get("commit") or {}).get("message", ""))
            who = (c.get("author") or {}).get("login") or c["commit"]["author"]["name"]
            when = c["commit"]["committer"]["date"]
            if msg in PAYLOAD_MSGS:
                self.add("affected", full, f'Payload commit "{msg}"',
                         f"{c['sha'][:7]} by {who} at {fmt(when)}. If CI ran on it, every secret that job could read is gone.",
                         c.get("html_url", ""))
                sus.append((when, c["sha"], who))
                payload_shas.append(c["sha"])
            elif msg in CLEANUP_MSGS:
                sus.append((when, c["sha"], who))
                cleanups.append((f'Cleanup-style commit "{msg}"',
                                 f"{c['sha'][:7]} by {who} at {fmt(when)}. Common on its own; it matters "
                                 "right after a payload commit.", c.get("html_url", "")))

        def_ref = f"refs/heads/{default}"
        lookups: list[tuple[str, dict, str]] = []
        for ev in sorted(acts, key=lambda e: e.get("ref") != def_ref):
            if (ev.get("timestamp") or "") < self.since:
                continue
            actor = (ev.get("actor") or {}).get("login", "unknown")
            if ev.get("activity_type") == "force_push" and ev.get("ref") == def_ref:
                self.add("review", full, "Force push to the default branch",
                         f"By {actor} at {fmt(ev['timestamp'])}. History was rewritten, so git log alone proves nothing.",
                         f"{base}/activity")
            for sha in (ev.get("after"), ev.get("before")):
                if not sha or set(sha) == {"0"} or sha in seen_sha:
                    continue
                seen_sha.add(sha)
                if len(lookups) < (15 if token else 6):
                    lookups.append((sha, ev, actor))

        with ThreadPoolExecutor(max_workers=6) as pool:
            statuses = list(pool.map(lambda s: gh.get(f"{api}/commits/{s}/statuses")[0], payload_shas[:3]))
            looked = list(pool.map(lambda l: gh.get(f"{api}/commits/{l[0]}")[0], lookups))

        for sha, st in zip(payload_shas, statuses):
            for s in st or []:
                if (s.get("description") or "").strip() == "wfx":
                    self.add("affected", full, f'Forged commit status "{s.get("context")}"',
                             f'Marked {s.get("state")} with description "wfx" on {sha[:7]}. Check what was merged on the strength of it.',
                             f"{base}/commit/{sha}")
        for (sha, ev, actor), cr in zip(lookups, looked):
            msg = first_line(((cr or {}).get("commit") or {}).get("message", ""))
            if msg not in PAYLOAD_MSGS:
                continue
            ref = (ev.get("ref") or "").replace("refs/heads/", "")
            what = {"force_push": "Force push to", "branch_creation": "Branch created:",
                    "branch_deletion": "Branch deleted:"}.get(ev.get("activity_type"), "Push to")
            self.add("affected", full, f'Activity log shows payload commit "{msg}"',
                     f"{what} {ref} by {actor} at {fmt(ev['timestamp'])}. Commit {sha[:7]} may no longer show in git log.",
                     f"{base}/commit/{sha}")
            sus.append((ev["timestamp"], sha, actor))

        by_wf: dict = {}
        for r in runs:
            by_wf.setdefault(r["workflow_id"], []).append(r)
            title = (r.get("display_title") or "").strip()
            if title in PAYLOAD_MSGS:
                held = r.get("status") == "action_required"
                detail = f"Run #{r['run_number']} \"{r.get('name')}\" on {(r.get('head_sha') or '')[:7]}"
                if held:
                    detail += ". GitHub held it as action_required. Do not approve it, then delete it."
                else:
                    detail += f" ({r.get('conclusion') or r.get('status')}). Save its log before anyone deletes it."
                self.add("probed" if held else "affected", full,
                         "Payload run is waiting for approval" if held else "A run on a payload commit survived",
                         detail, r.get("html_url", ""))
                sus.append((r["created_at"], r.get("head_sha") or "", (r.get("actor") or {}).get("login", "")))

        review_gaps = 0
        for wf_runs in by_wf.values():
            wf_runs.sort(key=lambda r: r["run_number"])
            for prev, nxt in zip(wf_runs, wf_runs[1:]):
                gap = nxt["run_number"] - prev["run_number"]
                if gap <= 1:
                    continue
                lo, hi = ts(prev["created_at"]) - 900, ts(nxt["created_at"]) + 900
                near = next((s for s in sus if lo <= ts(s[0]) <= hi), None)
                if not near:
                    review_gaps += 1
                    if review_gaps > 4:
                        continue
                missing = [f"#{n}" for n in range(prev["run_number"] + 1, min(nxt["run_number"], prev["run_number"] + 7))]
                if gap - 1 > len(missing):
                    missing.append("...")
                detail = f"Between {fmt(prev['created_at'])} and {fmt(nxt['created_at'])}"
                if near:
                    detail += f". Lines up with suspicious commit {near[1][:7]}" + (f" by {near[2]}" if near[2] else "") + \
                              ". This is the wfx cover-up pattern."
                else:
                    detail += ". Could be routine cleanup. Compare with your audit log."
                self.add("affected" if near else "review", full,
                         f"Deleted run{'s' if len(missing) > 1 else ''} {', '.join(missing)} in \"{prev.get('name')}\"",
                         detail, f"{base}/actions")

        paths = [t["path"] for t in (tree or {}).get("tree", []) if t.get("type") == "blob"]
        for p in paths:
            for rx, level, why in FILE_RULES:
                if rx.search(p):
                    self.add(level, full, f"{why} is still on {default}", p, f"{base}/blob/{enc(default)}/{enc(p)}")
        to_read = [p for p in paths if re.fullmatch(r"\.github/workflows/[^/]+\.ya?ml", p) or p == "package.json"]
        to_read = to_read[:(20 if token else 0) if meta.get("private") else 30]

        def read(p: str) -> str:
            if not meta.get("private"):
                return gh.raw(full, default, p)
            blob, _ = gh.get(f"{api}/contents/{enc(p)}", {"ref": default})
            try:
                return base64.b64decode((blob or {}).get("content", "")).decode(errors="ignore")
            except (ValueError, TypeError):
                return ""

        with ThreadPoolExecutor(max_workers=6) as pool:
            texts = list(pool.map(read, to_read))
        for p, text in zip(to_read, texts):
            link = f"{base}/blob/{enc(default)}/{enc(p)}"
            if MARKERS.search(text):
                self.add("affected", full, f"Live wfx payload markers in {p}",
                         f"The stealer is still in this file on {default}. Remove it and rotate secrets now.", link)
            if p == "package.json" and HOOK_RE.search(text):
                self.add("affected", full, "An npm script runs a hidden .ci-*.sh",
                         "Anyone who ran npm install on this branch executed the stealer on their machine.", link)

        with self._lock:
            hit = any(f.repo == full and f.level != "info" for f in self.findings)
            self.scanned.append(full)
        if hit:
            for c in cleanups[:3]:
                self.add("info", full, *c)
        else:
            self.add("info", full, "No wfx indicators found",
                     f"Checked branches, pull requests, {len(commits)} commits, {len(runs)} workflow runs, "
                     f"the activity log, and {len(to_read)} workflow/package files.", base)

    # ---- org, user, or token scope ----------------------------------------------------
    def scan_owner(self, name: str, kind: str | None = None, all_repos: bool = False,
                   max_repos: int | None = None, workers: int = 4) -> None:
        gh = self.gh
        user, _ = gh.get(f"/users/{urllib.parse.quote(name)}")
        if not user:
            raise ValueError(f'No GitHub user or organization called "{name}" is visible.')
        login = user["login"]
        is_org = user.get("type") == "Organization"
        if kind == "org" and not is_org:
            self.notes.append(f"{login} is a user account, scanned as a user.")
        if kind == "user" and is_org:
            self.notes.append(f"{login} is an organization, scanned as an org.")
        scope = f"{'org' if is_org else 'user'}:{login}"
        self.log(f"searching {scope}")

        flagged: dict = {}
        for q in (f"{scope} is:pr head:wfx-docs", f'{scope} is:pr in:title "{PROBE_TITLE}" created:>={self.since_day}'):
            res, _ = gh.get("/search/issues", {"q": q, "per_page": 100})
            for it in (res or {}).get("items", []):
                repo = (it.get("repository_url") or "").replace(f"{API}/repos/", "")
                who = (it.get("user") or {}).get("login", "unknown")
                self.add("probed", repo, f"Probe pull request #{it['number']} by {who}",
                         f"{'Still open' if it.get('state') == 'open' else 'Closed'}, opened {fmt(it['created_at'])}. "
                         f"Treat {who}'s account and tokens as stolen.", it.get("html_url", ""))
                flagged[repo] = max(flagged.get(repo, 0), 1)
        for msg in SEARCHABLE_PAYLOAD:
            res, _ = gh.get("/search/commits", {"q": f'{scope} "{msg}" committer-date:>={self.since_day}', "per_page": 100})
            for it in (res or {}).get("items", []):
                if first_line((it.get("commit") or {}).get("message", "")) != msg:
                    continue
                repo = (it.get("repository") or {}).get("full_name", "")
                who = (it.get("author") or {}).get("login") or it["commit"]["author"]["name"]
                self.add("affected", repo, f'Payload commit "{msg}"',
                         f"{it['sha'][:7]} by {who} at {fmt(it['commit']['committer']['date'])}.", it.get("html_url", ""))
                flagged[repo] = 2

        repos = gh.paged(f"/{'orgs' if is_org else 'users'}/{urllib.parse.quote(login)}/repos",
                         {"type": "all", "sort": "pushed", "direction": "desc"}, None, 1000 if gh.token else 100)
        live = [r for r in repos if not r.get("archived")]
        if all_repos:
            pool_names = [r["full_name"] for r in live]
        else:
            pool_names = [r["full_name"] for r in live if (r.get("pushed_at") or "") >= self.since_day]
        # Search already reported probe PRs, so deep-check slots go to payload-commit hits
        # first and then to the newest pushes, where force-pushed payloads and deleted runs hide.
        pushed = {r["full_name"]: r.get("pushed_at") or "" for r in repos}
        candidates = list(dict.fromkeys(list(flagged) + pool_names))
        order = sorted(candidates, key=lambda r: (flagged.get(r) == 2, pushed.get(r, "")), reverse=True)
        cap = max_repos if max_repos is not None else (50 if gh.token else 3)
        self.log(f"{len(repos)} repos, {len(pool_names)} {'live' if all_repos else 'pushed since ' + self.since_day}, "
                 f"{len(flagged)} flagged by search, deep-checking {min(cap, len(order))}")
        self.deep_scan(order[:cap], workers if gh.token else 1)
        self.skipped.extend(order[cap:])

    def scan_mine(self, max_repos: int | None = None, workers: int = 4) -> None:
        if not self.gh.token:
            raise ValueError("--mine needs GITHUB_TOKEN.")
        repos = self.gh.paged("/user/repos", {"affiliation": "owner,collaborator,organization_member", "sort": "pushed"})
        names = [r["full_name"] for r in repos if not r.get("archived")]
        cap = max_repos if max_repos is not None else len(names)
        self.deep_scan(names[:cap], workers)
        self.skipped.extend(names[cap:])

    def deep_scan(self, names: list[str], workers: int) -> None:
        if workers <= 1:
            for n in names:
                self.scan_repo(n)
            return
        with ThreadPoolExecutor(max_workers=workers) as pool:
            list(pool.map(self.scan_repo, names))

    # ---- results ----------------------------------------------------------------------
    def verdict(self) -> str:
        return max((f.level for f in self.findings), key=lambda l: RANK[l], default="info")

    def counts(self) -> dict:
        return {lvl: sum(f.level == lvl for f in self.findings) for lvl in LEVELS if lvl != "info"}

    def by_repo(self) -> list[tuple[str, list[Finding]]]:
        groups: dict = {}
        for f in self.findings:
            groups.setdefault(f.repo, []).append(f)
        for fs in groups.values():
            fs.sort(key=lambda f: -RANK[f.level])
        return sorted(groups.items(), key=lambda kv: (-max(RANK[f.level] for f in kv[1]), kv[0].lower()))


# ---- output -------------------------------------------------------------------------------
COLORS = {"affected": "\033[1;37;41m", "probed": "\033[1;30;43m", "review": "\033[1;30;103m",
          "info": "\033[1;30;47m", "dim": "\033[2m", "bold": "\033[1m", "end": "\033[0m"}


def render_text(h: Hunter, targets: list[str], incomplete: str, color: bool) -> str:
    c = COLORS if color else {k: "" for k in COLORS}
    v = h.verdict()
    lines = []
    for repo, fs in h.by_repo():
        lines.append(f"\n{c['bold']}{repo}{c['end']}")
        for f in fs:
            lines.append(f"  {c[f.level]} {f.level.upper():<8} {c['end']} {f.title}")
            lines.append(f"            {c['dim']}{f.detail}{c['end']}")
            if f.url:
                lines.append(f"            {c['dim']}{f.url}{c['end']}")
    if h.skipped:
        lines.append(f"\n{c['bold']}Not deep-checked ({len(h.skipped)}){c['end']}  raise --max-repos or set GITHUB_TOKEN")
        lines.append("  " + " ".join(h.skipped[:30]) + (" ..." if len(h.skipped) > 30 else ""))
    for note in h.notes:
        lines.append(f"\nnote: {note}")
    n = h.counts()
    lines.append(f"\n{c[v]} VERDICT: {v.upper() if v != 'info' else 'NO INDICATORS'} {c['end']}  "
                 f"{n['affected']} affected, {n['probed']} probed, {n['review']} to review "
                 f"across {len(h.scanned)} deep-checked repo(s)  [{', '.join(targets)}]")
    lines.append(VERDICTS[v])
    if incomplete:
        lines.append(f"{c['affected']} INCOMPLETE {c['end']} {incomplete}")
    lines.append("\nNext steps:")
    lines += [f"  {i}. {s}" for i, s in enumerate(NEXT_STEPS[v], 1)]
    left = f", {h.gh.remaining} left this hour" if h.gh.remaining is not None else ""
    lines.append(f"\n{c['dim']}API requests: {h.gh.calls}{left}{c['end']}")
    return "\n".join(lines)


def render_json(h: Hunter, targets: list[str], incomplete: str) -> dict:
    return {
        "tool": "wfx_hunt", "version": __version__,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "since": h.since, "targets": targets, "verdict": h.verdict(), "counts": h.counts(),
        "incomplete": incomplete or None, "repos_scanned": sorted(h.scanned), "repos_skipped": h.skipped,
        "notes": h.notes, "findings": [asdict(f) for f in h.findings], "next_steps": NEXT_STEPS[h.verdict()],
    }


def render_markdown(h: Hunter, targets: list[str], incomplete: str) -> str:
    v = h.verdict()
    md = [f"## wfx check: {', '.join(targets)}", "", f"**Verdict:** {v.upper() if v != 'info' else 'NO INDICATORS'}  ",
          f"{VERDICTS[v]}", "", f"_Generated {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC by wfx_hunt {__version__}, "
          f"window since {h.since}_", ""]
    if incomplete:
        md += [f"> Incomplete: {incomplete}", ""]
    for repo, fs in h.by_repo():
        md.append(f"### {repo}")
        md += [f"- **{f.level.upper()}** {f.title} - {f.detail}" + (f" ([link]({f.url}))" if f.url else "") for f in fs]
        md.append("")
    if h.skipped:
        md += [f"### Not deep-checked ({len(h.skipped)})", ", ".join(f"`{r}`" for r in h.skipped), ""]
    md.append("### Next steps")
    md += [f"{i}. {s}" for i, s in enumerate(NEXT_STEPS[v], 1)]
    return "\n".join(md) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="wfx_hunt.py",
        description="Read-only check of GitHub orgs, users, and repos for the November 2026 wfx CI secret stealer.",
        epilog="Exit codes: 0 no indicators, 1 needs review, 2 probed, 3 affected, 4 scan incomplete.")
    ap.add_argument("targets", nargs="*", metavar="TARGET",
                    help="owner/repo, a github.com URL, or a bare org/user name")
    ap.add_argument("--org", action="append", default=[], metavar="NAME", help="scan an organization (repeatable)")
    ap.add_argument("--user", action="append", default=[], metavar="NAME", help="scan a user's repos (repeatable)")
    ap.add_argument("--mine", action="store_true", help="every repo the token can reach (needs GITHUB_TOKEN)")
    ap.add_argument("--all-repos", action="store_true",
                    help="with an org/user, deep-check every live repo instead of flagged + recently pushed ones")
    ap.add_argument("--max-repos", type=int, metavar="N",
                    help="cap deep checks per org/user (default 50 with a token, 3 without)")
    ap.add_argument("--since", default=DEFAULT_SINCE, metavar="ISO", help=f"start of the window (default {DEFAULT_SINCE})")
    ap.add_argument("--workers", type=int, default=4, metavar="N", help="repos checked in parallel with a token (default 4)")
    ap.add_argument("--json", metavar="FILE", help="write a JSON report ('-' for stdout)")
    ap.add_argument("--markdown", metavar="FILE", help="write a Markdown report")
    ap.add_argument("--no-color", action="store_true", help="plain text output")
    ap.add_argument("-q", "--quiet", action="store_true", help="no progress lines")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = ap.parse_args(argv)

    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2}Z)?", args.since):
        ap.error("--since must look like 2026-11-10 or 2026-11-10T00:00:00Z")
    since = args.since if "T" in args.since else args.since + "T00:00:00Z"

    repos, owners = [], []
    for t in args.targets:
        parsed = parse_target(t)
        if not parsed:
            ap.error(f"not a GitHub org, user, or owner/repo: {t!r}")
        if parsed[1]:
            repos.append(f"{parsed[0]}/{parsed[1]}")
        else:
            owners.append((parsed[0], None))
    owners += [(o, "org") for o in args.org] + [(u, "user") for u in args.user]
    if not (repos or owners or args.mine):
        ap.error("give at least one TARGET, --org, --user, or --mine")

    token = (os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or "").strip()
    color = sys.stdout.isatty() and not args.no_color and not os.environ.get("NO_COLOR")
    to_stderr = args.json == "-"

    def log(msg: str) -> None:
        if not args.quiet:
            print(f"{COLORS['dim'] if color else ''}> {msg}{COLORS['end'] if color else ''}",
                  file=sys.stderr if to_stderr else sys.stdout, flush=True)

    gh = GitHub(token)
    hunter = Hunter(gh, since, log)
    labels = repos + [o for o, _ in owners] + (["--mine"] if args.mine else [])
    log(f"wfx_hunt {__version__} | since {since} | token: {'yes' if token else 'no (public repos only, ~60 requests/hour)'}")

    incomplete = ""
    try:
        for name, kind in owners:
            hunter.scan_owner(name, kind, args.all_repos, args.max_repos, args.workers)
        if args.mine:
            hunter.scan_mine(args.max_repos, args.workers)
        hunter.deep_scan(repos, args.workers if token else 1)
    except RateLimited as e:
        when = datetime.fromtimestamp(e.args[0], timezone.utc).strftime("%H:%M UTC") if e.args and e.args[0] else "later"
        incomplete = f"GitHub's rate limit ran out (resets {when}). Results are partial; set GITHUB_TOKEN to keep going."
    except (AuthError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 4
    except urllib.error.URLError as e:
        incomplete = f"Network error talking to GitHub: {e}"

    if args.json:
        data = json.dumps(render_json(hunter, labels, incomplete), indent=2)
        if args.json == "-":
            print(data)
        else:
            with open(args.json, "w", encoding="utf-8") as fh:
                fh.write(data + "\n")
    if args.markdown:
        with open(args.markdown, "w", encoding="utf-8") as fh:
            fh.write(render_markdown(hunter, labels, incomplete))
    if args.json != "-":
        print(render_text(hunter, labels, incomplete, color))
    return 4 if incomplete else RANK[hunter.verdict()]


if __name__ == "__main__":
    sys.exit(main())
