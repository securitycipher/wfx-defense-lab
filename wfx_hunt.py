#!/usr/bin/env python3
"""wfx_hunt.py - read-only hunt for the November 2026 wfx / wfx-loot GitHub campaign.

Checks every repository a token can see (or the repos you pass) for:
  - probe pull requests ("docs: dependency audit notes" from wfx-docs)
  - attacker branches (wfx-docs, chore/xxxxxxxx, ci-check-NNNN, ci-<run>-<job>-<pid>)
  - payload / cleanup commits since 2026-11-10
  - forged commit statuses (the payload sets description "wfx")
  - deleted workflow runs (gaps in run_number) near a suspicious commit
  - leftovers on the default branch (.ci-*.sh, build-audit-*.yml, npm hooks, WF_CTOKEN)

Needs only the Python standard library and a token in GITHUB_TOKEN
(fine-grained, read-only: Contents, Pull requests, Actions, Commit statuses, Metadata).

  GITHUB_TOKEN=... python3 wfx_hunt.py                 # every repo the token can reach
  GITHUB_TOKEN=... python3 wfx_hunt.py owner/repo ...  # specific repos
"""
from __future__ import annotations

import base64
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict

SINCE = os.environ.get("WFX_SINCE", "2026-11-10T00:00:00Z")
API = "https://api.github.com"
TOKEN = os.environ.get("GITHUB_TOKEN", "")

PROBE_TITLE = "docs: dependency audit notes"
PAYLOAD_MSGS = ("ci: refresh build cache", "chore: add ci helper",
                "chore: add dependency audit workflow", "ci: cache")
CLEANUP_MSGS = ("ci: restore", "ci: cleanup")  # noisy alone, only meaningful next to a payload commit
BRANCH_RES = [
    (re.compile(r"^wfx-docs$"), "probe branch"),
    (re.compile(r"^chore/[a-z0-9]{8}$"), "throwaway payload branch"),
    (re.compile(r"^ci-check-[0-9]{4}$"), "October GhostAction-style branch"),
    (re.compile(r"^ci-[0-9]+-[A-Za-z0-9_-]+-[0-9]+$"), "encrypted-loot fallback branch"),
]
FILE_RES = [
    (re.compile(r"(^|/)\.ci-[a-z0-9]{6}\.sh$"), "hidden payload script"),
    (re.compile(r"^\.github/workflows/build-audit-[a-z0-9]{6}\.ya?ml$"), "payload workflow"),
    (re.compile(r"^docs/wfx-audit\.md$"), "probe file"),
    (re.compile(r"^\.ci/[0-9]+-[0-9]+\.bin$"), "encrypted loot blob"),
]
MARKERS = re.compile(rb"WF_CTOKEN|WF_CALLBACK|WF_TG_BOTS|\.wfx-\$\$|wfx_status_ok|memscan_files")

C = {"hit": "\033[91m", "warn": "\033[93m", "ok": "\033[92m", "dim": "\033[90m", "end": "\033[0m"}


def say(kind: str, msg: str) -> None:
    tag = {"hit": "HIT ", "warn": "WARN", "ok": " ok ", "dim": "    "}[kind]
    print(f"  {C[kind]}[{tag}]{C['end']} {msg}")


def gh(path: str, params: dict | None = None, raw: bool = False):
    url = path if path.startswith("http") else API + path
    if params:
        url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params)
    req = urllib.request.Request(url)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    if TOKEN:
        req.add_header("Authorization", f"Bearer {TOKEN}")
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                body = r.read()
                return body if raw else json.loads(body or b"null"), r.headers
        except urllib.error.HTTPError as e:
            if e.code in (403, 429) and attempt < 3 and "rate limit" in e.read().decode(errors="ignore").lower():
                time.sleep(20 * (attempt + 1))
                continue
            if e.code in (404, 409, 451):
                return None, {}
            raise
    return None, {}


def paged(path: str, params: dict | None = None, key: str | None = None, cap: int = 1000):
    params = dict(params or {}, per_page=100)
    url, out = path, []
    while url and len(out) < cap:
        data, headers = gh(url, params)
        params = None
        if data is None:
            break
        out.extend(data[key] if key else data)
        m = re.search(r'<([^>]+)>;\s*rel="next"', headers.get("Link", "") or "")
        url = m.group(1) if m else None
    return out[:cap]


def repos_for_token() -> list[str]:
    rs = paged("/user/repos", {"affiliation": "owner,collaborator,organization_member"})
    return sorted(r["full_name"] for r in rs if not r.get("archived"))


def hunt(full: str) -> int:
    meta, _ = gh(f"/repos/{full}")
    if not meta:
        print(f"\n{full}\n  (not visible to this token)")
        return 0
    owner, default = meta["owner"]["login"], meta["default_branch"]
    print(f"\n{full}  {C['dim']}(default: {default}, {'private' if meta['private'] else 'public'}){C['end']}")
    hits = 0

    for b in paged(f"/repos/{full}/branches"):
        for rx, why in BRANCH_RES:
            if rx.match(b["name"]):
                say("hit", f"branch {b['name']} - {why}"); hits += 1

    probes = paged(f"/repos/{full}/pulls", {"state": "all", "head": f"{owner}:wfx-docs"}, cap=50)
    recent = paged(f"/repos/{full}/pulls", {"state": "all", "sort": "created", "direction": "desc"}, cap=100)
    seen = {p["number"] for p in probes}
    probes += [p for p in recent if p["title"].strip().lower() == PROBE_TITLE and p["number"] not in seen]
    for pr in probes:
        say("hit", f"probe PR #{pr['number']} by {pr['user']['login']} ({pr['state']}, "
                   f"{pr['created_at']}) - that account's token is stolen"); hits += 1

    sus_times: list[tuple[str, str, str]] = []
    for c in paged(f"/repos/{full}/commits", {"since": SINCE}, cap=500):
        msg = c["commit"]["message"].splitlines()[0].strip()
        who = (c.get("author") or {}).get("login") or c["commit"]["author"]["name"]
        when = c["commit"]["committer"]["date"]
        if msg in PAYLOAD_MSGS:
            say("hit", f"payload commit {c['sha'][:7]} '{msg}' by {who} at {when}"); hits += 1
            sus_times.append((when, c["sha"], who))
            statuses, _ = gh(f"/repos/{full}/commits/{c['sha']}/statuses")
            for s in statuses or []:
                if (s.get("description") or "").strip() == "wfx":
                    say("hit", f"forged status '{s['context']}'=success on {c['sha'][:7]} "
                               f"(description 'wfx') - check what merged on it"); hits += 1
        elif msg in CLEANUP_MSGS:
            sus_times.append((when, c["sha"], who))
            say("warn", f"cleanup-style commit {c['sha'][:7]} '{msg}' by {who} at {when}")

    # Rewritten history hides payload commits from the commit list, but the
    # activity log and surviving runs still point at them.
    seen_sha = {s[1] for s in sus_times}
    for ev in paged(f"/repos/{full}/activity", {"time_period": "month"}, cap=300):
        if ev.get("timestamp", "") < SINCE:
            continue
        for sha in (ev.get("after"), ev.get("before")):
            if not sha or set(sha) == {"0"} or sha in seen_sha:
                continue
            seen_sha.add(sha)
            c, _ = gh(f"/repos/{full}/commits/{sha}")
            msg = ((c or {}).get("commit", {}).get("message", "")).splitlines()[:1]
            if msg and msg[0].strip() in PAYLOAD_MSGS:
                who = (ev.get("actor") or {}).get("login", "?")
                say("hit", f"{ev['activity_type']} to {ev['ref']} carried payload commit {sha[:7]} "
                           f"'{msg[0].strip()}' (pushed by {who} at {ev['timestamp']})"); hits += 1
                sus_times.append((ev["timestamp"], sha, who))
        if ev.get("activity_type") == "force_push" and ev.get("ref") == f"refs/heads/{default}":
            say("warn", f"force push to {ev['ref']} by {(ev.get('actor') or {}).get('login', '?')} "
                        f"at {ev['timestamp']} - history was rewritten, git log alone is not enough")

    runs = paged(f"/repos/{full}/actions/runs", {"created": f">={SINCE[:10]}"}, key="workflow_runs", cap=1000)
    by_wf: dict[int, list[dict]] = defaultdict(list)
    for r in runs:
        by_wf[r["workflow_id"]].append(r)
        title = (r.get("display_title") or "").strip()
        if title in PAYLOAD_MSGS or title in CLEANUP_MSGS:
            sus_times.append((r["created_at"], r["head_sha"], r["actor"]["login"]))
            if title in PAYLOAD_MSGS:
                say("hit", f"run #{r['run_number']} '{r['name']}' survived on payload commit "
                           f"{r['head_sha'][:7]} - read its log"); hits += 1
    for wf_runs in by_wf.values():
        wf_runs.sort(key=lambda r: r["run_number"])
        for prev, nxt in zip(wf_runs, wf_runs[1:]):
            if nxt["run_number"] - prev["run_number"] <= 1:
                continue
            lo, hi = prev["created_at"], nxt["created_at"]
            near = [s for s in sus_times if lo <= s[0] <= hi or abs(_ts(s[0]) - _ts(lo)) < 900]
            missing = ", ".join(f"#{n}" for n in range(prev["run_number"] + 1, nxt["run_number"]))
            line = (f"deleted run(s) {missing} in '{prev['name']}' between {lo} and {hi}")
            if near:
                say("hit", line + f" - next to {near[0][1][:7]} by {near[0][2]}"); hits += 1
            else:
                say("warn", line)

    tree, _ = gh(f"/repos/{full}/git/trees/{urllib.parse.quote(default, safe='')}", {"recursive": "1"})
    paths = [t["path"] for t in (tree or {}).get("tree", []) if t.get("type") == "blob"]
    for p in paths:
        for rx, why in FILE_RES:
            if rx.search(p):
                say("hit", f"{p} on {default} - {why}"); hits += 1
    for p in [p for p in paths if p.startswith(".github/workflows/") or p == "package.json"][:30]:
        blob, _ = gh(f"/repos/{full}/contents/{urllib.parse.quote(p)}", {"ref": default})
        data = base64.b64decode(blob.get("content", "")) if blob else b""
        if MARKERS.search(data):
            say("hit", f"{p} still carries wfx payload markers - live payload"); hits += 1
        if p == "package.json" and re.search(rb'"\w+"\s*:\s*"[^"]*\.ci-[a-z0-9]{6}\.sh', data):
            say("hit", "package.json script runs a hidden .ci-*.sh - npm install runs the stealer"); hits += 1

    if not hits:
        say("ok", "no wfx indicators")
    return hits


def _ts(iso: str) -> float:
    return time.mktime(time.strptime(iso[:19], "%Y-%m-%dT%H:%M:%S"))


def main() -> None:
    if not TOKEN:
        sys.exit("set GITHUB_TOKEN (read-only fine-grained token is enough)")
    targets = sys.argv[1:] or repos_for_token()
    print(f"wfx hunt since {SINCE} across {len(targets)} repo(s)")
    total = sum(hunt(r) for r in targets)
    print(f"\n{C['hit'] if total else C['ok']}{total} indicator(s){C['end']}")
    sys.exit(1 if total else 0)


if __name__ == "__main__":
    main()
