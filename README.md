# wfx-defense-lab

`wfx_hunt.py` checks a GitHub org, user, or repo for the November 2026 **wfx / wfx-loot**
GitHub Actions secret stealer. It is a single Python file, standard library only, and it
only ever reads from the GitHub API.

Write-up with the full attack chain and the hardening steps:
[GitHub Actions Secret Stealer (wfx): Hunt, Rotate, Harden](https://securitycipher.com/2026/11/12/github-actions-secret-stealer-wfx/)

## Quick start

```bash
curl -fsSLO https://raw.githubusercontent.com/securitycipher/wfx-defense-lab/main/wfx_hunt.py
export GITHUB_TOKEN=github_pat_...        # optional, read-only is enough

python3 wfx_hunt.py my-org/my-repo         # one repo
python3 wfx_hunt.py --org my-org           # a whole organization
python3 wfx_hunt.py --user some-dev        # a personal account
python3 wfx_hunt.py --mine                 # every repo your token can reach
```

Python 3.9 or newer. No `pip install`.

## Inputs

| Input | What it does |
|---|---|
| `TARGET ...` | `owner/repo`, a `https://github.com/...` URL, or a bare org/user name. Mix as many as you like. |
| `--org NAME` | Scan an organization. Repeatable. |
| `--user NAME` | Scan a user's repos. Repeatable. |
| `--mine` | Every repo the token can reach (owner, collaborator, org member). Needs a token. |
| `--all-repos` | Deep-check every non-archived repo, not only flagged and recently pushed ones. |
| `--max-repos N` | Cap deep checks per org/user. Default 50 with a token, 3 without. |
| `--since ISO` | Start of the window. Default `2026-11-10T00:00:00Z`. |
| `--workers N` | Repos checked in parallel (token only). Default 4. |
| `--json FILE` | Write a JSON report. Use `-` for stdout. |
| `--markdown FILE` | Write a Markdown report (good for a ticket or `$GITHUB_STEP_SUMMARY`). |
| `--no-color`, `-q` | Plain output, no progress lines. |

The token comes from `GITHUB_TOKEN` or `GH_TOKEN`. Without one you only see public repos
and GitHub gives you about 60 requests an hour, which is enough for one or two repos.
A fine-grained token with read access to **Contents, Actions, Metadata and Pull requests**
covers private repos. Nothing is ever written.

## What it looks for

Per repo (the "deep check"):

- The probe: PR titled `docs: dependency audit notes` from `wfx-docs`, and `docs/wfx-audit.md`.
- Payload commits: `ci: refresh build cache`, `chore: add ci helper`,
  `chore: add dependency audit workflow`, `ci: cache`, plus the `ci: restore` / `ci: cleanup` follow-ups.
- The repo **activity log**, which still lists payload pushes after a force push or branch delete.
- **Deleted workflow runs**: gaps in `run_number`, matched against suspicious commits in the same window.
- Surviving runs on payload commits, and runs GitHub held at `action_required`.
- Forged commit statuses with the description `wfx`.
- Loot and throwaway branches: `ci-<run>-<job>-<pid>`, `chore/xxxxxxxx`.
- Leftover files: `.ci-xxxxxx.sh`, `build-audit-xxxxxx.yml`, `.ci/*.bin`, npm hooks that run them,
  and live payload markers (`WF_CTOKEN`, `WF_CALLBACK`, `WF_TG_BOTS`, `WF_MEMSCAN`, `WFXLOG-BEGIN`).
- Force pushes to the default branch inside the window.

Per org or user, it first runs GitHub search for probe PRs and payload commits across the
whole account, then deep-checks repos with payload-commit hits first and then the newest pushes.
Repos that did not fit under `--max-repos` are listed so you can raise the cap.

## Verdicts and exit codes

| Exit | Verdict | Meaning |
|---|---|---|
| 0 | NO INDICATORS | Nothing found in what GitHub let us see. |
| 1 | REVIEW | Run-number gaps or force pushes with no payload commit next to them. Check the audit log. |
| 2 | PROBED | The probe PR or branch exists. The account that opened it is compromised. |
| 3 | AFFECTED | Payload commits, deleted runs next to them, or payload files. Rotate everything. |
| 4 | INCOMPLETE | Rate limit or auth failure. Results so far are printed; rerun with a token. |

Exit codes make it easy to fail a scheduled job when something turns up.

## Sample output

```text
wfx-lab % python3 wfx_hunt.py zerosoul/rc-bullets -q
zerosoul/rc-bullets
   AFFECTED  Payload commit "chore: add ci helper"
            5567b05 by zerosoul at 2026-11-12 08:06 UTC. If CI ran on it, every secret that job could read is gone.
   AFFECTED  Deleted run #67 in "Deploy to github pages"
            Between 2026-11-12 08:06 UTC and 2026-11-12 08:08 UTC. Lines up with suspicious commit 1e70e47 by zerosoul.
   PROBED    Probe pull request #27 by zerosoul
            Still open, opened 2026-11-11 12:52 UTC.
   ...
 VERDICT: AFFECTED   8 affected, 2 probed, 0 to review across 1 deep-checked repo(s)
```

## Run it on a schedule

[`examples/wfx-scan.yml`](examples/wfx-scan.yml) is a ready workflow: copy `wfx_hunt.py` into
your own repo (vendoring beats curling a script into CI, which is exactly how this campaign
got in), add a read-only token as `WFX_HUNT_TOKEN`, and it scans your org daily, writes the
Markdown report to the job summary, and fails when anything is found.

## Limits

- Deleted run logs are gone. The tool proves a run existed and was removed; the audit log
  (`workflows.delete_workflow_run`) tells you who removed it.
- Private repos you cannot read are invisible. So are cloud-side backdoors: check AWS roles
  trusting `"AWS": "*"`, new IAM keys, `wfx-*` sessions and Azure `wfx-ci-*` federated credentials yourself.
- GitHub search indexes commits on default branches only, which is why every flagged repo
  also gets the activity log and run-gap checks.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

The tests use a fake GitHub client, so they run offline and cover every verdict, owner scans,
the deep-check cap, reports, and the rate-limit path.

## The lab workflows

`.github/workflows/secret-scope.yml` and `status-forge.yml` are harmless demos that go with the
write-up. The secrets in this repo are dummy strings. Fork it into a private repo to run them;
on this public repo GitHub holds the runs at `action_required`.

- `secret-scope.yml` shows what `toJSON(secrets)` exposes in a plain job versus an
  `environment: production` job with a branch policy, and prints the OIDC `sub` each would present.
- `status-forge.yml` posts a fake `build` success with the job's own `GITHUB_TOKEN`, the same
  trick wfx uses to clear required checks.

## License

MIT
