# wfx-defense-lab

Harmless lab that backs the SecurityCipher write-up on the November 2026 wfx / wfx-loot
GitHub Actions secret stealer. Nothing here steals anything. The secrets in this repo
are dummy strings.

What it is built to show (fork it and run it in your own private repo; on this public repo
GitHub holds the runs at `action_required`, which is the July 2026 protection doing its job):

- `secret-scope.yml` - a plain job that can read every repository secret through
  `toJSON(secrets)`, next to an `environment: production` job that a deployment branch
  policy should reject on a throwaway `chore/xxxxxxxx` branch. Both print the OIDC `sub`
  claim they would present to AWS, Azure or GCP.
- `status-forge.yml` - posts a fake `build` success with the workflow's own `GITHUB_TOKEN`,
  the same trick wfx uses to clear required checks. The status is attributed to GitHub
  Actions, so check-source pinning alone is not a full defense.

Hunting script: [`wfx_hunt.py`](wfx_hunt.py) (read-only, standard library only).
