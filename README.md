# wfx-defense-lab

Harmless lab that backs the SecurityCipher write-up on the November 2026 wfx / wfx-loot
GitHub Actions secret stealer. Nothing here steals anything. The secrets in this repo
are dummy strings.

What it demonstrates:

- `secret-scope.yml` - a plain job sees every repository secret through
  `toJSON(secrets)`, but an `environment: production` job with a branch policy refuses to
  start on a throwaway `chore/xxxxxxxx` branch. It also prints the OIDC `sub` claim each job
  would present to AWS, Azure or GCP.
- `status-forge.yml` - posts a fake `build` success with the workflow's own `GITHUB_TOKEN`,
  the same trick wfx uses to clear required checks. Pinning the required check to the
  GitHub Actions app does not stop it, because the forged status comes from that app.

Hunting script: [`wfx_hunt.py`](wfx_hunt.py) (read-only, standard library only).
