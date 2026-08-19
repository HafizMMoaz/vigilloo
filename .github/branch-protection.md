# Branch protection on `main`

**Applied 2026-08-19.** This file records what is configured and how to reproduce it.

`main` was red for seven consecutive commits between 2026-08-12 and 2026-08-19 because pushes
land without CI having to pass. A build nobody can merge past is the only kind that stays
green. The cost was not only a week of red lint: `set -e` halts the job at the first failure,
so the wheel step never ran, and it was concealing a total import failure on Python 3.13 - the
floor this package declares in `pyproject.toml`. A red build stops reporting everything
downstream of the first thing that broke.

## Configured

- Branch name pattern: `main`
- Require status checks to pass before merging: **on**
  - Required check: `check` (the single job in `.github/workflows/ci.yml`)
- Require branches to be up to date before merging (`strict`): **on**
- Do not allow bypassing the above settings (`enforce_admins`): **on**
- Force pushes: **blocked**
- Branch deletion: **blocked**
- Required approving reviews: **0**, deliberately. This is a solo repository; the value of the
  rule is the status check, not a second pair of eyes that does not exist. Raise it when there
  is someone to review.

## Reproducing it

The settings body has booleans and integers, so it must be sent as typed JSON. `gh api -f`
sends every value as a string and the API rejects it with a 422 (`"true" is not a boolean`),
so the body lives in `branch-protection.json` beside this file and goes in through `--input`:

```bash
gh api -X PUT repos/HafizMMoaz/vigilloo/branches/main/protection \
  -H "Accept: application/vnd.github+json" \
  --input .github/branch-protection.json
```

The body is a checked-in file rather than a heredoc in this document on purpose: CLAUDE.md
records that heredocs hang the agent environment, and a command in a runbook gets run.

Verify:

```bash
gh api repos/HafizMMoaz/vigilloo/branches/main/protection \
  -q '"checks: \(.required_status_checks.contexts)  admins: \(.enforce_admins.enabled)"'
```

Expected: `checks: ["check"]  admins: true`.

## Consequences for day-to-day work

Direct pushes to `main` are refused. Work goes on a branch and merges through a pull request
whose `check` run is green. `enforce_admins` means this applies to the repository owner too,
which is the point: the seven red commits were all pushed by the owner.

If the CI job is ever renamed, the required check name must be updated in the same commit, or
every pull request will wait forever on a check that no longer reports.
