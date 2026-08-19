# Branch protection on `main`

`main` was red for seven consecutive commits between 2026-08-12 and 2026-08-19 because pushes
land without CI having to pass. A build nobody can merge past is the only kind that stays
green.

Apply in Settings > Branches > Add rule, or with the `gh` command below:

- Branch name pattern: `main`
- Require a pull request before merging: **on**
- Require status checks to pass before merging: **on**
  - Required check: `check` (the single job in `.github/workflows/ci.yml`)
- Require branches to be up to date before merging: **on**
- Do not allow bypassing the above settings: **on**

```bash
gh api -X PUT repos/HafizMMoaz/vigilloo/branches/main/protection \
  -H "Accept: application/vnd.github+json" \
  -f 'required_status_checks[strict]=true' \
  -f 'required_status_checks[contexts][]=check' \
  -f 'enforce_admins=true' \
  -f 'required_pull_request_reviews[required_approving_review_count]=0' \
  -f 'restrictions=null'
```

The review count is zero deliberately: this is a solo repository, and the value of the rule is
the status check, not a second pair of eyes that does not exist.
