# CLI

`vigilloo` is the primary interface and, through v1.0, the only one. Built on Typer + Rich,
with Textual for interactive views.

The binary name is **`vigilloo`** - from Latin *vigil*, watchman. No short alias; one name in
docs, CI configs and muscle memory.

## Commands

### `vigilloo scan`

The main command. Full analysis of a project.

```bash
vigilloo scan                          # current directory
vigilloo scan ./app --severity high    # only high and critical
vigilloo scan --format sarif -o out.sarif
vigilloo scan --no-ai                  # deterministic only (also the default without a key)
vigilloo scan --rules laravel.*,php.sql-injection
vigilloo scan --baseline .vigilloo/baseline.json
vigilloo scan --fail-on high           # CI gate
```

| Flag | Purpose |
| --- | --- |
| `--format` | `terminal` (default), `markdown`, `json`, `sarif`, `html` |
| `-o, --output` | Output file; stdout otherwise |
| `--severity` | Minimum severity to report |
| `--fail-on` | Minimum severity that sets a non-zero exit code |
| `--rules` / `--exclude-rules` | Glob-matched rule selection |
| `--baseline` | Suppress findings present in the baseline |
| `--min-confidence` | Drop findings below a confidence threshold |
| `--no-ai` / `--ai-provider` / `--ai-budget` | AI layer control |
| `--incremental` / `--no-cache` | Cache behaviour |
| `--jobs` | Parallelism, defaults to CPU count |
| `--include-vendor` | Analyse `vendor/` too (off by default) |

### `vigilloo review`

Focused review of a change rather than a whole project - the PR and pre-commit workflow.

```bash
vigilloo review                        # uncommitted changes
vigilloo review --staged               # pre-commit hook
vigilloo review --base main            # everything since main
vigilloo review --commit HEAD~3..HEAD
vigilloo review --pr 42                # GitHub PR (v1.0)
```

Reports only findings the change **introduced**, using the full graph for context so cross-file
flows are still caught. A change that adds a tainted argument to an existing sink is a new
finding even though the sink line is untouched.

### `vigilloo graph`

```bash
vigilloo graph build                              # build/refresh only
vigilloo graph export --format graphml -o g.graphml
vigilloo graph show --focus 'App\Http\Controllers\OrderController@search' --depth 3
vigilloo graph routes                             # route table with middleware and auth status
vigilloo graph paths --from route --to 'sink:sql'
vigilloo graph stats
```

`vigilloo graph routes` doubles as the attack-surface inventory, and is often the first thing a
security engineer runs on an unfamiliar codebase.

### `vigilloo explain`

```bash
vigilloo explain FINDING-ID     # full evidence path, CWE context, remediation
vigilloo explain --cwe 89
```

### `vigilloo fix`

```bash
vigilloo fix FINDING-ID              # show a validated patch
vigilloo fix FINDING-ID --apply      # apply after confirmation
vigilloo fix --all --severity critical --interactive
```

Never applies without confirmation, and never applies a patch that failed validation
([09-ai-engine](../09-ai-engine/README.md)).

### `vigilloo deps`

```bash
vigilloo deps                    # vulnerable packages, ranked by reachability
vigilloo deps --sbom cyclonedx -o sbom.json
vigilloo deps --reachable-only   # only advisories whose code is actually called
```

### `vigilloo secrets`

```bash
vigilloo secrets                 # working tree
vigilloo secrets --history       # full git history - finds rotated-but-never-purged keys
```

### `vigilloo mcp`

```bash
vigilloo mcp                          # stdio, for editor integration
vigilloo mcp --transport sse --port 8931
```

See [12-mcp](../12-mcp/README.md).

### `vigilloo report`

```bash
vigilloo report --format html -o report.html    # render the last scan, no re-scan
vigilloo report --compare .vigilloo/last.json   # what changed since
```

### `vigilloo baseline`

```bash
vigilloo baseline create      # accept current findings, gate only on new ones
vigilloo baseline update
vigilloo baseline diff
```

The realistic adoption path for an existing codebase: stop the bleeding first, pay down later.

### `vigilloo init`

Interactive setup - writes `vigilloo.yml`, offers a pre-commit hook and a CI workflow file.

### `vigilloo doctor`

Environment diagnostics: Python version, grammars, corpus version and age, provider connectivity,
cache health, plugin status. First thing to ask for in a bug report.

### `vigilloo update`

Refresh advisories, EPSS, KEV and the knowledge corpus. Explicit and never automatic - a scan
must never silently change behaviour because a feed updated mid-run.

### `vigilloo plugin`

`list`, `install`, `remove`, `info`.

### Gated behind authorization

`vigilloo attack` ([14-attack-engine](../14-attack-engine/README.md)) and `vigilloo monitor`
([15-runtime](../15-runtime/README.md)). Both ship disabled in v0.1.

### `vigilloo server` *(v2.0)*

Host, container and Kubernetes auditing.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success, nothing at or above `--fail-on` |
| 1 | Findings at or above `--fail-on` |
| 2 | Usage error |
| 3 | Analysis error - parse failures, plugin crash |
| 4 | Configuration error |
| 5 | Authorization missing for a gated command |

Distinguishing 1 from 3 is what lets CI tell "your code has a vulnerability" apart from
"the scanner broke" - conflating them trains teams to ignore both.

## Configuration

`vigilloo.yml` at the project root; precedence is CLI flags > env (`VIGILLOO_*`) > project file >
user config > defaults.

```yaml
version: 1
project:
  name: acme-app
  framework: laravel
scan:
  exclude: ["storage/**", "database/seeders/**"]
  severity: medium
  fail_on: high
rules:
  disable: ["laravel.debug-artifact"]
  custom_dir: .vigilloo/rules
taint:
  sources:
    - fqn: 'App\Support\LegacyInput::get'
      kinds: [sql, html, shell]
  sanitizers:
    - fqn: 'App\Support\Escaper::clean'
      clears: [html]
ai:
  enabled: true
  provider: ollama
  model: <configured-model>
  budget_usd: 2.00
suppress:
  - rule: php.sql-injection
    path: database/seeders/**
    reason: "Seeders run offline with static data"
    expires: 2026-12-31
```

## Output

Rich terminal output: severity-coloured, grouped by file, with the evidence path shown as a
code frame per step and a summary table. `--format terminal` detects non-TTY and degrades to
plain text automatically, so piping into a file or a CI log does not produce escape-code soup.

Interactive Textual mode (`vigilloo scan --interactive`) gives a browsable finding list with
path navigation and inline patch preview.
