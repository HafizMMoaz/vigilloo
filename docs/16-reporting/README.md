# Reporting

Findings serialised for four audiences: the developer at a terminal, the reviewer in a PR, the
CI pipeline, and the auditor.

## Formats

| Format | Audience | Notes |
| --- | --- | --- |
| **Terminal** | Developer, interactive | Rich output, severity colours, code frames. Auto-degrades to plain text when not a TTY. |
| **Markdown** | PR comments, tickets, humans | Default for `--format markdown`. Renders on GitHub/GitLab without extra tooling. |
| **JSON** | Machines, the desktop app, custom pipelines | Canonical, lossless, schema-versioned |
| **SARIF 2.1.0** | CI | GitHub code scanning, Azure DevOps, any SARIF consumer |
| **HTML** | Sharing, management, self-contained artefact | Single file, no external assets, embedded graph diagrams |
| **PDF** *(v2.0)* | Formal audits, compliance | Rendered from HTML |
| **CycloneDX / SPDX** | SBOM consumers | From `vigilloo deps --sbom` |

## Report structure

Every format carries the same content, ordered so the reader gets the answer before the detail:

1. **Summary** - counts by severity, scan duration, commit, engine and ruleset version
2. **Coverage** - files parsed / partial / failed, unresolved call edges, analysis gaps
3. **Findings** - grouped by severity, then by file
4. **Dependencies** - vulnerable packages, ranked by reachability
5. **Attack surface** - route inventory with auth status
6. **Trends** - new / fixed / unchanged vs the previous scan, when history exists

**Coverage sits second, ahead of the findings.** A report saying "0 critical findings" while
silently having failed to parse 40% of the codebase is worse than no report at all - it converts
ignorance into false confidence. Any report claiming a clean result must show what it actually
managed to look at.

## Finding presentation

Each finding renders: title and severity, location, the **full evidence path** with a code frame
per step, why it matters, remediation, and CWE/OWASP references. The AI explanation and patch
appear when available, clearly marked as AI-generated with their confidence.

```markdown
### 🔴 Critical - SQL Injection in OrderRepository::search

`app/Repositories/OrderRepository.php:42` · CWE-89 · OWASP A03:2021 · `php.sql-injection`

Attacker-controlled input reaches an unparameterised SQL fragment.

**Evidence path**

1. `routes/api.php:23` - route `POST /api/orders/search` → `OrderController@search`
   Middleware: `api`, `auth:sanctum` - requires authentication
2. `app/Http/Controllers/OrderController.php:41` - source
   ```php
   $sort = $request->input('sort');
   ```
3. `app/Http/Controllers/OrderController.php:44` - propagates as argument 0
   ```php
   return $this->orders->search($request->input('q'), $sort);
   ```
4. `app/Repositories/OrderRepository.php:42` - **sink**, unsanitized
   ```php
   ->orderByRaw("created_at {$sort}")
   ```

**Remediation** - pass user input as a binding, or validate against an allowlist:

```php
$direction = $sort === 'asc' ? 'asc' : 'desc';
->orderBy('created_at', $direction)
```
```

The path is the product. A severity label with a line number is what every other scanner
already produces; the traversal from route to sink is what a developer needs to decide whether
to care.

## SARIF specifics

- `rules[]` from the rule catalogue, with `help`, `helpUri`, CWE in `properties.tags`
- `partialFingerprints.vigillooFingerprint` - the stable fingerprint, so GitHub tracks a finding
  across commits instead of reopening it on every reformat
- Evidence paths as `codeFlows[].threadFlows[]`, which GitHub renders as clickable steps
- `invocation.executionSuccessful` false on partial scans, with `toolExecutionNotifications`
  carrying parse failures - surfacing coverage gaps in CI rather than hiding them
- Severity mapped to `level` (`error` / `warning` / `note`) plus `security-severity` for
  GitHub's own ranking

## Determinism

Byte-identical output for identical input (NFR-7): findings sorted by (severity, rule ID, path,
line), JSON keys sorted, no timestamps in the body - run metadata lives in a separate header
section that CI diffing can ignore. This is what makes report diffs meaningful.

## Diffing and trends

`vigilloo report --compare <previous.json>` classifies findings as new / fixed / unchanged by
fingerprint, not by line number. `vigilloo review` uses the same mechanism to report only what a
change introduced.

## Templating

Reporters are plugins ([11-plugin-sdk](../11-plugin-sdk/README.md)); Markdown and HTML use Jinja2
templates overridable per project for teams with their own house format. The JSON schema is
published and versioned so third-party consumers can rely on it.
