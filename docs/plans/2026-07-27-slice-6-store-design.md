# Slice 6 Design: The SQLite Store

**Status:** planned.
**Supersedes nothing.** Builds directly on slice 5, which gave the workspace its `.vigilloo/`
directory and left the store that belongs inside it unbuilt.

## Why this slice

Nothing survives a run. Every feature that makes a scanner usable in CI - baselines,
suppressions that stay suppressed, `report --compare`, "when did this get introduced" - reads
history that does not exist yet. This slice creates `.vigilloo/vigilloo.db` and writes one row
per scan and one row per finding into it.

The store is a **write** this slice, not a read. No command reads the history back; the readers
(`report --compare`, baseline matching) are their own slices with their own CLI surface, and
building them against an empty database would be building them blind.

## Scope

Implemented, with the column shapes of [17-database](../17-database/README.md):

| Table | Why now |
| --- | --- |
| `schema_meta` | The version cell. Without it the first migration has nothing to read. |
| `projects` | One row per root path. Everything else hangs off `project_id`. |
| `scans` | The unit of history. `engine_version` + `ruleset_hash` are what make an old result reproducible. |
| `files` | The FK target for findings and evidence steps, and the honest source of `files_total`/`files_parsed`/`files_failed`. Its `sha256` is the incrementality key, unused this slice. |
| `findings` | The point of the slice. |
| `evidence_paths` | Invariant 2: no path, no finding. A finding stored without its path is not a stored finding. |

Not implemented, and why:

| Table | Trigger to build it |
| --- | --- |
| `nodes`, `edges` | The graph is rebuilt in memory every run and no consumer reads it back. Lands with incremental scanning, which is what makes persisting it pay. |
| `packages`, `advisories`, `package_advisories` | There is no dependency scanner yet. |
| `ai_verdicts`, `ai_cache` | v0.5. |
| `symbol_cache`, `summary_cache` | Caches with no cache hit path. Lands with incrementality, keyed by the `files.sha256` this slice starts writing. |

Also deferred inside the tables that are built:

- **Retention.** [17-database](../17-database/README.md) keeps the last 10 scans. Ten scans of a
  small findings set is kilobytes; pruning arrives when something measures.
- **`git_commit` / `git_branch` / `dirty`.** Nullable, no reader, and they would put a
  `subprocess` call in the scan path for nobody.
- **`files.role`.** Left NULL rather than guessed. Role classification is a real piece of Laravel
  knowledge and does not belong in a storage slice.
- **Real migrations.** One schema version, created whole. Forward-only migration steps arrive
  with version 2, which is the first time there is anything to migrate from.

## Spec correction: the findings primary key

[17-database](../17-database/README.md) declares `findings.id TEXT PRIMARY KEY` **and**
`UNIQUE (scan_id, id)`, while its design notes say findings are per-scan so that trends and
`first_seen_scan` work. Those three statements cannot all hold: `id` is content-derived, so a
finding that survives from scan 1 into scan 2 has the same `id` in both, and a bare
`PRIMARY KEY` on it makes the second scan's insert fail. The `UNIQUE (scan_id, id)` line is the
one that reflects the intent.

Resolved, and `docs/17-database` updated in the same commit:

- `findings`: `PRIMARY KEY (scan_id, id)`, replacing both the bare primary key and the now
  redundant unique constraint. `id` stays a content-derived `TEXT` column and stays the finding's
  identity; the scan is what makes a *row*.
- `evidence_paths`: gains `scan_id`, so its foreign key can reference the composite parent -
  `FOREIGN KEY (scan_id, finding_id) REFERENCES findings(scan_id, id) ON DELETE CASCADE` - and its
  uniqueness becomes `UNIQUE (scan_id, finding_id, step, is_primary)`.
- `ai_verdicts.finding_id` is left as spec'd. A verdict is about a finding's identity, not about
  the run that happened to observe it. It is not built in this slice.

## Interface

`src/store.py`, a flat module beside `graph.py` and `report.py` like the rest of the first
slices. It is registered nowhere in `pyproject.toml` because it is not a subpackage.

```python
def connect(workspace: Workspace) -> sqlite3.Connection
    """Open .vigilloo/vigilloo.db, apply the pragmas, create the schema if absent."""

def record_scan(
    conn: sqlite3.Connection,
    project: Project,
    findings: list[Finding],
    *,
    engine_version: str,
    ruleset_hash: str,
    duration_ms: int,
) -> int
    """Write one scan and its findings in one transaction. Returns the scan id."""
```

`ruleset_hash` is passed in, never computed here. The store is below the security engine and must
not learn what a rule is; `rules.py` exports `RULESET_HASH` over its own rule table and the CLI
carries it down. The same reasoning keeps `engine_version` a parameter.

`record_scan` is one transaction. A scan that fails halfway leaves no row rather than a row
claiming a coverage it did not achieve.

**`first_seen_scan`** is the one derived column: for each finding, the earliest scan of this
project that recorded the same `fingerprint`, falling back to the current scan. Fingerprint, not
`id`, is the lookup key - that is what makes a finding survive a reformat, and getting it wrong
here is what makes every reformat resurrect a backlog.

**`scans.status`** is `partial` when any file failed to read or parse, `completed` otherwise.
Coverage is reported, never hidden, and that includes in the store.

## Supporting change: file digests

`files.sha256` must be the digest of what was analysed. `Project` keeps `ParsedFile.source` for
PHP, but for Blade it keeps the *rewritten* PHP, whose digest is not a safe stand-in for the
template's. `graph.load_project` therefore records `Project.digests: dict[Path, str]` while it
still holds the original bytes of each file. Four lines, and it keeps the store from re-reading
the tree it was just handed.

## Tests

`tests/test_store.py`:

| Test | Guards |
| --- | --- |
| Schema is created and `schema_meta` carries the version | The migration entry point runs at all. |
| Reopening an existing database keeps its rows | Reopen must not drop findings history - the one thing in `.vigilloo/` that cannot be rebuilt. |
| A scan writes its findings and every evidence step | Invariant 2, at the storage boundary. |
| The same finding recorded in two scans keeps its `first_seen_scan` | The spec-correction key and the derived column together. This is the test that would have failed against the schema as written. |
| A file that failed to parse makes the scan `partial` and shows in `files_failed` | Invariant 4. |
| Recording a scan for the same root twice reuses the project row | `root_path UNIQUE` is honoured rather than crashed into. |

`tests/test_cli.py` gains one case: `vigilloo scan` on a fixture leaves a `vigilloo.db` holding
one scan and the same findings the terminal printed.

## Tasks

1. **`src/store.py`, `Project.digests`, `tests/test_store.py`.** The schema, the connection, the
   write path, its tests. No CLI change, so the whole suite still passes with the store unused.
2. **Wire it into `scan`, correct the spec.** `cli.py` opens the store and records the scan;
   `rules.py` exports `RULESET_HASH`; `docs/17-database` takes the primary-key correction and
   `CLAUDE.md` stops saying nothing persists.
