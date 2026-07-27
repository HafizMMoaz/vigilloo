# Database

SQLite, one file per project at `.vigilloo/vigilloo.db`. It holds the graph, the findings and
the caches that make incremental scans fast.

Why SQLite: zero setup, single file, ships with Python, transactional, and recursive CTEs handle
graph traversal well enough at target scale. A scanner that needs a database server before it can
scan is a scanner people do not run.

## Schema

```sql
-- ─── Project & runs ──────────────────────────────────────────────────────
CREATE TABLE projects (
    id            INTEGER PRIMARY KEY,
    root_path     TEXT NOT NULL UNIQUE,
    name          TEXT,
    language      TEXT,              -- 'php'
    framework     TEXT,              -- 'laravel'
    framework_ver TEXT,              -- '11.9.2'
    created_at    TEXT NOT NULL
);

CREATE TABLE scans (
    id             INTEGER PRIMARY KEY,
    project_id     INTEGER NOT NULL REFERENCES projects(id),
    started_at     TEXT NOT NULL,
    finished_at    TEXT,
    status         TEXT NOT NULL,    -- running | completed | failed | partial
    git_commit     TEXT,
    git_branch     TEXT,
    dirty          INTEGER,          -- uncommitted changes present
    engine_version TEXT NOT NULL,
    ruleset_hash   TEXT NOT NULL,    -- with engine_version, makes results reproducible
    corpus_version TEXT,
    files_total    INTEGER,
    files_parsed   INTEGER,
    files_failed   INTEGER,          -- coverage honesty, surfaced in every report
    duration_ms    INTEGER,
    manifest       TEXT              -- JSON: plugin versions, disabled rules, errors
);

-- ─── Files ───────────────────────────────────────────────────────────────
CREATE TABLE files (
    id          INTEGER PRIMARY KEY,
    project_id  INTEGER NOT NULL REFERENCES projects(id),
    path        TEXT NOT NULL,       -- relative to root, forward slashes on all platforms
    sha256      TEXT NOT NULL,       -- the incrementality key
    language    TEXT,
    role        TEXT,                -- controller | model | middleware | blade | config | migration | test
    size_bytes  INTEGER,
    lines       INTEGER,
    parsed_at   TEXT,
    parse_state TEXT,                -- ok | partial | failed
    UNIQUE (project_id, path)
);

-- ─── Graph ───────────────────────────────────────────────────────────────
CREATE TABLE nodes (
    id          TEXT PRIMARY KEY,    -- deterministic: sha1(project:kind:fqn:span)
    project_id  INTEGER NOT NULL REFERENCES projects(id),
    kind        TEXT NOT NULL,       -- route | class | method | variable | package | …
    name        TEXT,
    fqn         TEXT,
    file_id     INTEGER REFERENCES files(id),
    start_line  INTEGER, start_col INTEGER,
    end_line    INTEGER, end_col   INTEGER,
    start_byte  INTEGER, end_byte  INTEGER,
    attrs       TEXT                 -- JSON, kind-specific
);
CREATE INDEX idx_nodes_kind  ON nodes(project_id, kind);
CREATE INDEX idx_nodes_fqn   ON nodes(project_id, fqn);
CREATE INDEX idx_nodes_file  ON nodes(file_id);

CREATE TABLE edges (
    id         INTEGER PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id),
    src_id     TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    dst_id     TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL,        -- CALLS | PROPAGATES_TO | PROTECTED_BY | …
    confidence REAL NOT NULL DEFAULT 1.0,
    resolution TEXT,                 -- static | facade | container | interface | heuristic | unresolved
    attrs      TEXT
);
CREATE INDEX idx_edges_src ON edges(src_id, kind);
CREATE INDEX idx_edges_dst ON edges(dst_id, kind);

-- ─── Findings ────────────────────────────────────────────────────────────
CREATE TABLE findings (
    id             TEXT NOT NULL,      -- sha1(rule:path:span:path_signature)
    project_id     INTEGER NOT NULL REFERENCES projects(id),
    scan_id        INTEGER NOT NULL REFERENCES scans(id),
    rule_id        TEXT NOT NULL,
    fingerprint    TEXT NOT NULL,      -- survives reformatting; baseline matching key
    severity       TEXT NOT NULL,
    confidence     REAL NOT NULL,
    title          TEXT NOT NULL,
    description    TEXT,
    remediation    TEXT,
    file_id        INTEGER REFERENCES files(id),
    start_line     INTEGER, start_col INTEGER,
    end_line       INTEGER, end_col   INTEGER,
    cwe            TEXT,               -- JSON array
    owasp          TEXT,               -- JSON array
    status         TEXT DEFAULT 'open',-- open | fixed | suppressed | false_positive
    suppressed_by  TEXT,
    suppress_reason TEXT,
    first_seen_scan INTEGER REFERENCES scans(id),
    PRIMARY KEY (scan_id, id)          -- the scan is what makes a row; see the design note
);
CREATE INDEX idx_findings_fp   ON findings(project_id, fingerprint);
CREATE INDEX idx_findings_scan ON findings(scan_id, severity);

CREATE TABLE evidence_paths (
    id         INTEGER PRIMARY KEY,
    scan_id    INTEGER NOT NULL,      -- part of the composite parent key, not a denormalisation
    finding_id TEXT NOT NULL,
    step       INTEGER NOT NULL,      -- 0 = source
    node_id    TEXT REFERENCES nodes(id),
    file_id    INTEGER REFERENCES files(id),
    line       INTEGER,
    role       TEXT,                  -- source | propagator | sanitizer | sink
    snippet    TEXT,
    note       TEXT,
    is_primary INTEGER DEFAULT 1,     -- 0 for alternate paths to the same sink
    FOREIGN KEY (scan_id, finding_id) REFERENCES findings(scan_id, id) ON DELETE CASCADE,
    UNIQUE (scan_id, finding_id, step, is_primary)
);

CREATE TABLE ai_verdicts (
    finding_id   TEXT PRIMARY KEY REFERENCES findings(id) ON DELETE CASCADE,
    provider     TEXT, model TEXT,
    explanation  TEXT,
    exploitability TEXT,             -- confirmed | likely | unlikely | not-exploitable
    impact       TEXT,
    patch_diff   TEXT,
    patch_validated INTEGER,         -- passed the validation gate
    confidence   REAL,
    citations    TEXT,               -- JSON array
    tokens_in    INTEGER, tokens_out INTEGER, cost_usd REAL,
    created_at   TEXT
);

-- ─── Dependencies ────────────────────────────────────────────────────────
CREATE TABLE packages (
    id         INTEGER PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id),
    ecosystem  TEXT NOT NULL,        -- 'composer'
    name       TEXT NOT NULL,
    version    TEXT NOT NULL,
    is_dev     INTEGER DEFAULT 0,
    direct     INTEGER DEFAULT 1,
    license    TEXT,
    UNIQUE (project_id, ecosystem, name)
);

CREATE TABLE advisories (
    id             TEXT PRIMARY KEY,  -- CVE or GHSA id
    package_name   TEXT NOT NULL,
    ecosystem      TEXT NOT NULL,
    affected_range TEXT NOT NULL,
    fixed_version  TEXT,
    severity       TEXT,
    cvss           REAL,
    epss           REAL,
    kev            INTEGER DEFAULT 0,
    summary        TEXT,
    published_at   TEXT
);

CREATE TABLE package_advisories (
    package_id   INTEGER NOT NULL REFERENCES packages(id) ON DELETE CASCADE,
    advisory_id  TEXT    NOT NULL REFERENCES advisories(id),
    reachable    INTEGER,            -- NULL = not computed; the key triage signal
    reach_path   TEXT,
    PRIMARY KEY (package_id, advisory_id)
);

-- ─── Caches ──────────────────────────────────────────────────────────────
CREATE TABLE symbol_cache   (file_sha TEXT PRIMARY KEY, parser_version TEXT NOT NULL,
                             symbols BLOB NOT NULL, created_at TEXT);
CREATE TABLE summary_cache  (fqn TEXT NOT NULL, file_sha TEXT NOT NULL,
                             summary BLOB NOT NULL, PRIMARY KEY (fqn, file_sha));
CREATE TABLE ai_cache       (key TEXT PRIMARY KEY,   -- hash(rule, code_slice, model)
                             response TEXT NOT NULL, created_at TEXT);

CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);  -- schema version
```

## Design notes

**Deterministic node and finding IDs.** Content-derived, never autoincrement. This is what makes
findings stable across runs, baselines meaningful, and incremental invalidation correct.
Getting this wrong breaks three features at once.

**Two identity keys per finding.** `id` is exact; `fingerprint` is location-independent. A
finding that moves down 20 lines during a refactor keeps its fingerprint and stays suppressed -
without this, every reformat resurrects the entire backlog and teams abandon the baseline.

**`ruleset_hash` + `engine_version` on every scan.** Reproducing a six-month-old result requires
knowing exactly what produced it.

**`files_failed` is a first-class column,** not a log line. Coverage gaps are surfaced in every
report; a security tool that quietly skips files it could not parse is actively misleading.

**Findings are per-scan, not global.** History enables trend reporting, `report --compare`, and
answering "when did this get introduced" via `first_seen_scan`. This is why the primary key is
`(scan_id, id)` and not `id` alone: `id` is content-derived, so a finding that survives from one
scan into the next carries the same `id` in both, and a bare primary key on it would make the
second scan's insert fail. `evidence_paths` carries `scan_id` for the same reason, to reference
that composite parent; `ai_verdicts` keys on `finding_id` alone on purpose, because a verdict is
about a finding's identity rather than the run that happened to observe it.

## Pragmas

```sql
PRAGMA journal_mode = WAL;      -- concurrent readers during a scan
PRAGMA synchronous  = NORMAL;   -- durability is not worth the write cost for a rebuildable cache
PRAGMA foreign_keys = ON;
PRAGMA cache_size   = -64000;   -- 64 MB
```

## Migrations

Version in `schema_meta`. Forward-only migrations at startup. Because the database is a
**rebuildable cache**, a migration that gets complicated is allowed to drop the graph and
re-derive it - but findings history and baselines must be preserved, since those cannot be
regenerated.

## Retention

Full graph for the current scan; the last N scans (default 10) of findings for trends; caches
pruned by age and total size. `vigilloo scan --no-cache` bypasses; `.vigilloo/` belongs in
`.gitignore`, while `vigilloo.yml` and the baseline are committed.

## Scale

At 1M LOC expect roughly 5-10M AST nodes. The AST layer stays in SQL and is queried, never
loaded wholesale; call and data-flow layers are materialised into NetworkX on demand. If the
graph outgrows SQLite, the store interface is the seam where Neo4j or DuckDB would go - but not
before there is a measured reason.
