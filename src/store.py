"""The SQLite store: `.vigilloo/vigilloo.db`, one row per scan and per finding.

Write-only this slice (docs/plans/2026-07-27-slice-6-store-design.md): nothing reads history
back yet, so the only entry points are opening the database and recording a completed scan.
Knows nothing about rules or taint - `engine_version` and `ruleset_hash` arrive as parameters,
never computed here, so the store stays below the security engine in the layering CLAUDE.md
describes.
"""

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .graph import Project
from .models import Finding
from .workspace import Workspace

_DB_FILENAME = "vigilloo.db"
_SCHEMA_VERSION = 1

# Spec correction (docs/plans/2026-07-27-slice-6-store-design.md, "Spec correction" section):
# docs/17-database still shows `findings.id TEXT PRIMARY KEY` plus a redundant
# `UNIQUE (scan_id, id)`, which contradicts findings being per-scan - a finding that survives
# from one scan into the next has the same content-derived id in both, so a bare PRIMARY KEY on
# it would fail the second scan's insert. Built here as `PRIMARY KEY (scan_id, id)` instead; the
# doc is corrected in the same slice's second task. `evidence_paths` gains `scan_id` for the same
# reason, so its foreign key can reference the composite parent.
_SCHEMA_SQL = f"""
BEGIN;
CREATE TABLE projects (
    id            INTEGER PRIMARY KEY,
    root_path     TEXT NOT NULL UNIQUE,
    name          TEXT,
    language      TEXT,
    framework     TEXT,
    framework_ver TEXT,
    created_at    TEXT NOT NULL
);

CREATE TABLE scans (
    id             INTEGER PRIMARY KEY,
    project_id     INTEGER NOT NULL REFERENCES projects(id),
    started_at     TEXT NOT NULL,
    finished_at    TEXT,
    status         TEXT NOT NULL,
    git_commit     TEXT,
    git_branch     TEXT,
    dirty          INTEGER,
    engine_version TEXT NOT NULL,
    ruleset_hash   TEXT NOT NULL,
    corpus_version TEXT,
    files_total    INTEGER,
    files_parsed   INTEGER,
    files_failed   INTEGER,
    duration_ms    INTEGER,
    manifest       TEXT
);

CREATE TABLE files (
    id          INTEGER PRIMARY KEY,
    project_id  INTEGER NOT NULL REFERENCES projects(id),
    path        TEXT NOT NULL,
    sha256      TEXT NOT NULL,
    language    TEXT,
    role        TEXT,
    size_bytes  INTEGER,
    lines       INTEGER,
    parsed_at   TEXT,
    parse_state TEXT,
    UNIQUE (project_id, path)
);

CREATE TABLE findings (
    id              TEXT NOT NULL,
    project_id      INTEGER NOT NULL REFERENCES projects(id),
    scan_id         INTEGER NOT NULL REFERENCES scans(id),
    rule_id         TEXT NOT NULL,
    fingerprint     TEXT NOT NULL,
    severity        TEXT NOT NULL,
    confidence      REAL NOT NULL,
    title           TEXT NOT NULL,
    description     TEXT,
    remediation     TEXT,
    file_id         INTEGER REFERENCES files(id),
    start_line      INTEGER, start_col INTEGER,
    end_line        INTEGER, end_col   INTEGER,
    cwe             TEXT,
    owasp           TEXT,
    status          TEXT DEFAULT 'open',
    suppressed_by   TEXT,
    suppress_reason TEXT,
    first_seen_scan INTEGER REFERENCES scans(id),
    PRIMARY KEY (scan_id, id)
);
CREATE INDEX idx_findings_fp   ON findings(project_id, fingerprint);
CREATE INDEX idx_findings_scan ON findings(scan_id, severity);

CREATE TABLE evidence_paths (
    id         INTEGER PRIMARY KEY,
    scan_id    INTEGER NOT NULL,
    finding_id TEXT NOT NULL,
    step       INTEGER NOT NULL,
    -- node_id: docs/17-database declares REFERENCES nodes(id). `nodes` is not built this
    -- slice, and SQLite rejects a foreign key whose target table does not exist, so the
    -- reference arrives with the table. This is the only divergence from the doc's DDL.
    node_id    TEXT,
    file_id    INTEGER REFERENCES files(id),
    line       INTEGER,
    role       TEXT,
    snippet    TEXT,
    note       TEXT,
    is_primary INTEGER DEFAULT 1,
    FOREIGN KEY (scan_id, finding_id) REFERENCES findings(scan_id, id) ON DELETE CASCADE,
    UNIQUE (scan_id, finding_id, step, is_primary)
);
INSERT INTO schema_meta (key, value) VALUES ('version', '{_SCHEMA_VERSION}');
COMMIT;
"""
# schema_meta's table itself is created separately, before this script runs, so its version row
# can be checked before deciding whether the rest of the schema needs creating at all. The
# version row it holds afterward is written by the BEGIN/COMMIT inside the script above, in the
# same transaction as every CREATE TABLE - a process killed mid-script must roll back to nothing
# rather than leave tables with no version row, which would wedge every later connect() against
# "table already exists" with no schema_meta entry to tell it the schema is already there.


def connect(workspace: Workspace) -> sqlite3.Connection:
    """Open `.vigilloo/vigilloo.db`, apply the pragmas, create the schema if absent."""
    conn = sqlite3.connect(workspace.dir / _DB_FILENAME)
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA cache_size = -64000")
    _ensure_schema(conn)
    return conn


def _ensure_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
    )
    row = conn.execute("SELECT value FROM schema_meta WHERE key = 'version'").fetchone()
    if row is not None:
        return
    # ponytail: one whole-schema create, no migration steps - there is nothing yet to migrate
    # from. Version 2 needs a real migration runner the first time a shipped database has to
    # gain a column or table without losing findings history (docs/17-database "Migrations":
    # the graph may be dropped and re-derived, but findings and baselines must survive).
    conn.executescript(_SCHEMA_SQL)


def record_scan(
    conn: sqlite3.Connection,
    project: Project,
    findings: list[Finding],
    *,
    engine_version: str,
    ruleset_hash: str,
    duration_ms: int,
) -> int:
    """Write one scan and its findings in one transaction. Returns the scan id.

    A scan that fails halfway must leave no row rather than a row claiming a coverage it did
    not achieve, so every insert below - the project upsert included - happens inside the one
    transaction this connection opens on its first write.
    """
    finished_at = datetime.now(UTC)
    started_at = finished_at - timedelta(milliseconds=duration_ms)

    files_failed = len(project.failed)
    files_parsed = len(project.files) + len(project.blade)
    status = "partial" if project.failed or project.unparsed else "completed"

    with conn:
        project_id = _upsert_project(conn, project.root, finished_at)

        # git_commit / git_branch / dirty: ponytail, left NULL. Nullable, no reader yet, and a
        # subprocess call in the scan path buys nothing until something reads them back.
        cursor = conn.execute(
            "INSERT INTO scans "
            "(project_id, started_at, finished_at, status, engine_version, ruleset_hash, "
            "files_total, files_parsed, files_failed, duration_ms) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                project_id,
                started_at.isoformat(),
                finished_at.isoformat(),
                status,
                engine_version,
                ruleset_hash,
                files_parsed + files_failed,
                files_parsed,
                files_failed,
                duration_ms,
            ),
        )
        scan_id = cursor.lastrowid
        assert scan_id is not None  # AUTOINCREMENT rowid alias, always set on insert

        file_ids = _upsert_files(conn, project_id, project, finished_at.isoformat())

        for finding in findings:
            _insert_finding(conn, project_id, scan_id, finding, file_ids)

    # ponytail: no retention pruning. docs/17-database keeps the last 10 scans; ten scans of a
    # small findings set is kilobytes, so pruning arrives when a real project's history measures
    # large enough to justify it, not preemptively here.
    return scan_id


def _upsert_project(conn: sqlite3.Connection, root: Path, created_at: datetime) -> int:
    """Reuse the existing row for `root` rather than crash into `root_path UNIQUE`."""
    # language/framework are fixed for v0.1's PHP-and-Laravel-only scope (CLAUDE.md).
    # framework_ver: ponytail, left NULL - no version-detection pass exists yet.
    root_path = str(root)
    conn.execute(
        "INSERT INTO projects (root_path, language, framework, created_at) VALUES (?, ?, ?, ?) "
        "ON CONFLICT (root_path) DO NOTHING",
        (root_path, "php", "laravel", created_at.isoformat()),
    )
    row = conn.execute("SELECT id FROM projects WHERE root_path = ?", (root_path,)).fetchone()
    return int(row[0])


def _upsert_files(
    conn: sqlite3.Connection, project_id: int, project: Project, parsed_at: str
) -> dict[Path, int]:
    file_ids: dict[Path, int] = {}
    for rel_path, parsed in project.files.items():
        file_ids[rel_path] = _upsert_file(
            conn,
            project_id,
            rel_path,
            sha256=project.digests[rel_path],
            language="php",
            size_bytes=len(parsed.source),
            lines=len(parsed.source.splitlines()),
            parsed_at=parsed_at,
            parse_state="partial" if parsed.has_errors else "ok",
        )
    for rel_path, parsed in project.blade.items():
        file_ids[rel_path] = _upsert_file(
            conn,
            project_id,
            rel_path,
            sha256=project.digests[rel_path],
            language="blade",
            # size_bytes: ponytail, left NULL. ParsedFile.source here is the rewritten PHP, not
            # the template - the same gap project.digests exists to close - and a byte count of
            # the wrong text is worse than none, since nothing reads this column yet to notice.
            # lines comes from project.blade_lines instead: those are the template's own lines,
            # captured before the rewrite, so the count is exact rather than merely plausible.
            size_bytes=None,
            lines=len(project.blade_lines[rel_path]),
            parsed_at=parsed_at,
            parse_state="partial" if parsed.has_errors else "ok",
        )
    for path in project.failed:
        # A file that raised OSError never became a ParsedFile, so load_project recorded it as
        # whatever it was handed - absolute, since the walk itself deals in absolute paths and
        # only relativises on success. Hand-built Project fixtures may already be relative.
        rel_path = path.relative_to(project.root) if path.is_absolute() else path
        file_ids[rel_path] = _upsert_file(
            conn,
            project_id,
            rel_path,
            # sha256: ponytail, empty string. The file was never read, so there is no content to
            # hash - hashing zero bytes would claim a digest that matches no real content of
            # this file. NOT NULL forces some value; empty string is the least dishonest one
            # available until incremental scanning needs a real per-file failure record.
            sha256="",
            language="blade" if rel_path.name.endswith(".blade.php") else "php",
            size_bytes=None,
            lines=None,
            parsed_at=None,
            parse_state="failed",
        )
    return file_ids


def _upsert_file(
    conn: sqlite3.Connection,
    project_id: int,
    rel_path: Path,
    *,
    sha256: str,
    language: str,
    size_bytes: int | None,
    lines: int | None,
    parsed_at: str | None,
    parse_state: str,
) -> int:
    # role: ponytail, left NULL. Classifying controller/model/middleware/blade/etc. is real
    # Laravel knowledge (docs/17-database) and does not belong in a storage slice.
    #
    # ponytail: the row reflects the latest scan, unconditionally. Ceiling: a file that becomes
    # transiently unreadable overwrites a previously good row with sha256='' and NULL
    # size_bytes/lines/parsed_at, destroying the incrementality key for that file - the next
    # scan then has no digest to compare against and must re-analyse it. Harmless while nothing
    # reads files.sha256 back. Upgrade trigger: the first reader of that column, which is
    # incremental scanning (docs/plans/2026-07-27-slice-6-store-design.md leaves symbol_cache
    # and summary_cache keyed on it). Then a failed read must preserve the prior digest rather
    # than clear it - `DO UPDATE ... WHERE excluded.sha256 <> ''` or an explicit failure row.
    path = rel_path.as_posix()
    conn.execute(
        "INSERT INTO files "
        "(project_id, path, sha256, language, size_bytes, lines, parsed_at, parse_state) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT (project_id, path) DO UPDATE SET "
        "sha256 = excluded.sha256, language = excluded.language, "
        "size_bytes = excluded.size_bytes, lines = excluded.lines, "
        "parsed_at = excluded.parsed_at, parse_state = excluded.parse_state",
        (project_id, path, sha256, language, size_bytes, lines, parsed_at, parse_state),
    )
    row = conn.execute(
        "SELECT id FROM files WHERE project_id = ? AND path = ?", (project_id, path)
    ).fetchone()
    return int(row[0])


def _insert_finding(
    conn: sqlite3.Connection,
    project_id: int,
    scan_id: int,
    finding: Finding,
    file_ids: dict[Path, int],
) -> None:
    fingerprint = finding.fingerprint
    first_seen_scan = _first_seen_scan(conn, project_id, fingerprint, scan_id)

    # confidence: ponytail, hardcoded to 1.0. v0.1 rules are deterministic pattern matches with
    # no probability signal of their own; Finding gains a real one before this becomes a lie.
    # owasp/description: ponytail, left NULL. No OWASP category mapping exists yet, and Finding
    # carries only a title and a remediation - nothing today needs a longer prose field.
    #
    # DO NOTHING on the primary key only, never a bare OR IGNORE: `id` is content-derived over
    # the rule, the location and every evidence step's file, line and snippet, so two findings
    # sharing an id within one scan are a genuine duplicate and the dropped row loses nothing
    # that a reader could act on. rules.py does not dedupe before this point, and letting the
    # collision raise IntegrityError would roll back every other finding in the scan for the
    # sake of one that adds no information. OR IGNORE would also swallow a NOT NULL or foreign
    # key violation, which is a real defect losing a real finding and must still be loud.
    # The evidence-path insert below is scoped the same way.
    conn.execute(
        "INSERT INTO findings "
        "(id, project_id, scan_id, rule_id, fingerprint, severity, confidence, title, "
        "remediation, file_id, start_line, start_col, end_line, end_col, cwe, first_seen_scan) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT (scan_id, id) DO NOTHING",
        (
            finding.id,
            project_id,
            scan_id,
            finding.rule_id,
            fingerprint,
            finding.severity,
            1.0,
            finding.title,
            finding.remediation,
            file_ids.get(finding.span.file),
            finding.span.start_line,
            finding.span.start_col,
            finding.span.end_line,
            finding.span.end_col,
            json.dumps(list(finding.cwe)),
            first_seen_scan,
        ),
    )

    for step_index, step in enumerate(finding.evidence_path):
        conn.execute(
            "INSERT INTO evidence_paths "
            "(scan_id, finding_id, step, file_id, line, role, snippet, note, is_primary) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1) "
            "ON CONFLICT (scan_id, finding_id, step, is_primary) DO NOTHING",
            (
                scan_id,
                finding.id,
                step_index,
                file_ids.get(step.span.file),
                step.span.start_line,
                step.role,
                step.snippet,
                step.note,
            ),
        )


def _first_seen_scan(
    conn: sqlite3.Connection, project_id: int, fingerprint: str, scan_id: int
) -> int:
    """The earliest scan that ever recorded this fingerprint, or this scan if none did.

    Looked up by fingerprint, not `id`: fingerprint is what survives a reformat, and keying
    this on `id` instead is exactly the bug that would resurrect a suppressed backlog on every
    line shift (docs/plans/2026-07-27-slice-6-store-design.md).
    """
    row = conn.execute(
        "SELECT MIN(first_seen_scan) FROM findings WHERE project_id = ? AND fingerprint = ?",
        (project_id, fingerprint),
    ).fetchone()
    return int(row[0]) if row and row[0] is not None else scan_id
