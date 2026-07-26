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
_SCHEMA_SQL = """
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
"""
# schema_meta itself is created separately, before this script runs, so its version row can be
# checked before deciding whether the rest of the schema needs creating at all.


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
    conn.execute(
        "INSERT INTO schema_meta (key, value) VALUES ('version', ?)", (str(_SCHEMA_VERSION),)
    )
    conn.commit()


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
            source=parsed.source,
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
            source=parsed.source,
            parsed_at=parsed_at,
            parse_state="partial" if parsed.has_errors else "ok",
        )
    return file_ids


def _upsert_file(
    conn: sqlite3.Connection,
    project_id: int,
    rel_path: Path,
    *,
    sha256: str,
    language: str,
    source: bytes,
    parsed_at: str,
    parse_state: str,
) -> int:
    # role: ponytail, left NULL. Classifying controller/model/middleware/blade/etc. is real
    # Laravel knowledge (docs/17-database) and does not belong in a storage slice.
    path = rel_path.as_posix()
    conn.execute(
        "INSERT INTO files "
        "(project_id, path, sha256, language, size_bytes, lines, parsed_at, parse_state) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT (project_id, path) DO UPDATE SET "
        "sha256 = excluded.sha256, language = excluded.language, "
        "size_bytes = excluded.size_bytes, lines = excluded.lines, "
        "parsed_at = excluded.parsed_at, parse_state = excluded.parse_state",
        (
            project_id,
            path,
            sha256,
            language,
            len(source),
            source.count(b"\n") + 1,
            parsed_at,
            parse_state,
        ),
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
    conn.execute(
        "INSERT INTO findings "
        "(id, project_id, scan_id, rule_id, fingerprint, severity, confidence, title, "
        "remediation, file_id, start_line, start_col, end_line, end_col, cwe, first_seen_scan) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)",
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
