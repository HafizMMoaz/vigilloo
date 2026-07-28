"""The SQLite store: `.vigilloo/vigilloo.db`, the graph tables, and one row per scan
and per finding.

Writing is `record_scan`, which puts one scan, its files, its graph and its findings down in a
single transaction. Reading is `project_id_for` -> `latest_scan` -> `findings_for_scan`, the
path `vigilloo report` and `vigilloo explain` take, plus `findings_by_fingerprint` for the
history of one finding across scans.

Knows nothing about rules or taint - `engine_version` and `ruleset_hash` arrive as parameters
and are never computed here, so the store stays below the security engine in the layering
CLAUDE.md describes. It does know about the graph, because it is the graph's storage: it takes
a `Project` and asks `vigilloo.graph` to flatten it, rather than learning how to do that here.
"""

import json
import sqlite3
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .graph import GraphRows, NodeLocator, Project, graph_rows
from .models import EdgeRow, Finding, NodeRow
from .workspace import Workspace

_DB_FILENAME = "vigilloo.db"
_SCHEMA_VERSION = 3

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
-- "the latest scan of this project" is what `report` and `explain` start from, and without
-- this it reads every scan row of every project in the file to answer it.
CREATE INDEX idx_scans_project ON scans(project_id, id);

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

CREATE TABLE nodes (
    id          TEXT PRIMARY KEY,
    project_id  INTEGER NOT NULL REFERENCES projects(id),
    kind        TEXT NOT NULL,
    name        TEXT,
    fqn         TEXT,
    file_id     INTEGER REFERENCES files(id),
    start_line  INTEGER, start_col INTEGER,
    end_line    INTEGER, end_col   INTEGER,
    start_byte  INTEGER, end_byte  INTEGER,
    attrs       TEXT
);
CREATE INDEX idx_nodes_kind  ON nodes(project_id, kind);
CREATE INDEX idx_nodes_fqn   ON nodes(project_id, fqn);
CREATE INDEX idx_nodes_file  ON nodes(file_id);

CREATE TABLE edges (
    id         INTEGER PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id),
    src_id     TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    dst_id     TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL,
    confidence REAL NOT NULL DEFAULT 1.0,
    resolution TEXT,
    attrs      TEXT
);
CREATE INDEX idx_edges_src ON edges(src_id, kind);
CREATE INDEX idx_edges_dst ON edges(dst_id, kind);

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
    node_id    TEXT REFERENCES nodes(id),
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


@dataclass(frozen=True)
class StoredStep:
    """One step of a stored evidence path.

    Deliberately not a `PathStep`. A `PathStep` carries a full `Span`, and docs/17-database
    stores a step's `line` and nothing narrower - a step is a point on a path, and its column
    offsets are presentation. Handing back a `PathStep` would mean inventing three numbers,
    and a caller could not tell the invented ones from the real one.
    """

    step: int
    role: str
    file: Path | None
    line: int | None
    snippet: str
    note: str
    node_id: str | None


@dataclass(frozen=True)
class StoredFinding:
    """A finding as the database holds it, with its complete evidence path.

    Everything `Finding.id` and `Finding.fingerprint` are derived from is here - the rule, the
    file, the start line, and each step's role, file, line and snippet - so a reader can
    recompute both and check them against the stored values. That is the round trip that
    matters: not that the object is byte-identical, but that its identity survived, because
    identity is what baselines and suppressions are keyed on.
    """

    id: str
    fingerprint: str
    scan_id: int
    rule_id: str
    severity: str
    title: str
    remediation: str
    cwe: tuple[str, ...]
    file: Path | None
    start_line: int | None
    first_seen_scan: int | None
    path: tuple[StoredStep, ...]


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
    if row is None:
        conn.executescript(_SCHEMA_SQL)
        return
    if row[0] != str(_SCHEMA_VERSION):
        # ponytail: one whole-schema create and no migration steps, so a database written by
        # another schema version is refused rather than upgraded. Ceiling: the developer loses
        # that project's findings history, which is the one thing under .vigilloo/ that cannot
        # be rebuilt. Acceptable only because nothing has been released yet. Upgrade trigger:
        # the first shipped version, after which docs/17-database "Migrations" applies - a
        # forward-only runner keyed on this cell, free to drop and re-derive the graph but not
        # findings or baselines. Failing loudly here is deliberate: the alternative is version 2
        # code opening a version 1 database and reporting "no such table: nodes" much later.
        raise RuntimeError(
            f"{_DB_FILENAME} was written by schema version {row[0]}, this build expects "
            f"{_SCHEMA_VERSION}, and no migration runner exists yet. Delete "
            f".vigilloo/{_DB_FILENAME} and re-scan; that project's findings history is lost."
        )


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

        # The graph is written before the findings, and both inside the scan's transaction:
        # evidence_paths.node_id references nodes(id), so a finding whose steps point at graph
        # nodes cannot be inserted until those nodes exist. Ordering it this way also means a
        # scan that dies partway leaves no graph rather than a graph with no scan to explain it.
        rows = graph_rows(project, project_id, file_ids)
        _replace_graph(conn, project_id, rows)

        locator = NodeLocator(rows)
        for finding in findings:
            _insert_finding(conn, project_id, scan_id, finding, file_ids, locator)

    # ponytail: no retention pruning. docs/17-database keeps the last 10 scans; ten scans of a
    # small findings set is kilobytes, so pruning arrives when a real project's history measures
    # large enough to justify it, not preemptively here.
    return scan_id


def _replace_graph(conn: sqlite3.Connection, project_id: int, rows: GraphRows) -> None:
    """Make the stored graph this project's graph, as this scan just derived it.

    Edges are dropped and rewritten because an edge has no identity of its own (see
    `insert_edges`): re-deriving the same call site would otherwise add a second row every
    scan, and a `CALLS` edge counted twice is a traversal that reports the same path twice.
    Nodes are not dropped, only re-inserted, and their content-derived ids make that a no-op
    for everything unchanged.

    ponytail: a node for a class or file that has since been deleted is never removed, so the
    node table only ever grows. Ceiling: a stale node has no edges - those were just dropped -
    so it cannot appear in a traversal or a finding, and the cost is disk plus a `kind` count
    that overstates a long-lived project. Upgrade trigger: docs/04-knowledge-graph section
    "Invalidation", which needs per-file node deletion keyed on the content hash anyway; the
    same pass that drops a changed file's nodes drops a removed file's.
    """
    conn.execute("DELETE FROM edges WHERE project_id = ?", (project_id,))
    insert_nodes(conn, project_id, rows.nodes)
    insert_edges(conn, project_id, rows.edges)


def project_id_for(conn: sqlite3.Connection, root: Path) -> int | None:
    """The stored project for a root path, or None if it has never been scanned.

    Every other reader here takes a `project_id`, and a caller holding a directory has no
    other way to get one. None rather than a raise: "this project has no history" is the
    ordinary state of a first run, not an error.
    """
    row = conn.execute("SELECT id FROM projects WHERE root_path = ?", (str(root),)).fetchone()
    return int(row[0]) if row else None


def latest_scan(conn: sqlite3.Connection, project_id: int) -> int | None:
    """The most recent scan of a project, or None if it has none.

    Keyed on `id` rather than on `started_at`. `id` is assigned by the insert, so it orders
    scans by when they were actually recorded; `started_at` is derived by subtracting the
    measured duration from the finish time, so a long scan can carry an earlier start than a
    short one that ran after it and "latest" would then mean the wrong row.
    """
    row = conn.execute(
        "SELECT id FROM scans WHERE project_id = ? ORDER BY id DESC LIMIT 1", (project_id,)
    ).fetchone()
    return int(row[0]) if row else None


def findings_for_scan(conn: sqlite3.Connection, scan_id: int) -> list[StoredFinding]:
    """Every finding one scan recorded, each with its complete evidence path."""
    return _load_findings(conn, "fi.scan_id = ?", (scan_id,))


def findings_by_fingerprint(
    conn: sqlite3.Connection, project_id: int, fingerprint: str
) -> list[StoredFinding]:
    """Every scan's view of one finding, oldest scan first.

    Fingerprint and not `id`, because this answers "is this the same problem I saw before"
    across code that has moved. `id` changes the moment a line shifts; the fingerprint is what
    a baseline and a `// vigilloo-ignore` are written against, and matching on the wrong one
    is exactly the bug that resurrects a suppressed backlog after a reformat.
    """
    return _load_findings(
        conn, "fi.project_id = ? AND fi.fingerprint = ?", (project_id, fingerprint)
    )


def _load_findings(
    conn: sqlite3.Connection, where: str, params: tuple[object, ...]
) -> list[StoredFinding]:
    """Findings matching `where`, each with its path, in two queries rather than one per row.

    docs/23-dev-guide section Performance names N+1 against SQLite as what dominates, and a
    scan with 500 findings would otherwise be 501 round trips to rebuild what one pass over
    `evidence_paths` already returns in order. The steps query reuses the same predicate
    through a subquery, so a caller cannot ask for findings and paths that disagree.

    Ordered by scan and then by source position, never by severity. Ranking findings is the
    reporter's decision and it changes; where a finding is does not, and a stable order is
    what makes two reads of the same rows comparable (invariant 8).

    `where` is interpolated into the SQL and its values are not. It is private to this module
    and every call site passes a literal - it is a fragment of a query, not data - while
    everything that varies goes through `params` as a bound parameter. A scanner that built
    its own queries by concatenating values would be an unusually poor advertisement.
    """
    steps: dict[tuple[int, str], list[StoredStep]] = {}
    for row in conn.execute(
        "SELECT e.scan_id, e.finding_id, e.step, e.role, f.path, e.line, e.snippet, e.note, "
        "e.node_id "
        "FROM evidence_paths e LEFT JOIN files f ON f.id = e.file_id "
        "WHERE e.is_primary = 1 AND (e.scan_id, e.finding_id) IN "
        f"(SELECT fi.scan_id, fi.id FROM findings fi WHERE {where}) "
        "ORDER BY e.scan_id, e.finding_id, e.step",
        params,
    ):
        steps.setdefault((row[0], row[1]), []).append(
            StoredStep(
                step=row[2],
                role=row[3],
                file=None if row[4] is None else Path(row[4]),
                line=row[5],
                snippet=row[6] or "",
                note=row[7] or "",
                node_id=row[8],
            )
        )

    findings: list[StoredFinding] = []
    for row in conn.execute(
        "SELECT fi.id, fi.fingerprint, fi.scan_id, fi.rule_id, fi.severity, fi.title, "
        "fi.remediation, fi.cwe, f.path, fi.start_line, fi.first_seen_scan "
        "FROM findings fi LEFT JOIN files f ON f.id = fi.file_id "
        f"WHERE {where} "
        "ORDER BY fi.scan_id, f.path, fi.start_line, fi.id",
        params,
    ):
        path = steps.get((row[2], row[0]), [])
        if not path:
            # Invariant 2: no path, no finding. Returning one anyway would hand a caller
            # something the engine is not allowed to produce, and the caller would have no way
            # to tell it from a finding whose path was genuinely empty - which cannot happen,
            # because Finding.__post_init__ refuses to construct one.
            raise ValueError(
                f"finding {row[0]} in scan {row[2]} has no stored evidence path; "
                f"{_DB_FILENAME} is corrupt"
            )
        findings.append(
            StoredFinding(
                id=row[0],
                fingerprint=row[1],
                scan_id=row[2],
                rule_id=row[3],
                severity=row[4],
                title=row[5],
                remediation=row[6] or "",
                cwe=tuple(json.loads(row[7])) if row[7] else (),
                file=None if row[8] is None else Path(row[8]),
                start_line=row[9],
                first_seen_scan=row[10],
                path=tuple(path),
            )
        )
    return findings


def insert_nodes(conn: sqlite3.Connection, project_id: int, nodes: Iterable[NodeRow]) -> None:
    """Write a batch of nodes with one `executemany`.

    docs/23-dev-guide section Performance: N+1 queries against SQLite dominate graph
    construction, so a graph write is one statement over the whole batch, never one statement
    per node.

    No transaction is opened here. The batch is atomic either way - the driver begins one
    before the first insert and holds it - and leaving the commit to the caller is what lets a
    graph write join the single transaction `record_scan` already owns, rather than committing
    a half-written scan behind its back. Callers that write nothing else wrap the call in
    `with conn:`.

    A node whose id is already present is left alone. The id is content-derived, so a repeat
    is the same node re-derived, not a collision, and re-scanning a file that did not change
    must not fail. `ON CONFLICT (id)` and not `OR IGNORE`, for the reason `_insert_finding`
    gives: `OR IGNORE` would also swallow a NOT NULL or foreign key violation, which is a real
    defect losing a real node.
    """
    conn.executemany(
        "INSERT INTO nodes "
        "(id, project_id, kind, name, fqn, file_id, start_line, start_col, end_line, end_col, "
        "start_byte, end_byte, attrs) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT (id) DO NOTHING",
        (
            (
                node.id,
                project_id,
                node.kind,
                node.name,
                node.fqn,
                node.file_id,
                node.start_line,
                node.start_col,
                node.end_line,
                node.end_col,
                node.start_byte,
                node.end_byte,
                _attrs_json(node.attrs),
            )
            for node in nodes
        ),
    )


def insert_edges(conn: sqlite3.Connection, project_id: int, edges: Iterable[EdgeRow]) -> None:
    """Write a batch of edges with one `executemany`. Transactions as in `insert_nodes`.

    ponytail: no idempotence. `edges.id` is an autoincrement rowid, per docs/17-database,
    because an edge has no identity of its own - it is (src, dst, kind) between two nodes that
    do. Ceiling: inserting the same logical edge twice writes two rows, so a caller must not
    re-derive edges that are already stored. `_replace_graph` is what keeps that true today, by
    dropping the project's edges before every rewrite - which only works because the graph is
    still derived whole per scan. Upgrade trigger: incremental scanning, which re-derives one
    file at a time and cannot drop the whole project's edges to do it; then this needs
    `UNIQUE (src_id, dst_id, kind)` with the same DO NOTHING, and docs/17-database gains it.
    """
    conn.executemany(
        "INSERT INTO edges (project_id, src_id, dst_id, kind, confidence, resolution, attrs) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            (
                project_id,
                edge.src_id,
                edge.dst_id,
                edge.kind,
                edge.confidence,
                edge.resolution,
                _attrs_json(edge.attrs),
            )
            for edge in edges
        ),
    )


def _attrs_json(attrs: Mapping[str, object] | None) -> str | None:
    """Serialise a kind-specific attribute bag, keys sorted.

    Sorted because invariant 8 is byte-identical output for the same input, and a report or
    an export that reads this column back would otherwise inherit dictionary insertion order.
    """
    return None if attrs is None else json.dumps(attrs, sort_keys=True)


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
    locator: NodeLocator,
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

    # node_id is what makes a stored step a position in the graph rather than a line number:
    # invariant 2 wants a path whose every step is a real node, and a reader holding one can
    # ask what else reaches it. It stays nullable because a step can land somewhere no node
    # covers - a Blade template resolves only to its file node - and inventing one there would
    # be worse than admitting the gap.
    for step_index, step in enumerate(finding.evidence_path):
        conn.execute(
            "INSERT INTO evidence_paths "
            "(scan_id, finding_id, step, node_id, file_id, line, role, snippet, note, "
            "is_primary) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1) "
            "ON CONFLICT (scan_id, finding_id, step, is_primary) DO NOTHING",
            (
                scan_id,
                finding.id,
                step_index,
                locator.at(step.span.file, step.span.start_line),
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
