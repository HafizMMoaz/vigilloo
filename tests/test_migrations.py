"""Migrating an existing workspace, which is the only way a findings history survives an upgrade.

The v1 schema below is copied out of the commit that shipped it, not generated from anything in
`src/`. That is the point: a migration test that builds its "old" database from today's code
tests nothing, because today's code already produces today's schema.
"""

import shutil
import sqlite3
from pathlib import Path

import pytest
from typer.testing import CliRunner

from vigilloo.cli import app
from vigilloo.store import connect, findings_for_scan, latest_scan, project_id_for
from vigilloo.workspace import Workspace
from vigilloo.workspace.migrations import (
    SCHEMA_VERSION,
    SchemaCorruptError,
    SchemaTooNewError,
    migrate,
)

runner = CliRunner()
FIXTURE = Path("tests/fixtures/laravel-minimal")

# Schema version 1 verbatim, as commit 52b7e06 created it: no `nodes`, no `edges`, no
# `idx_scans_project`, and `evidence_paths.node_id` a bare TEXT column with nothing to point at.
_V1_SCHEMA = """
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
CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
INSERT INTO schema_meta (key, value) VALUES ('version', '1');
COMMIT;
"""

_FINDING_ID = "f00dcafe"
_FINGERPRINT = "beefbeef"
_REL_PATH = "app/Http/Controllers/OrderController.php"


def _v1_database(workspace: Workspace, *, version: str = "1") -> Path:
    """A hand-built version 1 database holding one project, one scan and one finding.

    `version` is a parameter so the same fixture can claim to be a version it is not, which is
    how the refusal cases below get a database from the future without a build from the future.
    """
    path = workspace.dir / "vigilloo.db"
    conn = sqlite3.connect(path)
    conn.executescript(_V1_SCHEMA)
    with conn:
        conn.execute(
            "INSERT INTO projects (id, root_path, language, framework, created_at) "
            "VALUES (1, ?, 'php', 'laravel', '2026-01-01T00:00:00+00:00')",
            (str(workspace.root),),
        )
        conn.execute(
            "INSERT INTO scans (id, project_id, started_at, finished_at, status, "
            "engine_version, ruleset_hash, files_total, files_parsed, files_failed, duration_ms) "
            "VALUES (7, 1, '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:01+00:00', "
            "'completed', '0.0.1', 'rs1', 1, 1, 0, 1000)"
        )
        conn.execute(
            "INSERT INTO files (id, project_id, path, sha256, language, parse_state) "
            "VALUES (3, 1, ?, 'deadbeef', 'php', 'ok')",
            (_REL_PATH,),
        )
        conn.execute(
            "INSERT INTO findings (id, project_id, scan_id, rule_id, fingerprint, severity, "
            "confidence, title, remediation, file_id, start_line, start_col, end_line, end_col, "
            "cwe, first_seen_scan) "
            "VALUES (?, 1, 7, 'php.sql-injection', ?, 'critical', 1.0, 'SQL Injection', "
            "'Bind the parameter', 3, 12, 0, 12, 10, '[\"CWE-89\"]', 7)",
            (_FINDING_ID, _FINGERPRINT),
        )
        for step, (role, line, snippet) in enumerate(
            [("source", 5, "$request->input('q')"), ("sink", 12, "DB::raw($q)")]
        ):
            conn.execute(
                "INSERT INTO evidence_paths "
                "(scan_id, finding_id, step, node_id, file_id, line, role, snippet, note, "
                "is_primary) VALUES (7, ?, ?, NULL, 3, ?, ?, ?, '', 1)",
                (_FINDING_ID, step, line, role, snippet),
            )
        conn.execute("UPDATE schema_meta SET value = ? WHERE key = 'version'", (version,))
    conn.close()
    return path


def _schema_shape(conn: sqlite3.Connection) -> dict[str, object]:
    """Tables, their columns, their foreign keys and their indexes, as SQLite reports them.

    Compared instead of the `CREATE TABLE` text in `sqlite_master` because a table rebuilt and
    renamed carries a quoted name and the original whitespace of whichever definition produced
    it. Neither is a difference anything can observe; a missing column, a missing foreign key or
    a missing index all are.
    """
    shape: dict[str, object] = {}
    tables = sorted(
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
        )
    )
    for table in tables:
        shape[f"{table}.columns"] = [
            tuple(row) for row in conn.execute(f"PRAGMA table_info({table})")
        ]
        shape[f"{table}.foreign_keys"] = sorted(
            # Column 0 is the constraint's ordinal, which counts down from however many the
            # table has and so differs between a rebuilt table and a freshly created one
            # without any of the references differing. Everything after it is the reference.
            tuple(row[1:])
            for row in conn.execute(f"PRAGMA foreign_key_list({table})")
        )
        shape[f"{table}.indexes"] = sorted(
            (row[1], row[2], tuple(c[2] for c in conn.execute(f"PRAGMA index_info({row[1]})")))
            for row in conn.execute(f"PRAGMA index_list({table})")
        )
    return shape


def test_a_version_1_database_migrates_and_keeps_its_findings(tmp_path: Path) -> None:
    """The upgrade promise: the graph may be re-derived, the findings history may not."""
    workspace = Workspace.open(tmp_path)
    _v1_database(workspace)

    conn = connect(workspace)

    version = conn.execute("SELECT value FROM schema_meta WHERE key = 'version'").fetchone()[0]
    assert version == str(SCHEMA_VERSION)

    # Read back through the store's own reader rather than by hand: a migration that preserved
    # rows but broke the query that reads them has still lost the history in every way a user
    # can tell. This is the exact path `vigilloo report` takes.
    project_id = project_id_for(conn, tmp_path.resolve())
    assert project_id == 1
    scan_id = latest_scan(conn, project_id)
    assert scan_id == 7

    stored = findings_for_scan(conn, scan_id)
    assert len(stored) == 1
    assert stored[0].id == _FINDING_ID
    assert stored[0].fingerprint == _FINGERPRINT
    assert stored[0].rule_id == "php.sql-injection"
    assert stored[0].first_seen_scan == 7
    assert stored[0].file == Path(_REL_PATH)
    assert stored[0].cwe == ("CWE-89",)
    assert [step.role for step in stored[0].path] == ["source", "sink"]
    assert [step.line for step in stored[0].path] == [5, 12]
    assert stored[0].path[1].snippet == "DB::raw($q)"


def test_the_graph_tables_arrive_empty_and_ready_to_be_re_derived(tmp_path: Path) -> None:
    """docs/17-database: the graph is a rebuildable cache, so a migration need not carry one."""
    workspace = Workspace.open(tmp_path)
    _v1_database(workspace)

    conn = connect(workspace)

    assert conn.execute("SELECT count(*) FROM nodes").fetchone()[0] == 0
    assert conn.execute("SELECT count(*) FROM edges").fetchone()[0] == 0
    # The evidence path that survived points at no node, and that is the honest answer: a v1
    # database recorded lines, not traversals, so there is no node for it to have pointed at.
    assert all(step.node_id is None for step in findings_for_scan(conn, 7)[0].path)


def test_a_migrated_database_has_the_same_schema_as_a_fresh_one(tmp_path: Path) -> None:
    """Otherwise `version 3` names two different schemas and the version number means nothing."""
    old_root = tmp_path / "old"
    new_root = tmp_path / "new"
    old_root.mkdir()
    new_root.mkdir()

    old = Workspace.open(old_root)
    _v1_database(old)
    migrated = connect(old)

    fresh = connect(Workspace.open(new_root))

    assert _schema_shape(migrated) == _schema_shape(fresh)


def test_migrating_is_idempotent(tmp_path: Path) -> None:
    """`connect` runs the runner on every open, so the second open must be a no-op."""
    workspace = Workspace.open(tmp_path)
    _v1_database(workspace)

    first = connect(workspace)
    shape = _schema_shape(first)
    first.close()

    second = connect(workspace)

    assert _schema_shape(second) == shape
    assert second.execute("SELECT count(*) FROM findings").fetchone()[0] == 1
    assert second.execute("SELECT count(*) FROM evidence_paths").fetchone()[0] == 2
    assert second.execute("SELECT value FROM schema_meta WHERE key = 'version'").fetchone()[
        0
    ] == str(SCHEMA_VERSION)


def test_a_database_already_at_the_current_version_is_left_alone(tmp_path: Path) -> None:
    conn = connect(Workspace.open(tmp_path))

    assert migrate(conn, str(SCHEMA_VERSION)) == SCHEMA_VERSION


def test_a_partly_migrated_database_resumes_from_where_it_stopped(tmp_path: Path) -> None:
    """Each step commits its own version bump, so an interrupted run leaves a real version."""
    workspace = Workspace.open(tmp_path)
    _v1_database(workspace)

    # Version 2 is what the first step leaves behind, so this stands in for a run that died
    # between the two. Only the second step should run, and its index is what proves it did.
    conn = sqlite3.connect(workspace.dir / "vigilloo.db")
    conn.executescript(
        "BEGIN;\n"
        "CREATE TABLE nodes (id TEXT PRIMARY KEY);\n"
        "UPDATE schema_meta SET value = '2' WHERE key = 'version';\n"
        "COMMIT;"
    )
    conn.close()

    conn = connect(workspace)

    indexes = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='index'")}
    assert "idx_scans_project" in indexes
    # The first step did not run again: its own `CREATE TABLE nodes` would have raised on the
    # stub above rather than quietly replacing it.
    assert [row[1] for row in conn.execute("PRAGMA table_info(nodes)")] == ["id"]


def test_a_database_from_a_newer_build_is_refused(tmp_path: Path) -> None:
    """Forward-only: there is no down-migration, and guessing at a newer layout misreads columns."""
    workspace = Workspace.open(tmp_path)
    _v1_database(workspace, version=str(SCHEMA_VERSION + 1))

    with pytest.raises(SchemaTooNewError) as excinfo:
        connect(workspace)

    assert excinfo.value.found == SCHEMA_VERSION + 1
    assert excinfo.value.expected == SCHEMA_VERSION


def test_the_refusal_leaves_the_database_untouched(tmp_path: Path) -> None:
    """A build that cannot understand the file must not write to it either."""
    workspace = Workspace.open(tmp_path)
    _v1_database(workspace, version="99")

    with pytest.raises(SchemaTooNewError):
        connect(workspace)

    conn = sqlite3.connect(workspace.dir / "vigilloo.db")
    assert conn.execute("SELECT value FROM schema_meta WHERE key = 'version'").fetchone()[0] == "99"
    assert conn.execute("SELECT count(*) FROM findings").fetchone()[0] == 1
    tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert "nodes" not in tables


@pytest.mark.parametrize("version", ["", "beta", "0", "-1"])
def test_a_version_that_is_not_a_version_is_refused_as_corrupt(
    tmp_path: Path, version: str
) -> None:
    """Upgrading would not fix this one, so it is not a SchemaTooNewError."""
    workspace = Workspace.open(tmp_path)
    _v1_database(workspace, version=version)

    with pytest.raises(SchemaCorruptError):
        connect(workspace)


def test_scanning_a_workspace_from_a_newer_build_exits_4(tmp_path: Path) -> None:
    """docs/19-cli gives 4 to a configuration error; this is the tool being the wrong version."""
    root = tmp_path / "project"
    shutil.copytree(FIXTURE, root, ignore=shutil.ignore_patterns(".vigilloo"))
    _v1_database(Workspace.open(root), version=str(SCHEMA_VERSION + 1))

    result = runner.invoke(app, ["scan", str(root)])

    # 4 and not 1: the scan found ten real findings and printed them, and the exit code still
    # says the workspace could not be used, because every future run will fail the same way.
    assert result.exit_code == 4


def test_a_transient_store_failure_still_only_warns(tmp_path: Path) -> None:
    """The exit-4 path must not have widened into "any store error fails the scan"."""
    root = tmp_path / "project"
    shutil.copytree(FIXTURE, root, ignore=shutil.ignore_patterns(".vigilloo"))
    workspace = Workspace.open(root)
    # A file that is not a database at all: `connect` raises sqlite3.DatabaseError, which is
    # this run's bad luck rather than the wrong build, so the findings' exit code stands.
    (workspace.dir / "vigilloo.db").write_bytes(b"not a database")

    result = runner.invoke(app, ["scan", str(root)])

    assert result.exit_code == 1
    assert "Scan history not recorded" in result.stdout
