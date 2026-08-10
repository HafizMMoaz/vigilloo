"""Forward-only schema migrations for `.vigilloo/vigilloo.db` (docs/17-database, "Migrations").

The database is a rebuildable cache with two things in it that are not: the findings history
and the baseline matching that reads it. That asymmetry is the whole design here. A migration
is free to drop `nodes` and `edges` and let the next scan re-derive them, because re-deriving
them costs one scan; it is not free to touch `findings` or `evidence_paths`, because nothing
can bring those back and a user who upgrades and silently loses their baseline has every
suppressed finding resurrected at once.

Forward-only, and a database written by a newer schema than this build knows is refused rather
than opened. There is no down-migration to fall back on, and an older build guessing at a newer
layout reads columns that mean something else - the failure would surface as a wrong finding,
much later, with nothing pointing back here. `SchemaTooNewError` is what it raises, and the CLI
turns that into exit code 4, "configuration error" in docs/19-cli: the workspace is fine, the
tool pointed at it is the wrong version.

The ladder below and `store._SCHEMA_SQL` are two descriptions of the same schema - one built up
step by step for an existing database, one created whole for a new one - and nothing in the code
forces them to agree. `tests/test_migrations.py` does, by migrating a fabricated old database
and comparing its tables, columns, foreign keys and indexes against a freshly created one. A
migration added without the matching change to `_SCHEMA_SQL` fails there.
"""

import sqlite3
from dataclasses import dataclass

# Every DDL statement a migration runs is written out here rather than derived from
# `store._SCHEMA_SQL`. A migration is a historical record of one step, and it has to keep
# describing the shape the schema had at that version even after the current schema moves on;
# generating it from today's definition would silently rewrite history and stop reproducing the
# upgrade a released build actually performed.


@dataclass(frozen=True)
class Migration:
    """One forward step, from `to_version - 1` to `to_version`.

    `sql` is a script, not a single statement, and it is run without its own `BEGIN`/`COMMIT`:
    the runner wraps it, so a process killed halfway leaves the database at the version it
    started from rather than at a version whose tables only partly exist.
    """

    to_version: int
    summary: str
    sql: str


_MIGRATIONS: tuple[Migration, ...] = (
    Migration(
        to_version=2,
        summary="add the graph tables and their five indexes",
        # The graph is derived, so this creates `nodes` and `edges` empty and lets the next scan
        # fill them - `record_scan` rewrites the whole project's graph every run anyway. There
        # is deliberately no attempt to reconstruct a graph from the findings already stored: a
        # v1 database recorded evidence paths as file-and-line positions with no node behind
        # them, and inventing nodes to point at would make an old path claim a graph traversal
        # it never made (invariant 2 wants every step to be a real edge, not a plausible one).
        #
        # `evidence_paths` is then rebuilt, and this is the one step that touches data that
        # cannot be regenerated. It is here because v1 declared `node_id TEXT` with no
        # reference - there was no `nodes` table for it to point at - and v2 declares
        # `node_id TEXT REFERENCES nodes(id)`. SQLite cannot add a foreign key to an existing
        # table, so the choice is a rebuild or a version 2 that means one thing on an upgraded
        # database and another on a fresh one. Two schemas behind one version number is the
        # failure a migration system exists to prevent, so: rebuild, copying every row across
        # by name. v1 never wrote a non-NULL `node_id` (nothing existed to reference), so no
        # copied row can violate the constraint it is gaining.
        sql="""
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

CREATE TABLE evidence_paths_v2 (
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
INSERT INTO evidence_paths_v2
    (id, scan_id, finding_id, step, node_id, file_id, line, role, snippet, note, is_primary)
SELECT id, scan_id, finding_id, step, node_id, file_id, line, role, snippet, note, is_primary
FROM evidence_paths;
DROP TABLE evidence_paths;
ALTER TABLE evidence_paths_v2 RENAME TO evidence_paths;
""",
    ),
    Migration(
        to_version=3,
        summary="index scans by project, so 'the latest scan' is not a full table scan",
        # Pure addition: an index is derived from rows that are already there, so this one
        # neither reads nor rewrites anything, and re-running it on a database that somehow
        # already has the index would be caught by CREATE INDEX rather than corrupt anything.
        sql="CREATE INDEX idx_scans_project ON scans(project_id, id);",
    ),
    Migration(
        to_version=4,
        summary="add the summary_cache table for interprocedural analysis memoization",
        sql="""
CREATE TABLE summary_cache (
    fqn TEXT NOT NULL,
    file_sha TEXT NOT NULL,
    summary BLOB NOT NULL,
    PRIMARY KEY (fqn, file_sha)
);
""",
    ),
)

# Derived, never written down twice. The top of the ladder is by definition the version this
# build understands, so adding a migration cannot leave the constant behind and produce a build
# that migrates a database to 4 and then refuses to open it for being newer than 3.
SCHEMA_VERSION: int = _MIGRATIONS[-1].to_version


class SchemaTooNewError(RuntimeError):
    """The database was written by a schema version this build does not know about.

    Its own error class rather than a bare `RuntimeError` because the CLI has to tell it apart
    from every other way opening the store can fail: a full disk or a locked file is a warning
    and the scan's exit code stands, while this is exit code 4 and the user needs to upgrade.
    Catching it by message text would work until someone rewords the message.
    """

    def __init__(self, found: int, expected: int) -> None:
        super().__init__(
            f"the workspace database was written by schema version {found}, and this build "
            f"understands version {expected}. Migrations are forward-only: a newer database "
            f"cannot be opened by an older build. Upgrade vigilloo, or delete .vigilloo/ and "
            f"re-scan - which loses that project's findings history."
        )
        self.found = found
        self.expected = expected


class SchemaCorruptError(RuntimeError):
    """`schema_meta` holds a version this build cannot make sense of.

    Separate from `SchemaTooNewError` because upgrading will not fix it. A version row that is
    not a positive integer means the file was written by something that is not this store, and
    guessing which of the two it resembles would be worse than saying so.
    """


def migrate(conn: sqlite3.Connection, stored_version: str) -> int:
    """Bring an existing database up to `SCHEMA_VERSION`. Returns the version it now holds.

    Idempotent, which is not a nicety: `connect` runs this on every open, so the ordinary case
    is a database already at the current version and the ordinary cost has to be one SELECT the
    caller already did plus this comparison.

    Each step is its own transaction, committed before the next begins, and each commits its
    `schema_meta` bump together with its own DDL. A run interrupted between steps therefore
    leaves a database at a real intermediate version that the next open resumes from, rather
    than at a version whose tables are half built. The alternative - one transaction over the
    whole ladder - sounds safer and is not: SQLite would hold the write lock across every step,
    and a ladder that grows to a dozen steps over a large history would do all of it or none of
    it with no way to make progress on a database that trips over one bad step.
    """
    found = _parse_version(stored_version)
    if found > SCHEMA_VERSION:
        raise SchemaTooNewError(found, SCHEMA_VERSION)

    pending = [migration for migration in _MIGRATIONS if migration.to_version > found]
    if not pending:
        return found

    # Foreign keys go off for the duration, per SQLite's own documented procedure for altering
    # a table by rebuilding it: with them on, `DROP TABLE` and `RENAME TO` run their fixups
    # against constraints that are momentarily inconsistent by construction. `foreign_key_check`
    # below is what replaces the per-statement enforcement, and it is stronger - it validates
    # every row in the file rather than only the ones a statement happened to touch.
    #
    # The commit first is load-bearing: `PRAGMA foreign_keys` is silently a no-op inside a
    # transaction, so a pending one here would leave the pragma set to whatever it already was
    # and the failure would show up as an unexplained constraint error mid-rebuild.
    conn.commit()
    conn.execute("PRAGMA foreign_keys = OFF")
    try:
        for migration in pending:
            # BEGIN/COMMIT are inside the script on purpose. `executescript` commits any pending
            # transaction before it starts and adds no transaction control of its own, so a
            # `with conn:` around it would commit at the wrong moment and leave the DDL running
            # outside the transaction it was supposed to be protected by.
            conn.executescript(
                "BEGIN;\n"
                f"{migration.sql}\n"
                f"UPDATE schema_meta SET value = '{migration.to_version}' "
                "WHERE key = 'version';\n"
                "COMMIT;"
            )
    finally:
        conn.execute("PRAGMA foreign_keys = ON")

    violations = conn.execute("PRAGMA foreign_key_check").fetchall()
    if violations:
        # Loud, and after the commits rather than instead of them: the rows are already written,
        # so pretending otherwise would only mean the next open finds the same state with no
        # explanation. A migration that breaks a reference is a defect in the ladder above, and
        # the one thing that must not happen is a scan continuing on top of it.
        raise SchemaCorruptError(
            f"migrating to schema version {SCHEMA_VERSION} left {len(violations)} broken "
            f"foreign key reference(s); the first is in table {violations[0][0]!r}"
        )
    return SCHEMA_VERSION


def _parse_version(stored_version: str) -> int:
    try:
        found = int(stored_version)
    except ValueError as exc:
        raise SchemaCorruptError(
            f"schema_meta holds version {stored_version!r}, which is not a version number"
        ) from exc
    if found < 1:
        raise SchemaCorruptError(
            f"schema_meta holds version {found}, and schema versions start at 1"
        )
    return found
