"""Laravel and PHP taint vocabulary.

The canonical reference is docs/06-taint-analysis in the vigilloo/docs repo.
This module carries the subset needed for the SQL taint kind.
"""

# Illuminate\Http\Request methods returning attacker-controlled data.
SOURCE_METHODS: frozenset[str] = frozenset(
    {
        "input", "get", "query", "post", "json", "all", "only", "except",
        "string", "header", "cookie", "segment", "bearerToken", "userAgent",
        "url", "fullUrl", "ip",
    }
)

# Sink method name -> index of the argument that reaches the SQL parser.
# The *Raw builders accept bindings in argument 1, which are safe, so only
# argument 0 is dangerous.
SQL_SINKS: dict[str, int] = {
    "orderByRaw": 0,
    "whereRaw": 0,
    "orWhereRaw": 0,
    "havingRaw": 0,
    "groupByRaw": 0,
    "selectRaw": 0,
    "fromRaw": 0,
    "raw": 0,
    "statement": 0,
    "unprepared": 0,
    "select": 0,
}

SQL_SANITIZERS: frozenset[str] = frozenset({"intval", "e", "escapeshellarg"})


def is_source(method: str) -> bool:
    return method in SOURCE_METHODS


def sink_arg_index(method: str) -> int | None:
    return SQL_SINKS.get(method)
