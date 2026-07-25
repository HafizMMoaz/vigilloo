"""Laravel and PHP taint vocabulary.

The canonical reference is docs/06-taint-analysis.
This module carries the subset needed for the SQL taint kind.
"""

# Illuminate\Http\Request methods returning attacker-controlled data.
SOURCE_METHODS: frozenset[str] = frozenset(
    {
        "input",
        "get",
        "query",
        "post",
        "json",
        "all",
        "only",
        "except",
        "string",
        "header",
        "cookie",
        "segment",
        "bearerToken",
        "userAgent",
        "url",
        "fullUrl",
        "ip",
    }
)

# Sink method name -> index of the argument that reaches the SQL parser.
# The *Raw builders accept bindings in argument 1, which are safe, so only
# argument 0 is dangerous.
#
# ponytail: DB::raw/statement/unprepared/select are the genuinely dangerous
# static-facade forms, but they are scoped_call_expression nodes and the
# taint walk only iterates member_call_expression, so they are unreachable
# today. Listing them here would advertise coverage the engine doesn't have
# (and "select" also collides with the safe builder ->select(['col'])), so
# they are left out rather than left as false advertising. They come back
# together with scoped_call_expression / static-call handling.
SQL_SINKS: dict[str, int] = {
    "orderByRaw": 0,
    "whereRaw": 0,
    "orWhereRaw": 0,
    "havingRaw": 0,
    "groupByRaw": 0,
    "selectRaw": 0,
    "fromRaw": 0,
}


def is_source(method: str) -> bool:
    return method in SOURCE_METHODS


def sink_arg_index(method: str) -> int | None:
    return SQL_SINKS.get(method)
