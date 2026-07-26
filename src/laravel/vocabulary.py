"""Laravel and PHP taint vocabulary.

The canonical reference is docs/06-taint-analysis.
This module carries the subset needed for the sql and html taint kinds.
"""

from ..models import TaintKind

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

# Sink method name -> (index of the argument that reaches the parser, kind required).
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
SINKS: dict[str, tuple[int, TaintKind]] = {
    "orderByRaw": (0, TaintKind.SQL),
    "whereRaw": (0, TaintKind.SQL),
    "orWhereRaw": (0, TaintKind.SQL),
    "havingRaw": (0, TaintKind.SQL),
    "groupByRaw": (0, TaintKind.SQL),
    "selectRaw": (0, TaintKind.SQL),
    "fromRaw": (0, TaintKind.SQL),
}

# Function name -> the kinds calling it genuinely clears, per the sanitizer
# table in docs/06-taint-analysis.
#
# strip_tags, addslashes and mysql_real_escape_string are deliberately absent.
# The spec classes them as anti-sanitizers and findings in their own right;
# listing them here would turn a vulnerability into a clean result.
SANITIZERS: dict[str, frozenset[TaintKind]] = {
    "e": frozenset({TaintKind.HTML}),
    "htmlspecialchars": frozenset({TaintKind.HTML}),
    "htmlentities": frozenset({TaintKind.HTML}),
    "intval": frozenset({TaintKind.SQL, TaintKind.HTML}),
    "floatval": frozenset({TaintKind.SQL, TaintKind.HTML}),
}


def is_source(method: str) -> bool:
    return method in SOURCE_METHODS


def sink(method: str) -> tuple[int, TaintKind] | None:
    return SINKS.get(method)


def sanitizer_clears(name: str) -> frozenset[TaintKind]:
    return SANITIZERS.get(name, frozenset())
