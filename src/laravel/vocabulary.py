"""Laravel and PHP taint vocabulary.

The canonical reference is docs/06-taint-analysis.
This module carries the subset needed for the sql and html taint kinds.
"""

from ..models import ALL_KINDS, TaintKind

# Values whose keys the developer chose rather than the attacker. Still fully
# dangerous to print or interpolate - a validated string is still XSS - but
# safe to hand to an Eloquent array write, because a column the developer did
# not name cannot appear in them.
_KEYS_CHOSEN_BY_DEVELOPER: frozenset[TaintKind] = ALL_KINDS - {TaintKind.MASS_ASSIGN}

# Illuminate\Http\Request methods returning attacker-controlled data, mapped to
# the kinds the returned value carries.
#
# except() is deliberately in the dangerous group: it is a blacklist, so it
# does not protect the privileged column somebody adds to the table next month.
# only() is an allowlist and does.
SOURCE_METHODS: dict[str, frozenset[TaintKind]] = {
    name: ALL_KINDS
    for name in (
        "input",
        "get",
        "query",
        "post",
        "json",
        "all",
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
    )
} | {
    # docs/06-taint-analysis: "Validated input is still tainted, with reduced
    # kinds." Before this they were not sources at all, so
    # `{!! $request->validated()['bio'] !!}` was a false negative.
    name: _KEYS_CHOSEN_BY_DEVELOPER
    for name in ("only", "validated", "safe")
}

# Rule identities live here rather than in rules.py because the taint walk has
# to name the rule it matched and rules.py imports the walk, not the other way
# round. They are plain strings, so the graph layer never learns what a Rule
# is - it only passes an opaque label the security engine interprets.
#
# Permanent per invariant 7: these ship in users' baselines and vigilloo-ignore
# comments.
SQL_INJECTION_RULE = "php.sql-injection"
XSS_RULE = "php.xss"
# laravel. rather than php.: the rule is meaningless outside Eloquent. Spelled
# as docs/08-framework-adapters and docs/13-security-engine spell it, rather
# than invented to match the php. prefixes above, because invariant 7 makes it
# permanent the moment it ships.
MASS_ASSIGNMENT_RULE = "laravel.mass-assignment"
MISSING_AUTHORIZATION_RULE = "laravel.missing-authorization"

# Eloquent array writes -> (index of the mass-assigned argument, bypasses
# protection).
#
# updateOrCreate's argument 0 is the lookup, not the write. Flagging it would
# report the safe half of the call, which is the same mistake as flagging
# whereRaw's binding array.
#
# The force* pair bypasses both $fillable and $guarded - that is what "force"
# means in Eloquent - so they fire on any model, however well configured.
ELOQUENT_WRITES: dict[str, tuple[int, bool]] = {
    "create": (0, False),
    "make": (0, False),
    "firstOrNew": (0, False),
    "firstOrCreate": (0, False),
    "updateOrCreate": (1, False),
    "forceCreate": (0, True),
    "update": (0, False),
    "fill": (0, False),
    "forceFill": (0, True),
}


def eloquent_write(method: str) -> tuple[int, bool] | None:
    return ELOQUENT_WRITES.get(method)


# Sink method name -> (index of the argument that reaches the parser, kind
# required, rule that fires).
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
SINKS: dict[str, tuple[int, TaintKind, str]] = {
    "orderByRaw": (0, TaintKind.SQL, SQL_INJECTION_RULE),
    "whereRaw": (0, TaintKind.SQL, SQL_INJECTION_RULE),
    "orWhereRaw": (0, TaintKind.SQL, SQL_INJECTION_RULE),
    "havingRaw": (0, TaintKind.SQL, SQL_INJECTION_RULE),
    "groupByRaw": (0, TaintKind.SQL, SQL_INJECTION_RULE),
    "selectRaw": (0, TaintKind.SQL, SQL_INJECTION_RULE),
    "fromRaw": (0, TaintKind.SQL, SQL_INJECTION_RULE),
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


def source_kinds(method: str) -> frozenset[TaintKind]:
    """The kinds a value entering through this Request method carries."""
    return SOURCE_METHODS.get(method, frozenset())


def sink(method: str) -> tuple[int, TaintKind, str] | None:
    return SINKS.get(method)


def sanitizer_clears(name: str) -> frozenset[TaintKind]:
    return SANITIZERS.get(name, frozenset())
