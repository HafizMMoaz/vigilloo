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
SINKS: dict[str, tuple[int, TaintKind, str]] = {
    "orderByRaw": (0, TaintKind.SQL, SQL_INJECTION_RULE),
    "whereRaw": (0, TaintKind.SQL, SQL_INJECTION_RULE),
    "orWhereRaw": (0, TaintKind.SQL, SQL_INJECTION_RULE),
    "havingRaw": (0, TaintKind.SQL, SQL_INJECTION_RULE),
    "groupByRaw": (0, TaintKind.SQL, SQL_INJECTION_RULE),
    "selectRaw": (0, TaintKind.SQL, SQL_INJECTION_RULE),
    "fromRaw": (0, TaintKind.SQL, SQL_INJECTION_RULE),
}

# The DB facade, by every name a project can legitimately call it.
#
# Matching the resolved FQN rather than the written text is what makes the
# `select` entry below safe to add at all. `use App\Reporting\DB;` is a
# perfectly ordinary import of somebody's own class, and a scanner keying on
# the two letters "DB" would report every call to it.
#
# Two names, because both reach Laravel's facade. The FQN is the imported
# form. The bare `DB` is what `\DB::raw(...)` resolves to, and what a file
# with no namespace resolves to - Laravel registers a global class alias, so
# that form is not a mistake, it is the older of the two idioms and it is
# still in every upgrade-in-progress codebase.
DB_FACADE_FQNS = frozenset(
    {
        "Illuminate\\Support\\Facades\\DB",
        "DB",
    }
)

# (receiver class, method) -> sink, for calls whose danger depends on what
# they were called on. Keyed separately from SINKS rather than merged into it,
# because the collision is the entire difficulty here:
#
#   DB::select("select * from users where id = $id")   injection
#   $query->select(['id', 'name'])                     a column list
#
# One name, two meanings, and only the receiver tells them apart. A name-keyed
# table cannot express that, and adding "select" to it would fire on the
# single most common line in any query builder in any Laravel codebase.
#
# Every entry is argument 0. `DB::select($sql, $bindings)` and friends take
# their bindings in argument 1, exactly like the *Raw builders, so a
# parameterised call is safe and a call whose *query* is built from user data
# is not, whether or not bindings are also passed.
STATIC_SINKS: dict[tuple[str, str], tuple[int, TaintKind, str]] = {
    (facade, method): (0, TaintKind.SQL, SQL_INJECTION_RULE)
    for facade in DB_FACADE_FQNS
    for method in (
        "raw",
        "statement",
        "unprepared",
        "select",
        "insert",
        "update",
        "delete",
    )
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


def static_sink(receiver_fqn: str | None, method: str) -> tuple[int, TaintKind, str] | None:
    """The sink a `Receiver::method(...)` call reaches, if any.

    `receiver_fqn` is the resolved class, not the text at the call site, and None when the
    scope could not be resolved. None is not a near miss to be guessed at: an unresolved
    receiver named `DB` is as likely to be someone's own reporting helper as it is to be the
    facade, and firing on it would put a fabricated SQL injection in front of a developer
    who then has grounds to distrust the whole report.
    """
    if receiver_fqn is None:
        return None
    return STATIC_SINKS.get((receiver_fqn, method))


def sanitizer_clears(name: str) -> frozenset[TaintKind]:
    return SANITIZERS.get(name, frozenset())
