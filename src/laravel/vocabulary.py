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

# The kinds a magic property read on a Request carries - `$request->bio`, which
# docs/06-taint-analysis lists in the same source table as `input()` and calls
# "commonly missed". Laravel's Request implements __get(), so the property form and
# `$request->input('bio')` are the same lookup written two ways, and there is no
# argument for giving them different kinds.
#
# No property name is excluded, and the name is not inspected at all. __get() forwards
# to the route parameters and then the input bag, so every name a developer can write
# resolves to request data; an allowlist would have to decide which halves of one
# mechanism to believe. Symfony's real public bags - `$request->query`, `->headers`,
# `->files` - are reached by this rule too, and that is correct rather than tolerated:
# `$request->query->get('x')` is attacker data, and a bag object cannot reach a string
# sink on its own because PHP raises before it gets there.
#
# mass_assign is included for the same reason $_GET carries it: the attacker names the
# keys as well as the values, and `?bio[is_admin]=1` makes `$request->bio` an array that
# came off the wire. Dropping the kind would report an Eloquent write fed by a magic read
# as an injection rather than as the mass assignment it is.
MAGIC_PROPERTY_KINDS: frozenset[TaintKind] = ALL_KINDS

# `request('sort')` - the helper called *with* a key, which docs/06-taint-analysis lists
# beside `$request->input('x')` and `Input::get('x')` in the Laravel HTTP source table.
#
# Kept apart from SOURCE_METHODS because this is a plain function and those are methods
# reached through a receiver check. `request()->input('x')` already works: the helper is
# recognised there as the *receiver*, and this is the form that returns the value
# directly instead.
REQUEST_HELPER = "request"

# The legacy `Input` facade, by the names a project can reach it under. Removed from
# Laravel in 6.0, so code still calling it has skipped years of upgrades - which is
# precisely the code most likely to be vulnerable.
#
# Matched on the resolved FQN and not on the written text, for the reason the DB facade
# is: `use App\Support\Input;` is an ordinary import of somebody's own class, and a
# scanner keying on the five letters "Input" would report every call to it. The bare
# name is what `\Input::get()` resolves to and what an un-namespaced file resolves to,
# since Laravel registered a global class alias for it.
INPUT_FACADE_FQNS = frozenset(
    {
        "Illuminate\\Support\\Facades\\Input",
        "Input",
    }
)


def is_request_helper(name: str, arg_count: int) -> bool:
    """Is this a `request('key')` call that returns attacker-controlled input?

    An argument is required. Bare `request()` returns the Request *object*, not a value
    off the wire, and it is already handled as a receiver - treating it as a value here
    would report the object itself as a tainted string.
    """
    return name == REQUEST_HELPER and arg_count > 0


def input_facade_kinds(receiver_fqn: str | None, method: str) -> frozenset[TaintKind]:
    """The kinds `Input::method(...)` returns, empty when this is not the legacy facade.

    `receiver_fqn` is the resolved class rather than the text at the call site, and None
    when the scope could not be resolved. None yields nothing: an unresolved receiver
    named `Input` is as likely to be a project's own helper as the facade, and guessing
    would put a fabricated evidence path in front of a developer.

    The method table is SOURCE_METHODS, because the facade proxied the Request object -
    `Input::get`, `Input::all` and `Input::only` were the same calls with the same
    return values, so they carry the same kinds and inherit `only()`'s reduced set.
    """
    if receiver_fqn is None or receiver_fqn not in INPUT_FACADE_FQNS:
        return frozenset()
    return SOURCE_METHODS.get(method, frozenset())


# The kinds a route parameter carries - `/pages/{slug}` arriving as `$slug`, which
# docs/06-taint-analysis states as a source in its own right: "Route parameters
# injected into controller signatures are sources".
#
# mass_assign is excluded, and it is the one kind that separates this from a query
# parameter. `?u[is_admin]=1` makes `$_GET['u']` an array whose keys came off the wire,
# which is what makes an Eloquent array write dangerous. A URI segment cannot do that:
# Laravel binds it from a single path component, so it is always a scalar string and
# there are no attacker-named keys in it. Including the kind would report a mass
# assignment on a value that cannot be an array.
ROUTE_PARAM_KINDS: frozenset[TaintKind] = ALL_KINDS - {TaintKind.MASS_ASSIGN}

# Declared types that leave a URL segment as the string it arrived as. `mixed` is here
# because it constrains nothing.
_STRING_PARAM_TYPES: frozenset[str] = frozenset({"string", "mixed"})


def route_param_is_source(declared: str | None) -> bool:
    """Does a URI segment bound to a parameter of this declared type arrive tainted?

    Three answers, and the third is why this is not simply "is it a string".

    - No declared type, or `string`/`mixed`: yes. This is the spec's own example,
      `public function show(Request $r, string $slug)`.
    - A coerced scalar - `int`, `float`, `bool`: no. PHP converts the segment before the
      first line of the body runs, so a string payload never arrives. This is the same
      reasoning the walk already applies to an `(int)` cast, and the two have to agree,
      or a cast would look safer than a type declaration that does strictly more.
    - A class name: no, because a class-typed parameter is route *model* binding. The
      segment identifies a record rather than supplying a string, and what such a route
      is usually missing is authorization, not escaping - that is
      laravel.missing-authorization, a different rule with different advice. Tainting it
      would report an injection on an Eloquent object that cannot reach a string sink.

    The last two collapse into one branch deliberately: both are "not a string", and
    enumerating the scalars separately would mean an unrecognised scalar defaulted to
    tainted, which is the fabricated-finding direction on a value PHP has coerced.
    """
    if declared is None:
        return True
    name = declared.strip().lstrip("?").lower()
    if not name:
        return True
    return name in _STRING_PARAM_TYPES


# PHP superglobals whose every key the attacker chooses, per docs/06-taint-analysis
# section "PHP native". $_SERVER is deliberately absent: it is half request and half
# server configuration, and it gets the per-key rule below.
#
# All carry every kind, mass_assign included, because the attacker names the keys as
# well as the values. `?u[is_admin]=1` makes `$_GET['u']` an array whose keys came off
# the wire, which is the property that makes an Eloquent array write dangerous.
#
# $_ENV, getenv(), php://input and apache_request_headers() appear in the same spec
# section and are not here. None of them is a subscript read on a known variable name,
# so each needs its own handling rather than an entry in this table, and the roadmap
# already reports the taint vocabulary as partial rather than complete.
FULLY_TAINTED_SUPERGLOBALS: frozenset[str] = frozenset(
    {
        "_GET",
        "_POST",
        "_REQUEST",
        "_COOKIE",
        "_FILES",
        "argv",
    }
)

# The $_SERVER keys docs/06-taint-analysis names as attacker-controlled. The HTTP_
# prefix is the general rule rather than a list of headers: a request header arrives
# as HTTP_<NAME>, so HTTP_HOST and HTTP_X_FORWARDED_FOR are instances of it and not
# separate facts to be maintained.
_TAINTED_SERVER_KEYS: frozenset[str] = frozenset(
    {
        "REQUEST_URI",
        "QUERY_STRING",
        "PATH_INFO",
    }
)
_TAINTED_SERVER_PREFIX = "HTTP_"

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
        "Illuminate\\Database\\DatabaseManager",
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

# Sink method -> the name Laravel declares its dangerous parameter under, for
# call sites that pass it as a named argument.
#
# PHP lets the caller write `whereRaw(bindings: [], sql: $x)`, and once a name is
# written the position stops meaning anything. An index alone is then wrong in
# both directions: it reads the empty bindings array and loses that injection,
# and on the mirror image `whereRaw(bindings: [$x], sql: 'a = ?')` it reads the
# binding and reports the safe parameterised call. Argument precision is what
# separates these rules from a nuisance, so the name is part of the sink's
# definition rather than something the walk infers.
#
# The names are the framework's, which is why they belong in this module and not
# in the walk: the *Raw builders declare `$sql`, except selectRaw and fromRaw
# which declare `$expression`; `DB::raw` declares `$value`; and the
# connection-level methods declare `$query`. A call site that names nothing costs
# nothing - the walk falls back to the index, which is what PHP itself does for a
# positional argument.
SINK_ARG_NAMES: dict[str, str] = {
    "orderByRaw": "sql",
    "whereRaw": "sql",
    "orWhereRaw": "sql",
    "havingRaw": "sql",
    "groupByRaw": "sql",
    "selectRaw": "expression",
    "fromRaw": "expression",
    "raw": "value",
    "statement": "query",
    "unprepared": "query",
    "select": "query",
    "insert": "query",
    "update": "query",
    "delete": "query",
}


def sink_arg_name(method: str) -> str | None:
    """The parameter name a sink's dangerous argument can arrive under, if known."""
    return SINK_ARG_NAMES.get(method)


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


def is_superglobal(variable: str) -> bool:
    """Is this variable name, written without its `$`, a superglobal source?"""
    return variable in FULLY_TAINTED_SUPERGLOBALS or variable == "_SERVER"


def superglobal_kinds(variable: str, key: str | None) -> frozenset[TaintKind]:
    """The kinds `$variable[key]` carries, or `$variable` itself when `key` is None.

    `variable` is the name without its `$`. `key` is the literal text of the subscript,
    and None both when there is no subscript and when the subscript is not a literal.

    $_SERVER is the only superglobal that inspects the key, and it is the reason this
    takes one. `$_SERVER['HTTP_HOST']` is a request header and `$_SERVER['DOCUMENT_ROOT']`
    is a path out of the server's own configuration. Tainting the array wholesale reports
    a filesystem path no attacker can influence; tainting none of it misses the header
    every Host-header poisoning bug is built on.

    An unrecognised $_SERVER key is tainted, and the asymmetry with the allowlist above is
    deliberate. A key this module does not name is either one of the attacker-controlled
    keys the spec lists that nobody has added yet, or a dynamic `$_SERVER[$name]` whose
    value is not known until the request arrives. A bare `$_SERVER` is treated the same
    way, because it contains the tainted keys. Guessing the other way would be a silent
    false negative, which is what invariant 4 exists to prevent: the set of safe keys is
    short and knowable, and the set of dangerous ones is open-ended.
    """
    if variable in FULLY_TAINTED_SUPERGLOBALS:
        return ALL_KINDS
    if variable != "_SERVER":
        return frozenset()
    if key is None or key.startswith(_TAINTED_SERVER_PREFIX) or key in _TAINTED_SERVER_KEYS:
        return ALL_KINDS
    return frozenset()


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
