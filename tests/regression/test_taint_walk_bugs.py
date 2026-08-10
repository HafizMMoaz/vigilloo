"""One test per taint-walk bug that has already been fixed once.

docs/22-testing lists regression as a permanent layer, and this is it. The rule for the
directory is in that document; the short version is that a test lands here when a bug was
found, it names the commit that fixed it, its docstring says concretely what the engine
produced *before* the fix, and it is never deleted because the bug looks old. A bug that was
reachable once is reachable again: every fix here was a one-line condition, and every one of
them is the kind of line a later refactor moves without noticing.

These are deliberately not the unit tests the fix commits already carry in
`tests/test_taint.py` and `tests/test_views.py`. Those pin the mechanism - `stats.unresolved`
after `find_taint_paths`, the shape of a `ViewBinding`. These pin the *symptom*, the thing a
user would have seen: a finding that should not be in the report, or a scan that claims 100%
coverage over a trail it quietly dropped. The mechanism is free to be rewritten; the symptom
must never come back. When a refactor moves the give-up out of `find_taint_paths` and into
somewhere else entirely, the unit test is what gets updated and this is what still has to
hold.

Three of the four bugs are the same bug wearing different clothes: the walk lost tainted data
and said nothing, so the report was clean and the coverage line said everything was resolved.
That is invariant 4's exact failure mode, and it is invisible in production - nobody files a
bug for the vulnerability that was never reported.
"""

from pathlib import Path

from vigilloo.graph import coverage, load_project
from vigilloo.models import Coverage, Finding, WalkStats
from vigilloo.rules import scan_project

_ROUTES = (
    "<?php\n"
    "use App\\Http\\Controllers\\OrderController;\n"
    "use Illuminate\\Support\\Facades\\Route;\n"
    "Route::get('/orders', [OrderController::class, 'index']);\n"
)


def _project(root: Path, files: dict[str, str]) -> Path:
    """Write a minimal Laravel project and return its root.

    Written out per test rather than shared, because every one of these bugs is about the
    exact shape of one controller body, and a shared fixture edited for a fifth bug is how
    the other four quietly stop testing what their docstrings claim.
    """
    for relative, source in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source)
    return root


def _scan(root: Path) -> tuple[list[Finding], Coverage]:
    """Findings and coverage from one scan, the same pair `vigilloo scan` prints."""
    stats = WalkStats()
    project = load_project(root, stats)
    findings = scan_project(project, stats)
    return findings, coverage(project, stats)


def test_a_computed_view_name_is_reported_as_a_coverage_gap(tmp_path: Path) -> None:
    """Fixed in 71412ca, "stop dropping view() calls with a computed template name".

    `extract_view_bindings` did `if not name: continue`, so `view($name, compact('sort'))`
    was discarded before the taint walk was ever told the call existed. Before the fix this
    project scanned as: no findings, and `Coverage: 2/2 files parsed (100.0%), 1/1 call sites
    resolved (100.0%)` - a report claiming it had followed everything, over a controller that
    hands attacker-controlled data to a template it cannot even name. That is a clean bill of
    health with the evidence of its own blind spot deleted.

    After the fix the binding survives with `template=None`, the walk reaches its existing
    unresolved-template branch, and the gap is counted. Still no finding, which is correct:
    the walk genuinely cannot tell which template ran. The gap has to be visible instead.
    """
    root = _project(
        tmp_path,
        {
            "routes/api.php": _ROUTES,
            "app/Http/Controllers/OrderController.php": (
                "<?php\n"
                "namespace App\\Http\\Controllers;\n"
                "use Illuminate\\Http\\Request;\n"
                "class OrderController\n"
                "{\n"
                "    public function index(Request $request)\n"
                "    {\n"
                "        $sort = $request->input('sort');\n"
                "        $name = 'orders.' . $sort;\n"
                "\n"
                "        return view($name, compact('sort'));\n"
                "    }\n"
                "}\n"
            ),
        },
    )

    findings, result = _scan(root)

    assert findings == []
    assert result.calls_unresolved == 1
    assert result.call_resolution_rate < 1.0


def test_an_eloquent_result_is_not_reported_as_request_data(tmp_path: Path) -> None:
    """Fixed in 42c9b2e, "require a Request-like receiver before treating a method as a
    source".

    `is_source()` matched on method name alone, and get/all/query/only/except/json/url are
    Eloquent and Collection methods as much as they are Request methods. Before the fix this
    controller - a query result rendered by a template, the single most common shape in
    Laravel - produced one `php.xss` finding whose source step read
    `$orders = Order::where('status', 'paid')->get()` annotated "attacker-controlled request
    data". The path was real in the sense that every edge existed and false in the sense that
    the first step was a lie, which is the worse kind of false positive: it survives review
    because the evidence looks complete.

    The blast radius is why this one is worth a permanent test. It fired on correct code, in
    the shape that appears in nearly every Laravel controller, so it did not cost one bad
    finding but a report nobody would finish reading.
    """
    root = _project(
        tmp_path,
        {
            "routes/api.php": _ROUTES,
            "app/Http/Controllers/OrderController.php": (
                "<?php\n"
                "namespace App\\Http\\Controllers;\n"
                "class OrderController\n"
                "{\n"
                "    public function index()\n"
                "    {\n"
                "        $orders = Order::where('status', 'paid')->get();\n"
                "\n"
                "        return view('orders.show', compact('orders'));\n"
                "    }\n"
                "}\n"
            ),
            "resources/views/orders/show.blade.php": "<p>{!! $orders !!}</p>\n",
        },
    )

    findings, _ = _scan(root)

    assert findings == []


def test_a_genuine_request_receiver_is_still_reported(tmp_path: Path) -> None:
    """The other half of 42c9b2e: the fix must not have bought its precision with silence.

    Identical to the test above except that `->get()` is called on a real `Request`
    parameter. One `php.xss` finding, or the receiver check has gone from "is this actually a
    Request" to "never mind, no sources here". A regression test for a false positive is only
    half a test without the case that proves the true positive survived - the cheapest way to
    fix a noisy rule is to turn it off, and nothing else in this file would notice.
    """
    root = _project(
        tmp_path,
        {
            "routes/api.php": _ROUTES,
            "app/Http/Controllers/OrderController.php": (
                "<?php\n"
                "namespace App\\Http\\Controllers;\n"
                "use Illuminate\\Http\\Request;\n"
                "class OrderController\n"
                "{\n"
                "    public function index(Request $request)\n"
                "    {\n"
                "        $sort = $request->get('sort');\n"
                "\n"
                "        return view('orders.show', compact('sort'));\n"
                "    }\n"
                "}\n"
            ),
            "resources/views/orders/show.blade.php": "<p>{!! $sort !!}</p>\n",
        },
    )

    findings, _ = _scan(root)

    assert [finding.rule_id for finding in findings] == ["php.xss"]


def test_tainted_data_into_a_blade_loop_is_reported_as_a_finding(
    tmp_path: Path,
) -> None:
    """Implemented in TASK-050: Blade collection aliasing in loops.

    Blade loop variables are now aliased to the collection's taint, so
    @foreach ($rows as $row) {!! $row !!} propagates taint to $row and generates
    an XSS finding.
    """
    root = _project(
        tmp_path,
        {
            "routes/api.php": _ROUTES,
            "app/Http/Controllers/OrderController.php": (
                "<?php\n"
                "namespace App\\Http\\Controllers;\n"
                "use Illuminate\\Http\\Request;\n"
                "class OrderController\n"
                "{\n"
                "    public function index(Request $request)\n"
                "    {\n"
                "        $rows = $request->input('rows');\n"
                "\n"
                "        return view('orders.list', compact('rows'));\n"
                "    }\n"
                "}\n"
            ),
            "resources/views/orders/list.blade.php": (
                "@foreach ($rows as $row)\n  <li>{!! $row !!}</li>\n@endforeach\n"
            ),
        },
    )

    findings, result = _scan(root)

    assert len(findings) == 1
    assert findings[0].rule_id == "php.xss"
    assert result.calls_unresolved == 0


def test_correct_code_reports_no_gaps_at_all(tmp_path: Path) -> None:
    """Fixed in 0d252a5, "only count a lost trail when tainted data was actually abandoned".

    The other three bugs are the counter staying silent when it should speak. This is the
    counter that would not stop talking: every unresolved receiver incremented it, including
    the `$request->input()` source call itself and the `->get()` that terminates a query
    builder chain. It reported 78 gaps on koel and 2 on this repo's own reference fixture,
    and every one of them was correct code that the walk had understood perfectly well.

    Before the fix, the controller below - which loses nothing, because no tainted value is
    ever handed to a call the walk cannot follow - reported 3 unresolved call sites, printing
    something like `1/4 call sites resolved (25.0%)` on a scan with no blind spot in it.

    This is the false-positive half of coverage, and it matters as much as the other three.
    A counter that reports gaps on correct code is one people learn to ignore, and once it is
    ignored the three bugs above are back whether or not their code has regressed.
    """
    root = _project(
        tmp_path,
        {
            "routes/api.php": _ROUTES,
            "app/Http/Controllers/OrderController.php": (
                "<?php\n"
                "namespace App\\Http\\Controllers;\n"
                "use Illuminate\\Http\\Request;\n"
                "class OrderController\n"
                "{\n"
                "    public function index(Request $request)\n"
                "    {\n"
                "        $sort = $request->input('sort');\n"
                "        $rows = Order::where('status', 'paid')->orderBy('name')->get();\n"
                "\n"
                "        return view('orders.list', ['rows' => $rows]);\n"
                "    }\n"
                "}\n"
            ),
            "resources/views/orders/list.blade.php": "<p>{{ $rows }}</p>\n",
        },
    )

    findings, result = _scan(root)

    assert findings == []
    assert result.calls_unresolved == 0
    assert result.call_resolution_rate == 1.0
