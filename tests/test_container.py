from pathlib import Path

from vigilloo.graph import graph_rows, load_project
from vigilloo.taint import WalkStats, find_taint_paths


def test_container_bindings_graph_edges(tmp_path: Path) -> None:
    """Graph records RESOLVES_TO edges for constructor injection and app() calls."""
    app_dir = tmp_path / "app"
    app_dir.mkdir(parents=True)

    (tmp_path / "app" / "Providers").mkdir(parents=True)
    (tmp_path / "app" / "Providers" / "AppServiceProvider.php").write_text(
        "<?php\n"
        "namespace App\\Providers;\n"
        "use Illuminate\\Support\\ServiceProvider;\n"
        "use App\\Services\\PaymentGateway;\n"
        "use App\\Services\\StripeGateway;\n"
        "class AppServiceProvider extends ServiceProvider\n"
        "{\n"
        "    public function register()\n"
        "    {\n"
        "        $this->app->bind(PaymentGateway::class, StripeGateway::class);\n"
        "    }\n"
        "}\n"
    )

    (tmp_path / "app" / "Services").mkdir(parents=True)
    (tmp_path / "app" / "Services" / "PaymentGateway.php").write_text(
        "<?php\n"
        "namespace App\\Services;\n"
        "interface PaymentGateway { public function pay($amount); }\n"
    )
    (tmp_path / "app" / "Services" / "StripeGateway.php").write_text(
        "<?php\n"
        "namespace App\\Services;\n"
        "class StripeGateway implements PaymentGateway { public function pay($amount) {} }\n"
    )

    (tmp_path / "app" / "Http" / "Controllers").mkdir(parents=True)
    (tmp_path / "app" / "Http" / "Controllers" / "PaymentController.php").write_text(
        "<?php\n"
        "namespace App\\Http\\Controllers;\n"
        "use App\\Services\\PaymentGateway;\n"
        "class PaymentController\n"
        "{\n"
        "    public function __construct(PaymentGateway $gateway) {}\n"
        "    public function act()\n"
        "    {\n"
        "        $g = app(PaymentGateway::class);\n"
        "    }\n"
        "}\n"
    )

    project = load_project(tmp_path)
    rows = graph_rows(project, 1, {})
    nodes, edges = rows.nodes, rows.edges

    # We should have two RESOLVES_TO edges to StripeGateway:
    # 1. From PaymentController::__construct (constructor injection)
    # 2. From PaymentController::act (app() call)

    resolves_edges = [e for e in edges if e.kind == "RESOLVES_TO"]

    stripe_id = next(n.id for n in nodes if n.fqn == "App\\Services\\StripeGateway")
    constructor_id = next(
        n.id for n in nodes if n.fqn == "App\\Http\\Controllers\\PaymentController::__construct"
    )
    act_id = next(n.id for n in nodes if n.fqn == "App\\Http\\Controllers\\PaymentController::act")

    destinations = {e.dst_id for e in resolves_edges}
    assert stripe_id in destinations

    # Check the sources
    sources = {e.src_id for e in resolves_edges}
    assert constructor_id in sources
    assert act_id in sources


def test_container_bindings_taint(tmp_path: Path) -> None:
    """Taint path correctly follows an interface call to the concrete implementation."""
    (tmp_path / "app" / "Providers").mkdir(parents=True)
    (tmp_path / "app" / "Providers" / "AppServiceProvider.php").write_text(
        "<?php\n"
        "namespace App\\Providers;\n"
        "use Illuminate\\Support\\ServiceProvider;\n"
        "use App\\Services\\PaymentGateway;\n"
        "use App\\Services\\StripeGateway;\n"
        "class AppServiceProvider extends ServiceProvider\n"
        "{\n"
        "    public function register()\n"
        "    {\n"
        "        $this->app->bind(PaymentGateway::class, StripeGateway::class);\n"
        "    }\n"
        "}\n"
    )

    (tmp_path / "app" / "Services").mkdir(parents=True)
    (tmp_path / "app" / "Services" / "PaymentGateway.php").write_text(
        "<?php\n"
        "namespace App\\Services;\n"
        "interface PaymentGateway { public function pay($amount); }\n"
    )
    (tmp_path / "app" / "Services" / "StripeGateway.php").write_text(
        "<?php\n"
        "namespace App\\Services;\n"
        "use Illuminate\\Support\\Facades\\DB;\n"
        "class StripeGateway implements PaymentGateway {\n"
        "    public function pay($amount) {\n"
        "        DB::raw($amount);\n"  # Sink!
        "    }\n"
        "}\n"
    )

    (tmp_path / "app" / "Http" / "Controllers").mkdir(parents=True)
    (tmp_path / "app" / "Http" / "Controllers" / "PaymentController.php").write_text(
        "<?php\n"
        "namespace App\\Http\\Controllers;\n"
        "use Illuminate\\Http\\Request;\n"
        "use App\\Services\\PaymentGateway;\n"
        "class PaymentController\n"
        "{\n"
        "    private PaymentGateway $gateway;\n"
        "    public function __construct(PaymentGateway $gateway) {\n"
        "        $this->gateway = $gateway;\n"
        "    }\n"
        "    public function act(Request $request)\n"
        "    {\n"
        "        // Tainted data goes to the interface, but should be found in StripeGateway::pay\n"
        "        $this->gateway->pay($request->input('amount'));\n"
        "    }\n"
        "}\n"
    )

    (tmp_path / "routes").mkdir(parents=True)
    (tmp_path / "routes" / "web.php").write_text(
        "<?php\n"
        "use App\\Http\\Controllers\\PaymentController;\n"
        "Route::post('/pay', [PaymentController::class, 'act']);\n"
    )

    project = load_project(tmp_path)
    stats = WalkStats()
    paths = find_taint_paths(project, stats=stats)

    # We should find exactly one path, ending in StripeGateway::pay
    assert len(paths) == 1
    assert "raw" in paths[0][-1].snippet
