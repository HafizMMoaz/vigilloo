from pathlib import Path

from vigilloo.graph import load_project
from vigilloo.laravel.policies import extract_explicit_policies, find_policy
from vigilloo.parser import parse_source
from vigilloo.rules import scan_project


def test_extract_explicit_policies_property() -> None:
    code = b"""<?php
namespace App\\Providers;

use App\\Models\\Order;
use App\\Policies\\CustomOrderPolicy;
use Illuminate\\Foundation\\Support\\Providers\\AuthServiceProvider as ServiceProvider;

class AuthServiceProvider extends ServiceProvider {
    protected $policies = [
        Order::class => CustomOrderPolicy::class,
        'App\\Models\\Invoice' => 'App\\Policies\\CustomInvoicePolicy',
    ];
}
"""
    path = Path("app/Providers/AuthServiceProvider.php")
    parsed = parse_source(path, code)

    def resolve_fn(p: Path, name: str) -> str | None:
        mapping = {
            "Order": "App\\Models\\Order",
            "CustomOrderPolicy": "App\\Policies\\CustomOrderPolicy",
        }
        return mapping.get(name)

    policies = extract_explicit_policies({path: parsed}, resolve_fn)
    assert policies["App\\Models\\Order"] == "App\\Policies\\CustomOrderPolicy"
    assert policies["App\\Models\\Invoice"] == "App\\Policies\\CustomInvoicePolicy"


def test_extract_explicit_policies_gate_policy_call() -> None:
    code = b"""<?php
namespace App\\Providers;

use App\\Models\\Product;
use App\\Policies\\ProductGuard;
use Illuminate\\Support\\Facades\\Gate;

class AuthServiceProvider {
    public function boot(): void {
        Gate::policy(Product::class, ProductGuard::class);
    }
}
"""
    path = Path("app/Providers/AuthServiceProvider.php")
    parsed = parse_source(path, code)

    def resolve_fn(p: Path, name: str) -> str | None:
        mapping = {
            "Product": "App\\Models\\Product",
            "ProductGuard": "App\\Policies\\ProductGuard",
        }
        return mapping.get(name)

    policies = extract_explicit_policies({path: parsed}, resolve_fn)
    assert policies["App\\Models\\Product"] == "App\\Policies\\ProductGuard"


def test_find_policy_explicit_over_convention() -> None:
    classes = {}
    explicit = {"App\\Models\\Order": "App\\Policies\\CustomOrderPolicy"}
    found = find_policy(classes, "App\\Models\\Order", explicit)
    assert found == "App\\Policies\\CustomOrderPolicy"


def test_policies_explicit_map_integration(tmp_path: Path) -> None:
    """Acceptance test: a policy registered only via $policies is found.

    authorizeResource() in a constructor suppresses missing authorization IDOR findings.
    """
    auth_provider_code = """<?php
namespace App\\Providers;

use App\\Models\\Order;
use App\\Policies\\CustomPolicy;

class AuthServiceProvider {
    protected $policies = [
        Order::class => CustomPolicy::class,
    ];
}
"""
    order_model = """<?php
namespace App\\Models;

use Illuminate\\Database\\Eloquent\\Model;

class Order extends Model {}
"""
    custom_policy = """<?php
namespace App\\Policies;

class CustomPolicy {
    public function view() { return True; }
}
"""
    controller_code = """<?php
namespace App\\Http\\Controllers;

use App\\Models\\Order;

class OrderController {
    public function __construct() {
        $this->authorizeResource(Order::class);
    }

    public function show(Order $order) {
        return $order;
    }
}

class UnprotectedOrderController {
    public function show(Order $order) {
        return $order;
    }
}
"""
    routes_code = """<?php
use Illuminate\\Support\\Facades\\Route;
use App\\Http\\Controllers\\OrderController;
use App\\Http\\Controllers\\UnprotectedOrderController as Unprotected;

Route::get('/orders/{order}', [OrderController::class, 'show'])->middleware('auth');
Route::get('/unprotected/{order}', [Unprotected::class, 'show'])->middleware('auth');
"""

    (tmp_path / "app/Providers").mkdir(parents=True)
    (tmp_path / "app/Models").mkdir(parents=True)
    (tmp_path / "app/Policies").mkdir(parents=True)
    (tmp_path / "app/Http/Controllers").mkdir(parents=True)
    (tmp_path / "routes").mkdir(parents=True)

    (tmp_path / "app/Providers/AuthServiceProvider.php").write_text(auth_provider_code)
    (tmp_path / "app/Models/Order.php").write_text(order_model)
    (tmp_path / "app/Policies/CustomPolicy.php").write_text(custom_policy)
    (tmp_path / "app/Http/Controllers/OrderController.php").write_text(controller_code)
    (tmp_path / "routes/web.php").write_text(routes_code)

    project = load_project(tmp_path)
    assert project.policies.get("App\\Models\\Order") == "App\\Policies\\CustomPolicy"

    findings = scan_project(project)

    # OrderController (uses authorizeResource in __construct) HAS NO IDOR FINDINGS
    protected_findings = [
        f
        for f in findings
        if f.rule_id == "laravel.missing-authorization"
        and "App\\Http\\Controllers\\OrderController::show" in f.evidence_path[0].snippet
    ]
    assert len(protected_findings) == 0

    # UnprotectedOrderController HAS an IDOR finding referencing CustomPolicy!
    unprotected_findings = [
        f
        for f in findings
        if f.rule_id == "laravel.missing-authorization"
        and "App\\Http\\Controllers\\UnprotectedOrderController::show" in f.evidence_path[0].snippet
    ]
    assert len(unprotected_findings) == 1
    # Check that CustomPolicy was identified as the policy in the evidence path!
    policy_steps = [s for s in unprotected_findings[0].evidence_path if s.role == "policy"]
    assert len(policy_steps) == 1
    assert "CustomPolicy" in policy_steps[0].snippet
