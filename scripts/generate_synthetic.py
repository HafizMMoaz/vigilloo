import subprocess
import time
from pathlib import Path


def generate_synthetic(n_ifs: int, root_dir: Path):
    root_dir.mkdir(parents=True, exist_ok=True)

    app_dir = root_dir / "app" / "Http" / "Controllers"
    app_dir.mkdir(parents=True, exist_ok=True)

    routes_dir = root_dir / "routes"
    routes_dir.mkdir(parents=True, exist_ok=True)

    # Generate controller with n_ifs
    ifs = ""
    for i in range(n_ifs):
        ifs += f"        if (rand(0, 1)) {{ $x = {i}; }}\n"

    controller_code = f"""<?php
namespace App\\Http\\Controllers;
use Illuminate\\Http\\Request;
use Illuminate\\Support\\Facades\\DB;

class TestController {{
    public function index(Request $request) {{
        $data = $request->input('q');
{ifs}
        DB::select($data);
    }}
}}
"""
    (app_dir / "TestController.php").write_text(controller_code)

    # Generate route
    routes_code = """<?php
use Illuminate\\Support\\Facades\\Route;
use App\\Http\\Controllers\\TestController;

Route::get('/', [TestController::class, 'index']);
"""
    (routes_dir / "web.php").write_text(routes_code)


def run_benchmark(n_ifs: int):
    root_dir = Path(f"/private/tmp/synthetic_{n_ifs}")
    generate_synthetic(n_ifs, root_dir)

    # Run the vigilloo scan
    start = time.perf_counter()
    subprocess.run(
        ["uv", "run", "python", "scripts/benchmark.py", str(root_dir)],
        capture_output=False,
        text=True,
    )
    duration = time.perf_counter() - start
    print(f"N={n_ifs:3} -> {duration:.3f}s")


if __name__ == "__main__":
    for i in [1, 5, 10, 12, 14, 16]:
        run_benchmark(i)
