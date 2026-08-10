from pathlib import Path

from vigilloo.graph import load_project
from vigilloo.rules import scan_project


def _write_files(base_dir: Path, files: dict[str, str]) -> None:
    for rel_path, content in files.items():
        path = base_dir / rel_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)


def test_job_entrypoint_severity_deduction(tmp_path: Path) -> None:
    # A job that contains an SQL injection
    files = {
        "app/Jobs/ProcessOrder.php": """
        <?php
        namespace App\\Jobs;
        
        use Illuminate\\Contracts\\Queue\\ShouldQueue;
        use Illuminate\\Support\\Facades\\DB;
        
        class ProcessOrder implements ShouldQueue {
            public $orderId;
            
            public function __construct($orderId) {
                $this->orderId = $orderId;
            }
            
            public function handle() {
                // SQL injection sink inside a job handle
                DB::select("SELECT * FROM orders WHERE id = " . $this->orderId);
            }
        }
        """
    }

    _write_files(tmp_path, files)
    project = load_project(tmp_path)

    # Assert entrypoint was found
    assert len(project.entrypoints) == 1
    assert project.entrypoints[0].kind == "job"
    assert project.entrypoints[0].fqn == "App\\Jobs\\ProcessOrder::handle"

    findings = scan_project(project)

    # Assert the finding is reported
    assert len(findings) == 1
    finding = findings[0]

    # SQL_INJECTION is normally 'critical', but should be lowered to 'high'
    # because it's console-only
    assert finding.rule_id == "php.sql-injection"
    assert finding.severity == "high"
    assert finding.evidence_path[0].role == "entry"
    assert finding.evidence_path[0].note == "Job entry point"
