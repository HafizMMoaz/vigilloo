import pytest
from pathlib import Path

from vigilloo.graph import load_project
from vigilloo.rules import scan_project

FIXTURE = Path("tests/fixtures/duck-typing")

def test_duck_typed_call_demotes_severity() -> None:
    findings = scan_project(load_project(FIXTURE))
    assert findings, "Should find SQL injections"
    
    for f in findings:
        assert f.rule_id == "php.sql-injection"
        # The duck typed edge should demote confidence < 0.5 and lower severity to "high"
        assert f.severity == "high", "Duck typed call should demote critical to high"

        propagator_steps = [s for s in f.evidence_path if s.role == "propagator"]
        assert propagator_steps, "Should have a propagator step"
        
        # Verify the confidence of the step
        # Since there are 2 ducks, it should be 0.4 / 2 = 0.2
        for step in propagator_steps:
            if hasattr(step, "confidence"):
                assert step.confidence == 0.2
