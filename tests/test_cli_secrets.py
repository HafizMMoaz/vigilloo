"""Tests for `vigilloo secrets` CLI command."""

import json
from pathlib import Path

from typer.testing import CliRunner

from vigilloo.cli import app

runner = CliRunner()


def test_secrets_clean_directory(tmp_path: Path) -> None:
    source = tmp_path / "index.php"
    source.write_text("<?php echo 'Hello World';\n", encoding="utf-8")

    result = runner.invoke(app, ["secrets", str(tmp_path)])
    assert result.exit_code == 0
    assert "No exposed secrets or credentials detected" in result.stdout


def test_secrets_detected_terminal(tmp_path: Path) -> None:
    token = f"{'sk'}_{'live'}_51Abcdefghijklmnopqrstuvwx999"
    source = tmp_path / "env.php"
    source.write_text(
        f"<?php $stripe = '{token}';\n",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["secrets", str(tmp_path)])
    assert result.exit_code == 1
    assert "Stripe API Key" in result.stdout
    assert "sk_live_" in result.stdout
    assert token not in result.stdout


def test_secrets_detected_json(tmp_path: Path) -> None:
    token = f"{'sk'}_{'live'}_51Abcdefghijklmnopqrstuvwx999"
    source = tmp_path / "env.php"
    source.write_text(
        f"<?php $stripe = '{token}';\n",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["secrets", "--json", str(tmp_path)])
    assert result.exit_code == 1
    data = json.loads(result.stdout)
    assert data["secrets_count"] == 1
    assert data["findings"][0]["rule_id"] == "secrets.stripe-key"
    assert token not in data["findings"][0]["redacted_value"]


def test_secrets_nonexistent_path_exits_2() -> None:
    result = runner.invoke(app, ["secrets", "/nonexistent/path/xyz"])
    assert result.exit_code == 2


def test_secrets_history_non_git_exits_2(tmp_path: Path) -> None:
    result = runner.invoke(app, ["secrets", "--history", str(tmp_path)])
    assert result.exit_code == 2
    assert "not a git repository" in result.stdout
