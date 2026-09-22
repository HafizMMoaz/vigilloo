"""Tests for git history secrets scanning."""

import subprocess
from pathlib import Path

from vigilloo.secrets.history import scan_git_history


def test_scan_git_history_detects_removed_secret(tmp_path: Path) -> None:
    # Initialize a temporary git repository
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(
        ["git", "config", "user.name", "Test Committer"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )

    secret_file = tmp_path / "credentials.txt"

    # Commit 1: Add secret
    aws_key = f"{'AK'}{'IA'}IOSFODNN7EXAMPLE"
    secret_file.write_text(f"AWS_KEY = {aws_key}\n", encoding="utf-8")
    subprocess.run(["git", "add", "credentials.txt"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "add credentials"], cwd=tmp_path, check=True, capture_output=True
    )

    # Commit 2: Remove secret
    secret_file.write_text("AWS_KEY = REDACTED\n", encoding="utf-8")
    subprocess.run(["git", "add", "credentials.txt"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "rotate and remove secret"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )

    # Scan history
    findings = scan_git_history(tmp_path)
    assert len(findings) >= 1

    aws_finding = next(f for f in findings if f.rule_id == "secrets.aws-access-key")
    assert aws_finding.file_path == "credentials.txt"
    assert aws_finding.commit_hash is not None
    assert aws_finding.commit_author == "Test Committer"
    assert "AKIAIOSFODNN7EXAMPLE" not in aws_finding.redacted_value
    assert "AKIA" in aws_finding.redacted_value
