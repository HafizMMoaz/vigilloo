"""Tests for secrets pattern detection, entropy checks, and redaction."""

from pathlib import Path

from vigilloo.secrets.patterns import is_false_positive, shannon_entropy
from vigilloo.secrets.redact import redact_secret
from vigilloo.secrets.scanner import scan_working_tree


def test_redact_secret() -> None:
    raw = "AKIAIOSFODNN7EXAMPLE"
    redacted = redact_secret(raw)
    assert redacted != raw
    assert "*" in redacted
    assert "AKIA" in redacted
    assert "EXAMPLE" not in redacted
    assert len(redacted) == len(raw)


def test_shannon_entropy() -> None:
    # Low entropy (repeated or simple)
    assert shannon_entropy("AAAAAAAAAAAAAAAA") < 1.0
    assert shannon_entropy("0101010101010101") <= 1.0

    # High entropy (random base64/hex)
    assert shannon_entropy("dGhpcyBpcyBhIHJhbmRvbSBzdHJpbmc=") > 3.5
    assert shannon_entropy("4f8a2c1b9d3e7f0a") > 3.0


def test_false_positive_filters() -> None:
    # UUIDs
    assert is_false_positive("12345678-1234-1234-1234-123456789abc") is True
    # Hashes
    assert is_false_positive("e4d909c290d0fb1ca068ffaddf22cbd0") is True
    # Placeholders
    assert is_false_positive("your-secret-here") is True
    assert is_false_positive("changeme") is True
    assert is_false_positive("my_dummy_value") is True
    # Base64 data
    assert is_false_positive("data:image/png;base64,iVBORw0KGgo=") is True


def test_scan_working_tree_providers(tmp_path: Path) -> None:
    aws_tok = f"{'AK'}{'IA'}IOSFODNN7EXAMPLE"
    stripe_tok = f"{'sk'}_{'live'}_51Abcdefghijklmnopqrstuvwx999"
    gh_tok = f"{'gh'}{'p'}_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    google_tok = f"{'AI'}{'za'}SyA1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q"
    slack_tok = f"{'xo'}{'xb'}-123456789012-1234567890123-abcdefghijklmnopqrstuvwx"

    source_file = tmp_path / "config.php"
    source_file.write_text(
        f"""<?php
return [
    'aws_key' => '{aws_tok}',
    'stripe_key' => '{stripe_tok}',
    'github_token' => '{gh_tok}',
    'google_key' => '{google_tok}',
    'slack_token' => '{slack_tok}',
    'db_url' => 'postgres://admin:SuperSecretPass123@db.internal:5432/app',
];
""",
        encoding="utf-8",
    )

    findings = scan_working_tree(tmp_path)
    rule_ids = {f.rule_id for f in findings}

    assert "secrets.aws-access-key" in rule_ids
    assert "secrets.stripe-key" in rule_ids
    assert "secrets.github-token" in rule_ids
    assert "secrets.google-api-key" in rule_ids
    assert "secrets.slack-token" in rule_ids
    assert "secrets.database-url" in rule_ids

    # Critical invariant: Plaintext secrets must NEVER be present in findings
    for f in findings:
        assert "SuperSecretPass123" not in f.redacted_value
        assert "AKIAIOSFODNN7EXAMPLE" not in f.redacted_value
        assert "*" in f.redacted_value


def test_scan_working_tree_ignores_negatives(tmp_path: Path) -> None:
    source_file = tmp_path / "test.php"
    source_file.write_text(
        """<?php
// UUIDs
$uuid = 'c305f98a-2c94-4d8d-bb2d-74d7f53a48e7';
// MD5 and SHA256
$hash = '5d41402abc4b2a76b9719d911017c592';
// Placeholders
$token = 'your-secret-here';
$key = 'changeme';
""",
        encoding="utf-8",
    )

    findings = scan_working_tree(tmp_path)
    assert len(findings) == 0
