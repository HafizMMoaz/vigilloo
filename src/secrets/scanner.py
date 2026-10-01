"""Working tree scanner for credential and secret detection."""

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .patterns import SECRET_RULES, is_false_positive, shannon_entropy
from .redact import redact_secret


@dataclass(frozen=True)
class SecretFinding:
    """A detected credential or secret with redacted value."""

    rule_id: str
    rule_name: str
    severity: str
    file_path: str
    line_number: int
    redacted_value: str
    commit_hash: str | None = None
    commit_author: str | None = None
    commit_date: str | None = None


_IGNORE_DIRS = frozenset(
    {
        ".git",
        "vendor",
        "node_modules",
        ".vigilloo",
        "storage",
        "cache",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
    }
)


def _is_binary(path: Path) -> bool:
    """Check if a file appears to be binary."""
    try:
        with path.open("rb") as f:
            chunk = f.read(8192)
            return b"\x00" in chunk
    except OSError:
        return True


def _is_committed_env(path: Path) -> bool:
    """Check if a .env file is tracked in git."""
    try:
        res = subprocess.run(
            ["git", "ls-files", "--error-unmatch", path.name],
            cwd=path.parent,
            capture_output=True,
            text=True,
            check=False,
        )
        return res.returncode == 0
    except Exception:
        return False


def scan_working_tree(root_path: Path) -> list[SecretFinding]:
    """Scan all text files in root_path for secrets and committed credentials."""
    findings: list[SecretFinding] = []

    for dirpath, dirnames, filenames in os.walk(root_path):
        # Prune ignored directories in-place
        dirnames[:] = [d for d in dirnames if d not in _IGNORE_DIRS]

        for fname in filenames:
            file_path = Path(dirpath) / fname
            rel_path = file_path.relative_to(root_path).as_posix()

            # Rule: Tracked or committed .env files
            if fname == ".env":
                if _is_committed_env(file_path):
                    findings.append(
                        SecretFinding(
                            rule_id="secrets.committed-env",
                            rule_name="Committed Environment File",
                            severity="critical",
                            file_path=rel_path,
                            line_number=1,
                            redacted_value=".env (tracked in git)",
                        )
                    )

            # Skip common test fixtures and examples if they contain placeholder names
            is_example_file = fname.startswith(".env.") and (
                "example" in fname or "sample" in fname or "template" in fname
            )

            if _is_binary(file_path):
                continue

            try:
                lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                continue

            for line_idx, line in enumerate(lines, start=1):
                # Quick pre-filter: skip empty or very short lines
                if len(line.strip()) < 10:
                    continue

                for rule in SECRET_RULES:
                    for match in rule.pattern.finditer(line):
                        token = match.group(1) if match.groups() else match.group(0)

                        if is_example_file and is_false_positive(token):
                            continue

                        if is_false_positive(token):
                            continue

                        if rule.min_entropy > 0.0 and shannon_entropy(token) < rule.min_entropy:
                            continue

                        if rule.validator and not rule.validator(token):
                            continue

                        findings.append(
                            SecretFinding(
                                rule_id=rule.id,
                                rule_name=rule.name,
                                severity=rule.severity,
                                file_path=rel_path,
                                line_number=line_idx,
                                redacted_value=redact_secret(token),
                            )
                        )

    # Sort deterministically
    findings.sort(key=lambda f: (f.file_path, f.line_number, f.rule_id))
    return findings
