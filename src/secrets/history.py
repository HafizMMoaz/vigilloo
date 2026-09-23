"""Git history scanner for detecting rotated or removed secrets."""

import re
import subprocess
from pathlib import Path

from .patterns import SECRET_RULES, is_false_positive, shannon_entropy
from .redact import redact_secret
from .scanner import SecretFinding


def scan_git_history(repo_path: Path) -> list[SecretFinding]:
    """Scan full git history for historical secrets committed across revisions."""
    # Verify git repository
    git_dir = repo_path / ".git"
    if not git_dir.exists():
        raise ValueError(f"Path is not a git repository: {repo_path}")

    # Run git log with full diff output
    cmd = [
        "git",
        "log",
        "-p",
        "--full-history",
        "--no-color",
        "--format=COMMIT:%H|%an|%ad",
        "--date=iso-strict",
    ]

    try:
        proc = subprocess.run(
            cmd,
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True,
            errors="ignore",
        )
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"git log failed: {exc.stderr}") from exc

    findings: list[SecretFinding] = []
    seen: set[tuple[str, str, str, str]] = set()  # (commit_hash, file_path, rule_id, redacted)

    current_commit: str | None = None
    current_author: str | None = None
    current_date: str | None = None
    current_file: str = "unknown"
    line_number = 1

    file_header_re = re.compile(r"^\+\+\+ b/(.+)$")

    for raw_line in proc.stdout.splitlines():
        if raw_line.startswith("COMMIT:"):
            parts = raw_line[len("COMMIT:") :].split("|", 2)
            if len(parts) == 3:
                current_commit, current_author, current_date = parts
                current_file = "unknown"
                line_number = 1
            continue

        file_match = file_header_re.match(raw_line)
        if file_match:
            current_file = file_match.group(1)
            line_number = 1
            continue

        # Look only at added lines (diff lines starting with + but not +++)
        if raw_line.startswith("+") and not raw_line.startswith("+++"):
            added_text = raw_line[1:].strip()
            line_number += 1

            if len(added_text) < 10:
                continue

            for rule in SECRET_RULES:
                for match in rule.pattern.finditer(added_text):
                    token = match.group(1) if match.groups() else match.group(0)

                    if is_false_positive(token):
                        continue

                    if rule.min_entropy > 0.0 and shannon_entropy(token) < rule.min_entropy:
                        continue

                    if rule.validator and not rule.validator(token):
                        continue

                    redacted = redact_secret(token)
                    key = (current_commit or "", current_file, rule.id, redacted)
                    if key in seen:
                        continue
                    seen.add(key)

                    findings.append(
                        SecretFinding(
                            rule_id=rule.id,
                            rule_name=rule.name,
                            severity=rule.severity,
                            file_path=current_file,
                            line_number=line_number,
                            redacted_value=redacted,
                            commit_hash=current_commit,
                            commit_author=current_author,
                            commit_date=current_date,
                        )
                    )

    # Sort deterministically
    findings.sort(key=lambda f: (f.commit_hash or "", f.file_path, f.line_number, f.rule_id))
    return findings
