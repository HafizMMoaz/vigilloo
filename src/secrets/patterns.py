"""Secret provider patterns, entropy calculation, and context filters."""

import math
import re
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass


def shannon_entropy(s: str) -> float:
    """Calculate the Shannon entropy (bits per symbol) of a string."""
    if not s:
        return 0.0
    counts = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


_UUID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_HEX_HASH_PATTERN = re.compile(r"^[0-9a-fA-F]{32,64}$")
_PLACEHOLDERS = frozenset(
    {
        "your-secret-here",
        "your_secret_here",
        "your_api_key",
        "your-api-key",
        "changeme",
        "placeholder",
        "dummy_value",
        "test_secret",
        "example_key",
        "insert-key-here",
        "replace-me",
    }
)


def is_false_positive(token: str) -> bool:
    """Return True if the token is an obvious false positive (UUID, hash, placeholder)."""
    clean = token.strip().lower()

    if _UUID_PATTERN.match(token.strip()):
        return True

    # Bare hex hashes without provider signatures
    if _HEX_HASH_PATTERN.match(token.strip()):
        return True

    # Base64 data URIs
    if clean.startswith("data:") or clean.startswith("base64,"):
        return True

    for p in _PLACEHOLDERS:
        if p in clean:
            return True

    # Repeated characters like AAAAAAAAA or 11111111
    if len(clean) > 8 and len(set(clean)) <= 2:
        return True

    return False


@dataclass(frozen=True)
class SecretRule:
    """A pattern-and-entropy rule detecting a specific credential provider."""

    id: str
    name: str
    pattern: re.Pattern[str]
    severity: str  # critical, high, medium
    min_entropy: float = 2.5
    validator: Callable[[str], bool] | None = None


# Known provider pattern catalogue
SECRET_RULES: list[SecretRule] = [
    SecretRule(
        id="secrets.aws-access-key",
        name="AWS Access Key ID",
        pattern=re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        severity="critical",
        min_entropy=2.8,
    ),
    SecretRule(
        id="secrets.stripe-key",
        name="Stripe API Key",
        pattern=re.compile(r"\b((?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,99})\b"),
        severity="critical",
        min_entropy=3.0,
    ),
    SecretRule(
        id="secrets.github-token",
        name="GitHub Personal Access Token",
        pattern=re.compile(
            r"\b((?:ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})\b"
        ),
        severity="critical",
        min_entropy=3.0,
    ),
    SecretRule(
        id="secrets.google-api-key",
        name="Google API Key",
        pattern=re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
        severity="high",
        min_entropy=3.0,
    ),
    SecretRule(
        id="secrets.slack-token",
        name="Slack Token",
        pattern=re.compile(r"\b(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32})\b"),
        severity="high",
        min_entropy=2.8,
    ),
    SecretRule(
        id="secrets.jwt-token",
        name="JSON Web Token (JWT)",
        pattern=re.compile(
            r"\b(eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})\b"
        ),
        severity="medium",
        min_entropy=3.0,
    ),
    SecretRule(
        id="secrets.private-key",
        name="Private Key PEM Block",
        pattern=re.compile(r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)"),
        severity="critical",
        min_entropy=0.0,
    ),
    SecretRule(
        id="secrets.database-url",
        name="Database Connection URL with Credentials",
        pattern=re.compile(
            r"\b((?:postgres|mysql|mongodb|redis)://[^:\s@]+:[^@\s]+@[^/\s]+(?:/[^\s]*)?)\b"
        ),
        severity="critical",
        min_entropy=2.0,
    ),
]
