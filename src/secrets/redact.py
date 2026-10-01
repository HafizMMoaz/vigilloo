"""Secret redaction utilities to ensure secrets are never leaked in plaintext."""

_KNOWN_PREFIXES = (
    "sk_live_",
    "sk_test_",
    "rk_live_",
    "rk_test_",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "github_pat_",
    "xoxb-",
    "xoxp-",
    "AKIA",
    "AIza",
)


def redact_secret(secret: str) -> str:
    """Mask a secret string so the sensitive content is never exposed.

    Preserves provider prefixes for triage recognition, masking secret payload with asterisks.
    """
    secret = secret.strip()
    if not secret:
        return ""

    for prefix in _KNOWN_PREFIXES:
        if secret.startswith(prefix):
            prefix_len = len(prefix)
            suffix_len = min(2, max(0, len(secret) - prefix_len - 4))
            mask_len = len(secret) - prefix_len - suffix_len
            suffix = secret[-suffix_len:] if suffix_len > 0 else ""
            return f"{prefix}{'*' * mask_len}{suffix}"

    length = len(secret)
    if length <= 6:
        return "*" * length

    prefix_len = min(4, length // 3)
    suffix_len = min(2, (length - prefix_len) // 3)
    mask_len = length - prefix_len - suffix_len

    return f"{secret[:prefix_len]}{'*' * mask_len}{secret[-suffix_len:] if suffix_len > 0 else ''}"
