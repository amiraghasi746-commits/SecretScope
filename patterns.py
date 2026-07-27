"""Signature patterns for well-known secret/credential formats.

Each entry maps a human-readable name to a compiled regex. These are
checked before falling back to generic entropy-based detection, since
signature matches are cheap and have near-zero false-positive rates.
"""

from __future__ import annotations

import re

SECRET_PATTERNS: dict[str, re.Pattern] = {
    "AWS Access Key ID": re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    "AWS Secret Access Key": re.compile(
        r"(?i)aws(.{0,20})?(secret|access)?(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]"
    ),
    "GitHub Personal Access Token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"),
    "GitHub Fine-Grained Token": re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,255}\b"),
    "Slack Token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,72}\b"),
    "Slack Webhook": re.compile(
        r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]{8,}/B[A-Za-z0-9_]{8,}/[A-Za-z0-9_]{24,}"
    ),
    "Google API Key": re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    "Anthropic API Key": re.compile(r"\bsk-ant-[A-Za-z0-9\-_]{20,120}\b"),
    "OpenAI API Key": re.compile(r"\bsk-[A-Za-z0-9]{20,64}\b"),
    "Groq API Key": re.compile(r"\bgsk_[A-Za-z0-9]{20,80}\b"),
    "Stripe Secret Key": re.compile(r"\b(sk|rk)_(live|test)_[0-9a-zA-Z]{16,}\b"),
    "Private Key Block": re.compile(
        r"-----BEGIN (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----"
    ),
    "Generic Bearer Token": re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{20,}"),
    "JWT": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    "Generic API Key/Secret Assignment": re.compile(
        r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|pwd)"
        r"\s*[:=]\s*['\"][^'\"\s]{8,}['\"]"
    ),
    "Database Connection String": re.compile(
        r"(?i)(postgres|postgresql|mysql|mongodb(\+srv)?|redis)://[^:\s]+:[^@\s]+@[^\s'\"]+"
    ),
}

# File extensions/names that are almost always noise for secret scanning
# (lockfiles, minified assets, binaries) and can be skipped by default.
DEFAULT_IGNORED_SUFFIXES = {
    ".lock", ".min.js", ".map", ".png", ".jpg", ".jpeg", ".gif", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".zip", ".tar", ".gz", ".pdf",
    ".pyc", ".so", ".dll", ".exe", ".class", ".jar",
}

DEFAULT_IGNORED_DIRS = {
    ".git", "node_modules", "venv", ".venv", "__pycache__",
    "dist", "build", ".mypy_cache", ".pytest_cache", "site-packages",
}
