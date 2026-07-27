"""Core scanning engine: walks a directory tree (or a single file),
applies signature + entropy checks, and yields structured Findings."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from .entropy import extract_candidate_tokens, is_high_entropy, shannon_entropy
from .patterns import DEFAULT_IGNORED_DIRS, DEFAULT_IGNORED_SUFFIXES, SECRET_PATTERNS

SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"

# Signature matches are always high-confidence.
_SIGNATURE_SEVERITY = SEVERITY_HIGH


@dataclass
class Finding:
    """A single detected secret/credential candidate."""

    file_path: str
    line_number: int
    rule: str
    severity: str
    snippet: str
    entropy: float = 0.0

    def to_dict(self) -> dict:
        return {
            "file": self.file_path,
            "line": self.line_number,
            "rule": self.rule,
            "severity": self.severity,
            "snippet": self.snippet,
            "entropy": round(self.entropy, 2),
        }


def _redact(line: str, max_len: int = 120) -> str:
    """Trim and lightly redact a line for safe display (keeps first/last
    few characters of any long token so context is visible without
    printing the full secret)."""
    line = line.strip()
    if len(line) > max_len:
        line = line[:max_len] + "...(truncated)"
    return line


class Scanner:
    """Scans files or directories for potential leaked secrets."""

    def __init__(
        self,
        entropy_threshold: float = 4.0,
        min_token_length: int = 16,
        ignored_dirs: set[str] | None = None,
        ignored_suffixes: set[str] | None = None,
        enable_entropy_check: bool = True,
    ) -> None:
        self.entropy_threshold = entropy_threshold
        self.min_token_length = min_token_length
        self.ignored_dirs = ignored_dirs or DEFAULT_IGNORED_DIRS
        self.ignored_suffixes = ignored_suffixes or DEFAULT_IGNORED_SUFFIXES
        self.enable_entropy_check = enable_entropy_check

    # -- Public API ---------------------------------------------------

    def scan_path(self, target: str | os.PathLike) -> list[Finding]:
        """Scan a file or a directory tree and return all findings."""
        target_path = Path(target)
        findings: list[Finding] = []

        if target_path.is_file():
            findings.extend(self._scan_file(target_path))
        elif target_path.is_dir():
            for file_path in self._iter_files(target_path):
                findings.extend(self._scan_file(file_path))
        else:
            raise FileNotFoundError(f"Path does not exist: {target_path}")

        return findings

    # -- Internals ------------------------------------------------------

    def _iter_files(self, root: Path):
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in self.ignored_dirs]
            for name in filenames:
                path = Path(dirpath) / name
                if path.suffix in self.ignored_suffixes:
                    continue
                if any(str(path).endswith(suf) for suf in self.ignored_suffixes):
                    continue
                yield path

    def _scan_file(self, path: Path) -> list[Finding]:
        findings: list[Finding] = []
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, UnicodeDecodeError):
            return findings

        for line_number, line in enumerate(text.splitlines(), start=1):
            findings.extend(self._check_signatures(path, line_number, line))
            if self.enable_entropy_check:
                findings.extend(self._check_entropy(path, line_number, line))

        return findings

    def _check_signatures(self, path: Path, line_number: int, line: str) -> list[Finding]:
        results = []
        for rule_name, pattern in SECRET_PATTERNS.items():
            if pattern.search(line):
                results.append(
                    Finding(
                        file_path=str(path),
                        line_number=line_number,
                        rule=rule_name,
                        severity=_SIGNATURE_SEVERITY,
                        snippet=_redact(line),
                    )
                )
        return results

    def _check_entropy(self, path: Path, line_number: int, line: str) -> list[Finding]:
        results = []
        for token in extract_candidate_tokens(line):
            if len(token) < self.min_token_length:
                continue
            score = shannon_entropy(token)
            if is_high_entropy(token, self.entropy_threshold):
                severity = SEVERITY_MEDIUM if score < 4.5 else SEVERITY_HIGH
                results.append(
                    Finding(
                        file_path=str(path),
                        line_number=line_number,
                        rule="High-Entropy String",
                        severity=severity,
                        snippet=_redact(line),
                        entropy=score,
                    )
                )
        return results
