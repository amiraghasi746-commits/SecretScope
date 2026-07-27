"""Renders scan findings as console text, JSON, or a standalone HTML report."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from .scanner import Finding

_SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}

_ANSI = {
    "HIGH": "\033[91m",
    "MEDIUM": "\033[93m",
    "LOW": "\033[94m",
    "RESET": "\033[0m",
    "BOLD": "\033[1m",
}


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (_SEVERITY_ORDER.get(f.severity, 9), f.file_path, f.line_number))


def render_console(findings: list[Finding], use_color: bool = True) -> str:
    findings = sort_findings(findings)
    if not findings:
        return "No potential secrets found. \u2705"

    lines = []
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
        color = _ANSI.get(f.severity, "") if use_color else ""
        reset = _ANSI["RESET"] if use_color else ""
        lines.append(
            f"{color}[{f.severity}]{reset} {f.file_path}:{f.line_number} - {f.rule}\n"
            f"    {f.snippet}"
        )

    summary = (
        f"\nFound {len(findings)} potential issue(s): "
        f"{counts.get('HIGH', 0)} HIGH, {counts.get('MEDIUM', 0)} MEDIUM, {counts.get('LOW', 0)} LOW"
    )
    return "\n".join(lines) + "\n" + summary


def render_json(findings: list[Finding], target: str) -> str:
    payload = {
        "tool": "SecretScope",
        "scanned_target": target,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "finding_count": len(findings),
        "findings": [f.to_dict() for f in sort_findings(findings)],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def render_html(findings: list[Finding], target: str) -> str:
    findings = sort_findings(findings)
    rows = "\n".join(
        f"""<tr class="sev-{f.severity.lower()}">
                <td>{f.severity}</td>
                <td><code>{_escape(f.file_path)}:{f.line_number}</code></td>
                <td>{_escape(f.rule)}</td>
                <td><code>{_escape(f.snippet)}</code></td>
                <td>{f.entropy:.2f}</td>
            </tr>"""
        for f in findings
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SecretScope Report</title>
<style>
  body {{ font-family: 'Segoe UI', Tahoma, sans-serif; background: #0f1117; color: #e6e6e6; margin: 2rem; }}
  h1 {{ color: #4fd1c5; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 1.5rem; }}
  th, td {{ padding: 0.6rem; border-bottom: 1px solid #2a2f3a; text-align: left; font-size: 0.9rem; }}
  th {{ background: #1a1d27; color: #9aa5b1; text-transform: uppercase; font-size: 0.75rem; }}
  code {{ color: #f6ad55; word-break: break-all; }}
  .sev-high td:first-child {{ color: #fc8181; font-weight: bold; }}
  .sev-medium td:first-child {{ color: #f6e05e; font-weight: bold; }}
  .sev-low td:first-child {{ color: #63b3ed; font-weight: bold; }}
  .meta {{ color: #9aa5b1; font-size: 0.85rem; }}
</style>
</head>
<body>
  <h1>SecretScope Scan Report</h1>
  <p class="meta">Target: <code>{_escape(target)}</code> &middot; Generated: {datetime.now(timezone.utc).isoformat()} &middot; {len(findings)} finding(s)</p>
  <table>
    <thead>
      <tr><th>Severity</th><th>Location</th><th>Rule</th><th>Snippet</th><th>Entropy</th></tr>
    </thead>
    <tbody>
      {rows if findings else '<tr><td colspan="5">No potential secrets found.</td></tr>'}
    </tbody>
  </table>
</body>
</html>"""


def _escape(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
