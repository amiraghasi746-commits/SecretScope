"""Command-line interface for SecretScope."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .reporter import render_console, render_html, render_json
from .scanner import Scanner


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secretscope",
        description="Scan a file or directory for leaked secrets, API keys, and credentials.",
    )
    parser.add_argument("target", help="File or directory path to scan")
    parser.add_argument(
        "-o", "--output",
        choices=["console", "json", "html"],
        default="console",
        help="Output format (default: console)",
    )
    parser.add_argument(
        "-f", "--output-file",
        help="Write report to this file instead of stdout (required for html/json if you want a saved file)",
    )
    parser.add_argument(
        "--entropy-threshold",
        type=float,
        default=4.0,
        help="Shannon entropy threshold for generic secret detection (default: 4.0)",
    )
    parser.add_argument(
        "--no-entropy",
        action="store_true",
        help="Disable entropy-based detection; use signature rules only",
    )
    parser.add_argument(
        "--ai",
        action="store_true",
        help="Send a summary of findings to the Claude API for a plain-language risk explanation "
             "(requires ANTHROPIC_API_KEY)",
    )
    parser.add_argument(
        "--fail-on-findings",
        action="store_true",
        help="Exit with a non-zero status code if any findings are detected (useful for CI pipelines)",
    )
    parser.add_argument("--version", action="version", version=f"SecretScope {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    scanner = Scanner(
        entropy_threshold=args.entropy_threshold,
        enable_entropy_check=not args.no_entropy,
    )

    try:
        findings = scanner.scan_path(args.target)
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    if args.output == "json":
        report = render_json(findings, args.target)
    elif args.output == "html":
        report = render_html(findings, args.target)
    else:
        report = render_console(findings)

    if args.output_file:
        Path(args.output_file).write_text(report, encoding="utf-8")
        print(f"Report written to {args.output_file}")
    else:
        print(report)

    if args.ai:
        from .ai_analyzer import AIAnalyzerError, analyze_findings

        print("\n--- AI Risk Analysis (Claude) ---")
        try:
            print(analyze_findings(findings))
        except AIAnalyzerError as exc:
            print(f"[AI analysis skipped] {exc}")

    if args.fail_on_findings and findings:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
