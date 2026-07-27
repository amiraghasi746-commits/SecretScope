"""Optional AI-powered risk analysis using the Anthropic Claude API.

This module is entirely optional. SecretScope works fully offline using
signature + entropy detection; this adds a plain-language risk summary
and remediation advice on top of the findings, when an API key is
available.

Set the ANTHROPIC_API_KEY environment variable to enable this feature.
"""

from __future__ import annotations

import os

from .scanner import Finding

_SYSTEM_PROMPT = (
    "You are a senior application security engineer. You will be given a "
    "list of potential secret/credential findings from a static scan of a "
    "code repository. For each distinct rule type present, briefly explain "
    "the real-world risk if it were a genuine leaked secret, and give one "
    "concrete remediation step (e.g. rotate the key, move to env vars/secret "
    "manager, add to .gitignore). Be concise: use short bullet points, no "
    "more than 200 words total. Do not repeat the raw findings back verbatim."
)


class AIAnalyzerError(RuntimeError):
    """Raised when the AI analysis step cannot be completed."""


def is_available() -> bool:
    """Whether an Anthropic API key is configured in the environment."""
    return bool(os.environ.get("ANTHROPIC_API_KEY"))


def analyze_findings(findings: list[Finding], model: str = "claude-sonnet-4-6") -> str:
    """Send a summary of findings to the Claude API and return a
    plain-language risk assessment. Requires the `anthropic` package and
    the ANTHROPIC_API_KEY environment variable.

    Raises:
        AIAnalyzerError: if the SDK is missing, the API key is unset, or
            the API call fails for any reason.
    """
    if not findings:
        return "No findings to analyze."

    if not is_available():
        raise AIAnalyzerError(
            "ANTHROPIC_API_KEY is not set. Export it in your environment "
            "to enable AI-powered risk analysis."
        )

    try:
        import anthropic
    except ImportError as exc:
        raise AIAnalyzerError(
            "The 'anthropic' package is not installed. Run: pip install anthropic"
        ) from exc

    rule_summary: dict[str, int] = {}
    for f in findings:
        rule_summary[f.rule] = rule_summary.get(f.rule, 0) + 1

    summary_text = "\n".join(f"- {rule}: {count} occurrence(s)" for rule, count in rule_summary.items())

    try:
        client = anthropic.Anthropic()
        response = client.messages.create(
            model=model,
            max_tokens=600,
            system=_SYSTEM_PROMPT,
            messages=[
                {
                    "role": "user",
                    "content": f"Findings summary from a repository scan:\n{summary_text}",
                }
            ],
        )
        text_blocks = [block.text for block in response.content if getattr(block, "type", "") == "text"]
        return "\n".join(text_blocks).strip() or "No analysis text returned."
    except Exception as exc:  # noqa: BLE001 - surface any API/SDK error uniformly
        raise AIAnalyzerError(f"Claude API call failed: {exc}") from exc
