"""
SecretScope
~~~~~~~~~~~

A pure-Python, dependency-light secret & credential leak scanner for
source code repositories. Combines regex signature matching with
Shannon-entropy analysis to catch both known secret formats (AWS keys,
GitHub tokens, private keys, etc.) and generic high-entropy strings
that look like leaked credentials, API keys, or tokens.

Optionally sends flagged findings to the Anthropic Claude API for a
plain-language risk explanation and remediation suggestion.
"""

__version__ = "1.0.0"
__author__ = "Amir"
__license__ = "MIT"

from .scanner import Scanner, Finding
from .entropy import shannon_entropy

__all__ = ["Scanner", "Finding", "shannon_entropy", "shannon_entropy"]
