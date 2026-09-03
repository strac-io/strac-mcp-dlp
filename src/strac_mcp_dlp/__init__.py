"""Strac MCP DLP — PII/PHI/PCI & secret redaction for AI agents, over MCP.

A thin MCP wrapper around the Strac Data Loss Prevention API (https://docs.strac.io).
All detection and redaction happens in the Strac API; this package only speaks
MCP on one side and HTTPS to Strac on the other.
"""

__version__ = "0.1.1"

__all__ = ["__version__"]
