"""Errors surfaced to the MCP client as tool errors.

These subclass the SDK's `ToolError` deliberately: the MCP server only forwards
the message of a `ToolError` to the caller. Any other exception is treated as a
crash and reaches the model as a generic "Error executing tool …", which would
hide the very hints — set your API key, check your key's environment — that make
these errors worth raising.
"""

from mcp.server.mcpserver.exceptions import ToolError


class StracError(ToolError):
    """Base error. The message is shown verbatim to the calling agent."""


class StracConfigError(StracError):
    """The server is missing configuration (typically STRAC_API_KEY)."""


class StracAPIError(StracError):
    """The Strac API returned a non-success response."""
