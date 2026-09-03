"""MCP server exposing Strac's detection and redaction API as tools.

Transport: stdio (the default) or streamable-http, selected with --transport.
"""

from __future__ import annotations

import argparse
import mimetypes
import os
from pathlib import Path
from typing import Any, Literal

from mcp.server.mcpserver import MCPServer

from . import __version__
from .client import MAX_INLINE_CONTENT_BYTES, StracClient
from .config import Config
from .errors import StracError

INSTRUCTIONS = """\
Strac DLP finds and redacts sensitive data — PII, PHI, PCI and secrets — in text
and documents, by calling the Strac API.

Use `redact_text` before passing user- or tool-supplied text into a prompt, a log,
a ticket or a downstream system. Use `detect_sensitive_data` when you only need to know
whether sensitive data is present. Use `detect_file` / `redact_file` for images,
PDFs and other documents on disk.

By default these tools do NOT return the sensitive values they found — only the
data element types and their positions — so that redacting text does not leak the
same data back into the conversation. Pass include_matched_text=true only when the
caller genuinely needs the raw values.
"""

REDACT_FIELD_MODES = ("BLANK", "MASK_SEVEN_X", "REDACTED", "TOKEN_LINK_PLAINTEXT")

server = MCPServer(
    name="strac-mcp-dlp",
    title="Strac MCP DLP",
    version=__version__,
    instructions=INSTRUCTIONS,
    website_url="https://www.strac.io/mcp-integrations",
)

_client: StracClient | None = None


def get_client() -> StracClient:
    """Build the API client lazily so the server starts even without a key set."""
    global _client
    if _client is None:
        _client = StracClient(Config.from_env())
    return _client


def reset_client() -> None:
    """Drop the cached client. Used by tests."""
    global _client
    _client = None


def _document_type_for(media_type: str) -> Literal["text", "generic"]:
    """Strac takes `text` for utf-8 text and `generic` for everything else."""
    return "text" if media_type.startswith("text/") else "generic"


def _resolve_file(path: str) -> tuple[Path, bytes, str]:
    resolved = Path(path).expanduser()
    if not resolved.is_absolute():
        resolved = (Path.cwd() / resolved).resolve()
    if not resolved.exists():
        raise StracError(f"No such file: {resolved}")
    if not resolved.is_file():
        raise StracError(f"Not a file: {resolved}")
    media_type = mimetypes.guess_type(resolved.name)[0] or "application/octet-stream"
    return resolved, resolved.read_bytes(), media_type


def _format_detections(raw: Any, include_matched_text: bool) -> list[dict[str, Any]]:
    """Normalise `detectedEntities` into a stable shape, redacting matches by default."""
    detections: list[dict[str, Any]] = []
    for entity in raw or []:
        if not isinstance(entity, dict):
            continue
        detection: dict[str, Any] = {"type": entity.get("type")}
        begin = entity.get("begin_index")
        end = entity.get("end_index")
        if begin is not None:
            detection["begin_index"] = begin
        if end is not None:
            detection["end_index"] = end
        matched = entity.get("text")
        if matched is not None:
            matched = str(matched)
            if include_matched_text:
                detection["text"] = matched
            else:
                detection["length"] = len(matched)
        detections.append(detection)
    return detections


def _redacted_content(payload: dict[str, Any]) -> str:
    """The API has shipped this field under both spellings; accept either."""
    for key in ("redactedContent", "redacted_content"):
        value = payload.get(key)
        if isinstance(value, str):
            return value
    raise StracError(
        f"The Strac API response did not contain redacted content. Keys returned: {sorted(payload)}"
    )


@server.tool(
    title="Redact sensitive data from text",
    description=(
        "Redact PII, PHI, PCI and secrets out of a block of text using Strac DLP. "
        "Returns the redacted text plus the data element types that were found. "
        "Call this before putting untrusted or user-supplied text into a prompt, "
        "a log line, a ticket or any downstream system."
    ),
)
async def redact_text(
    text: str,
    redact_field_mode: Literal[
        "REDACTED", "BLANK", "MASK_SEVEN_X", "TOKEN_LINK_PLAINTEXT"
    ] = "REDACTED",
    include_matched_text: bool = False,
) -> dict[str, Any]:
    """Redact sensitive data in `text`.

    Args:
        text: The text to redact.
        redact_field_mode: How each match is replaced. REDACTED writes `[REDACTED]`,
            BLANK removes it, MASK_SEVEN_X writes `XXXXXXX`, and TOKEN_LINK_PLAINTEXT
            writes a link to the value in the Strac vault so an authorised human can
            still retrieve it.
        include_matched_text: Return the raw sensitive values alongside the redacted
            text. Off by default so redaction does not leak the data back to the model.
    """
    if not text:
        raise StracError("`text` is empty — nothing to redact.")
    payload = await get_client().redact_text(text, redact_field_mode)
    detections = _format_detections(payload.get("detectedEntities"), include_matched_text)
    return {
        "redacted_text": _redacted_content(payload),
        "redact_field_mode": redact_field_mode,
        "detection_count": len(detections),
        "data_element_types": sorted({d["type"] for d in detections if d.get("type")}),
        "detections": detections,
    }


@server.tool(
    title="Detect sensitive data in text",
    description=(
        "Detect sensitive data in text without changing it — personal data (PII), "
        "health data (PHI), payment and card data (PCI), and credentials such as API "
        "keys, cloud access keys, tokens and connection strings. Returns the data "
        "element types Strac found. Use this to decide whether text is safe to send "
        "onward; use redact_text when you need the sanitised text itself."
    ),
)
async def detect_sensitive_data(
    text: str,
    include_matched_text: bool = False,
) -> dict[str, Any]:
    """Detect sensitive data in `text` without redacting it.

    Args:
        text: The text to scan.
        include_matched_text: Return the raw sensitive values that were detected.
            Off by default.
    """
    if not text:
        raise StracError("`text` is empty — nothing to detect.")
    payload = await get_client().detect_content(text.encode("utf-8"), "text/plain", "text")
    detections = _format_detections(payload.get("detectedEntities"), include_matched_text)
    return {
        "has_sensitive_data": bool(detections),
        "detection_count": len(detections),
        "data_element_types": sorted({d["type"] for d in detections if d.get("type")}),
        "detections": detections,
    }


@server.tool(
    title="Detect sensitive data in a file",
    description=(
        "Detect PII, PHI, PCI and secrets in a local file — image, PDF, scan or text. "
        "Strac runs OCR on images and scanned documents. Returns the data element "
        "types found, without modifying the file."
    ),
)
async def detect_file(
    path: str,
    include_matched_text: bool = False,
) -> dict[str, Any]:
    """Detect sensitive data in the file at `path`.

    Files under 4 MB are sent inline and are not stored in the Strac vault. Larger
    files (up to 10 MB) are uploaded to the vault first, because that is the only
    way the Strac API accepts them.

    Args:
        path: Path to the file to scan.
        include_matched_text: Return the raw sensitive values that were detected.
            Off by default.
    """
    resolved, content, media_type = _resolve_file(path)
    document_type = _document_type_for(media_type)
    client = get_client()

    if len(content) <= MAX_INLINE_CONTENT_BYTES:
        stored_document_id = None
        payload = await client.detect_content(content, media_type, document_type)
    else:
        uploaded = await client.upload_document(content, resolved.name, media_type)
        stored_document_id = uploaded.get("id")
        payload = await client.detect_document(stored_document_id, document_type)

    detections = _format_detections(payload.get("detectedEntities"), include_matched_text)
    return {
        "file": str(resolved),
        "media_type": media_type,
        "size_bytes": len(content),
        "stored_document_id": stored_document_id,
        "has_sensitive_data": bool(detections),
        "detection_count": len(detections),
        "data_element_types": sorted({d["type"] for d in detections if d.get("type")}),
        "detections": detections,
    }


@server.tool(
    title="Redact a file",
    description=(
        "Redact PII, PHI, PCI and secrets out of a local file — image, PDF, scan or "
        "text — and write the redacted copy to disk. The original is never modified. "
        "Returns the path to the redacted file."
    ),
)
async def redact_file(
    path: str,
    output_path: str | None = None,
) -> dict[str, Any]:
    """Redact the file at `path` and save the result.

    The file is uploaded to the Strac document vault, redacted there, and the
    redacted copy downloaded back. The original document stays in the vault so it
    remains retrievable by authorised users.

    Args:
        path: Path to the file to redact.
        output_path: Where to write the redacted copy. Defaults to the original
            name with a `.redacted` suffix, next to the original.
    """
    resolved, content, media_type = _resolve_file(path)
    document_type = _document_type_for(media_type)
    client = get_client()

    uploaded = await client.upload_document(content, resolved.name, media_type)
    document_id = uploaded.get("id")
    if not document_id:
        raise StracError(f"Strac did not return a document id for {resolved.name}: {uploaded}")

    result = await client.redact_document(document_id, document_type)
    status = result.get("status")
    if status == "failed":
        raise StracError(
            f"Strac could not redact {resolved.name} (document {document_id}); "
            "the API reported status 'failed'."
        )

    redacted_bytes, _ = await client.get_redacted_document(document_id)

    destination = (
        Path(output_path).expanduser()
        if output_path
        else resolved.with_suffix(f".redacted{resolved.suffix}")
    )
    if not destination.is_absolute():
        destination = (Path.cwd() / destination).resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(redacted_bytes)

    return {
        "source_file": str(resolved),
        "redacted_file": str(destination),
        "document_id": document_id,
        "status": status,
        "size_bytes": len(redacted_bytes),
    }


@server.tool(
    title="Detokenize Strac tokens",
    description=(
        "Resolve Strac vault tokens (tkn_…) back to their original values. Use this "
        "only when the caller is authorised to see the raw sensitive data. Accepts up "
        "to 10 tokens per call and requires an IP-allowlisted server-to-server key in "
        "live mode."
    ),
)
async def detokenize(token_ids: list[str]) -> dict[str, Any]:
    """Resolve Strac tokens back to the original sensitive values.

    Args:
        token_ids: Token identifiers, e.g. `tkn_jgP1m98fdsnzBQh43uzCpt`. Maximum 10.
    """
    payload = await get_client().detokenize(token_ids)
    return {"tokens": payload.get("tokens", [])}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="strac-mcp-dlp",
        description="MCP server for Strac DLP — PII/PHI/PCI and secret redaction.",
    )
    parser.add_argument("--version", action="version", version=f"strac-mcp-dlp {__version__}")
    parser.add_argument(
        "--transport",
        choices=["stdio", "streamable-http"],
        default=os.environ.get("STRAC_MCP_TRANSPORT", "stdio"),
        help="MCP transport to serve. Defaults to stdio.",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    server.run(transport=args.transport)


if __name__ == "__main__":
    main()
