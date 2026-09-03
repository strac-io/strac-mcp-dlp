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


# Types that are binary even though some decode as UTF-8 by accident. SVG is XML
# but Strac treats it as an image, and OOXML/PDF are containers.
BINARY_MEDIA_PREFIXES = ("image/", "audio/", "video/")
BINARY_MEDIA_TYPES = frozenset(
    {
        "application/pdf",
        "application/zip",
        "application/msword",
        "application/vnd.ms-excel",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "application/vnd.ms-outlook",
    }
)

# How much of a file to inspect for NUL bytes before deciding it is binary.
BINARY_SNIFF_BYTES = 8192


def _classify_document(content: bytes, media_type: str) -> tuple[Literal["text", "generic"], str]:
    """Decide whether Strac should treat this as `text` or `generic` (its image path).

    The filename's MIME type alone is not enough. `mimetypes` reports .json as
    application/json, .yaml as application/yaml, and .env, .toml, id_rsa and
    Dockerfile as application/octet-stream — so trusting it sends exactly the
    files most likely to hold credentials down the OCR path instead of the text
    path, and detection suffers. Sniff the bytes instead.

    Returns the document type and the media type to send with the content.
    """
    if media_type.startswith(BINARY_MEDIA_PREFIXES) or media_type in BINARY_MEDIA_TYPES:
        return "generic", media_type
    if b"\x00" in content[:BINARY_SNIFF_BYTES]:
        return "generic", media_type
    try:
        content.decode("utf-8")
    except UnicodeDecodeError:
        return "generic", media_type
    # Strac documents `text` as "all utf-8 encoded text files"; text/plain is the
    # unambiguous way to hand it one, whatever the extension implied.
    return "text", "text/plain"


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


# The live API and the published OpenAPI spec disagree on these names, and the two
# endpoints disagree with each other. Accept every spelling seen in either.
REDACTED_CONTENT_KEYS = ("redacted_content", "redactedContent")
DETECTED_ENTITY_KEYS = ("detected_entities", "detectedEntities")


def _first_present(payload: dict[str, Any], keys: tuple[str, ...]) -> tuple[str | None, Any]:
    for key in keys:
        if key in payload:
            return key, payload[key]
    return None, None


def _is_zero_span(entity: dict[str, Any]) -> bool:
    return entity.get("begin_index") == 0 and entity.get("end_index") == 0


def _drop_duplicate_zero_spans(entities: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse the duplicate zero-span detections /redact currently emits.

    Observed against the live API: every match is returned twice, once with a real
    begin/end span and once with begin_index == end_index == 0. Reporting both
    doubles detection_count, so an agent reading the result sees two SSNs where
    there is one. A zero-span entry is kept when nothing else reported that same
    type and value, so a finding is never dropped.
    """
    real = [e for e in entities if not _is_zero_span(e)]
    if not real:
        return entities
    covered = {(e.get("type"), e.get("text")) for e in real}
    orphans = [
        e for e in entities if _is_zero_span(e) and (e.get("type"), e.get("text")) not in covered
    ]
    return real + orphans


def _detection(
    entity: dict[str, Any], position: int, include_matched_text: bool, source: str
) -> dict[str, Any]:
    if not isinstance(entity, dict):
        raise StracError(
            f"Strac API returned a malformed detection at index {position} for "
            f"{source} ({type(entity).__name__}); refusing to drop it silently."
        )
    element_type = entity.get("type")
    if not isinstance(element_type, str) or not element_type:
        raise StracError(
            f"Strac API returned a detection with no data element type at index "
            f"{position} for {source}; refusing to drop it silently."
        )
    detection: dict[str, Any] = {"type": element_type}
    for span_key in ("begin_index", "end_index"):
        value = entity.get(span_key)
        if value is not None and not _is_zero_span(entity):
            detection[span_key] = value
    matched = entity.get("text")
    if matched is not None:
        matched = str(matched)
        if include_matched_text:
            detection["text"] = matched
        else:
            detection["length"] = len(matched)
    return detection


def _detections_from_entities(
    raw: Any, include_matched_text: bool, *, source: str
) -> list[dict[str, Any]]:
    """Normalise detections from either shape the API has been observed to return.

    `/redact` returns a list of {type, text, begin_index, end_index}. `/detect`
    returns a mapping of {TYPE: [value, ...]} with no offsets. The spec documents
    only the list form, so both are accepted — the mapping for what ships today,
    the list for whenever the API is brought in line with its docs.
    """
    if isinstance(raw, dict):
        entities: list[dict[str, Any]] = []
        for element_type, values in raw.items():
            if not isinstance(values, list):
                raise StracError(
                    f"Strac API returned `{element_type}` as {type(values).__name__} "
                    f"rather than a list of values for {source}."
                )
            entities.extend({"type": element_type, "text": value} for value in values)
    elif isinstance(raw, list):
        if all(isinstance(entity, dict) for entity in raw):
            entities = _drop_duplicate_zero_spans(raw)
        else:
            entities = raw  # _detection() raises on the malformed entry, naming its index
    else:
        raise StracError(
            f"Strac API returned detections as {type(raw).__name__} for {source}; "
            f"expected a list or a mapping. Refusing to report a clean scan."
        )
    return [
        _detection(entity, position, include_matched_text, source)
        for position, entity in enumerate(entities)
    ]


def _parse_redact_response(
    payload: dict[str, Any], original: str, include_matched_text: bool
) -> tuple[str, list[dict[str, Any]]]:
    """Read a /redact response, failing closed on anything unexpected.

    The redacted content proves the call succeeded, so its absence is an error.
    Detections are omitted entirely when nothing is found, so an absent key is a
    legitimate clean result — but only if the text came back unchanged. Text that
    was modified with nothing reported means findings went missing, which is
    exactly the silent failure a DLP tool must not have.
    """
    key, redacted = _first_present(payload, REDACTED_CONTENT_KEYS)
    if key is None or not isinstance(redacted, str):
        raise StracError(
            "Strac API response for redact_text contained no redacted content. "
            f"Keys returned: {sorted(payload)}"
        )
    entity_key, raw = _first_present(payload, DETECTED_ENTITY_KEYS)
    if entity_key is None:
        if redacted != original:
            raise StracError(
                "Strac API redacted the text but reported no detections, so the "
                "findings cannot be verified. Refusing to report a clean scan."
            )
        return redacted, []
    return redacted, _detections_from_entities(raw, include_matched_text, source="redact_text")


def _parse_detect_response(
    payload: dict[str, Any], include_matched_text: bool, *, source: str
) -> dict[str, Any]:
    """Read a /detect response, failing closed on anything unexpected.

    `containsPii` is the authoritative signal: the detections key is absent
    entirely on a clean scan, so its absence alone cannot be trusted to mean
    "nothing found".
    """
    contains = payload.get("containsPii")
    entity_key, raw = _first_present(payload, DETECTED_ENTITY_KEYS)

    if contains is None and entity_key is None:
        raise StracError(
            f"Strac API response for {source} contained neither `containsPii` nor "
            f"detections, so this is not a verified clean scan. "
            f"Keys returned: {sorted(payload)}"
        )
    if contains is False:
        if raw:
            raise StracError(
                f"Strac API reported containsPii=false for {source} but also returned "
                f"detections; refusing to guess which is correct."
            )
        detections: list[dict[str, Any]] = []
    elif entity_key is None:
        raise StracError(
            f"Strac API reported sensitive data for {source} but returned no "
            f"detections; refusing to report a clean scan."
        )
    else:
        detections = _detections_from_entities(raw, include_matched_text, source=source)

    result: dict[str, Any] = {
        "has_sensitive_data": bool(detections) or contains is True,
        "detection_count": len(detections),
        "data_element_types": sorted({d["type"] for d in detections}),
        "detections": detections,
    }
    # The same element is named differently in `piiElementTypes` and in the
    # detections themselves (SSN vs SOCIAL_SECURITY_NUMBER). Surface both rather
    # than silently picking one.
    reported = payload.get("piiElementTypes")
    if isinstance(reported, list) and reported:
        result["reported_element_types"] = sorted(str(r) for r in reported)
    return result


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
    redacted, detections = _parse_redact_response(payload, text, include_matched_text)
    return {
        "redacted_text": redacted,
        "redact_field_mode": redact_field_mode,
        "detection_count": len(detections),
        "data_element_types": sorted({d["type"] for d in detections}),
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
    return _parse_detect_response(payload, include_matched_text, source="detect_sensitive_data")


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
    document_type, upload_media_type = _classify_document(content, media_type)
    client = get_client()

    if len(content) <= MAX_INLINE_CONTENT_BYTES:
        stored_document_id = None
        payload = await client.detect_content(content, upload_media_type, document_type)
    else:
        uploaded = await client.upload_document(content, resolved.name, upload_media_type)
        stored_document_id = uploaded.get("id")
        payload = await client.detect_document(stored_document_id, document_type)

    result = _parse_detect_response(
        payload, include_matched_text, source=f"detect_file({resolved.name})"
    )
    return {
        "file": str(resolved),
        "media_type": media_type,
        "document_type": document_type,
        "size_bytes": len(content),
        "stored_document_id": stored_document_id,
        **result,
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
    document_type, upload_media_type = _classify_document(content, media_type)
    client = get_client()

    uploaded = await client.upload_document(content, resolved.name, upload_media_type)
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

    # For text documents the API returns the redacted content inline and never
    # publishes a downloadable copy — GET /redacted-documents/{id} 404s. Only fall
    # back to the download when nothing came back inline.
    _, inline = _first_present(result, REDACTED_CONTENT_KEYS)
    if isinstance(inline, str):
        redacted_bytes = inline.encode("utf-8")
    else:
        try:
            redacted_bytes, _ = await client.get_redacted_document(document_id)
        except StracError as exc:
            raise StracError(
                f"Strac redacted {resolved.name} (document {document_id}) but returned "
                f"neither inline content nor a downloadable document. Response keys: "
                f"{sorted(result)}. Underlying error: {exc}"
            ) from exc

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
