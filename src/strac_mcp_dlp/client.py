"""Thin async HTTP client for the Strac DLP API.

Every method maps 1:1 onto an endpoint documented at https://docs.strac.io.
No detection, classification or redaction logic lives here — the API does that work.
"""

from __future__ import annotations

import base64
from typing import Any

import httpx

from . import __version__
from .config import Config
from .errors import StracAPIError

# Endpoints that the Strac API exposes and this server wraps.
DOCUMENTS_PATH = "/documents"
DETECT_PATH = "/detect"
REDACT_PATH = "/redact"
REDACTED_DOCUMENT_PATH = "/redacted-documents/{document_id}"
DETOKENIZE_BATCH_PATH = "/tokens-detokenize/batch"

# Strac's own limits, documented on docs.strac.io. Enforced client-side so the
# agent gets a useful message instead of an opaque HTTP error.
MAX_INLINE_CONTENT_BYTES = 4 * 1024 * 1024  # /detect document_content
MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # POST /documents
MAX_DETOKENIZE_TOKENS = 10  # POST /tokens-detokenize/batch


def to_data_url(content: bytes, media_type: str) -> str:
    """Encode bytes as an RFC 2397 data URL, the shape `/detect` expects."""
    encoded = base64.b64encode(content).decode("ascii")
    return f"data:{media_type};base64,{encoded}"


class StracClient:
    def __init__(self, config: Config) -> None:
        self._config = config
        self._client: httpx.AsyncClient | None = None

    @property
    def api_base(self) -> str:
        return self._config.api_base

    async def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self._config.api_base,
                timeout=self._config.timeout,
                headers={
                    "X-Api-Key": self._config.api_key,
                    "User-Agent": f"strac-mcp-dlp/{__version__}",
                },
            )
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        http = await self._http()
        try:
            response = await http.request(method, path, **kwargs)
        except httpx.TimeoutException as exc:
            raise StracAPIError(
                f"Strac API request timed out after {self._config.timeout}s "
                f"({method} {path}). Raise STRAC_API_TIMEOUT if you are sending large documents."
            ) from exc
        except httpx.HTTPError as exc:
            raise StracAPIError(
                f"Could not reach the Strac API at {self._config.api_base}: {exc}"
            ) from exc

        if response.is_success:
            return response
        raise StracAPIError(self._describe_failure(response))

    def _describe_failure(self, response: httpx.Response) -> str:
        detail = response.text.strip()
        if len(detail) > 500:
            detail = detail[:500] + "…"
        hint = ""
        if response.status_code in (401, 403):
            hint = (
                " Check that STRAC_API_KEY is valid and matches the environment "
                f"({self._config.api_base}) — `sk_test_` keys only work against the "
                "sandbox and `sk_live_` keys only against production."
            )
        return (
            f"Strac API returned {response.status_code} for "
            f"{response.request.method} {response.request.url.path}."
            f"{hint} Response: {detail or '<empty>'}"
        )

    async def _json_post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        response = await self._request("POST", path, json=payload)
        try:
            body = response.json()
        except ValueError as exc:
            raise StracAPIError(f"Strac API returned a non-JSON response for POST {path}.") from exc
        return body if isinstance(body, dict) else {"result": body}

    # --- Endpoint wrappers -------------------------------------------------

    async def redact_text(
        self, content: str, redact_field_mode: str = "REDACTED"
    ) -> dict[str, Any]:
        """POST /redact (redactTextDocument) — inline text in, redacted text out."""
        return await self._json_post(
            REDACT_PATH,
            {
                "content": content,
                "type": "text",
                "redact_field_mode": redact_field_mode,
            },
        )

    async def detect_content(
        self, content: bytes, media_type: str, document_type: str
    ) -> dict[str, Any]:
        """POST /detect (detectDocument) with inline `document_content`."""
        if len(content) > MAX_INLINE_CONTENT_BYTES:
            raise StracAPIError(
                f"Content is {len(content)} bytes; the Strac /detect endpoint accepts at "
                f"most {MAX_INLINE_CONTENT_BYTES} bytes inline. Use detect_file, which "
                "uploads to the document vault first."
            )
        return await self._json_post(
            DETECT_PATH,
            {
                "document_type": document_type,
                "document_content": to_data_url(content, media_type),
            },
        )

    async def detect_document(self, document_id: str, document_type: str) -> dict[str, Any]:
        """POST /detect (detectDocument) against an already-uploaded document."""
        return await self._json_post(
            DETECT_PATH,
            {"document_type": document_type, "document_id": document_id},
        )

    async def upload_document(
        self, content: bytes, filename: str, media_type: str
    ) -> dict[str, Any]:
        """POST /documents (uploadDocument) — returns the vault document reference."""
        if len(content) > MAX_UPLOAD_BYTES:
            raise StracAPIError(
                f"File is {len(content)} bytes; the Strac document vault accepts at most "
                f"{MAX_UPLOAD_BYTES} bytes."
            )
        response = await self._request(
            "POST",
            DOCUMENTS_PATH,
            files={"document": (filename, content, media_type)},
        )
        return response.json()

    async def redact_document(self, document_id: str, document_type: str) -> dict[str, Any]:
        """POST /redact (redactDocument) — redacts a document already in the vault."""
        return await self._json_post(
            REDACT_PATH,
            {"document_id": document_id, "document_type": document_type},
        )

    async def get_redacted_document(self, document_id: str) -> tuple[bytes, str]:
        """GET /redacted-documents/{documentId} (getRedactedDocument)."""
        response = await self._request(
            "GET", REDACTED_DOCUMENT_PATH.format(document_id=document_id)
        )
        media_type = response.headers.get("content-type", "application/octet-stream")
        return response.content, media_type.split(";")[0].strip()

    async def detokenize(self, token_ids: list[str]) -> dict[str, Any]:
        """POST /tokens-detokenize/batch (detokenizeTokensBatch)."""
        if not token_ids:
            raise StracAPIError("Provide at least one token id to detokenize.")
        if len(token_ids) > MAX_DETOKENIZE_TOKENS:
            raise StracAPIError(
                f"The Strac detokenize endpoint accepts at most "
                f"{MAX_DETOKENIZE_TOKENS} tokens per call; got {len(token_ids)}."
            )
        return await self._json_post(
            DETOKENIZE_BATCH_PATH,
            {"tokens": [{"id": token_id} for token_id in token_ids]},
        )
