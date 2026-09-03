import base64
import json

import httpx
import pytest
import respx

from strac_mcp_dlp.config import TEST_API_BASE
from strac_mcp_dlp.errors import StracAPIError, StracError
from strac_mcp_dlp.server import (
    detect_file,
    detect_sensitive_data,
    detokenize,
    redact_file,
    redact_text,
)

REDACT_URL = f"{TEST_API_BASE}/redact"
DETECT_URL = f"{TEST_API_BASE}/detect"
DOCUMENTS_URL = f"{TEST_API_BASE}/documents"

SSN_TEXT = "Please onboard the user with SSN 123-45-6789"

REDACT_RESPONSE = {
    "redactedContent": "Please onboard the user with SSN [REDACTED]",
    "detectedEntities": [
        {
            "type": "TAX_ID_NUMBER",
            "text": "123-45-6789",
            "begin_index": 33,
            "end_index": 44,
        }
    ],
}

DETECT_RESPONSE = {
    "detectedEntities": [
        {"type": "TAX_ID_NUMBER", "text": "123-45-6789"},
        {"type": "EMAIL", "text": "jane@example.com"},
    ]
}


@respx.mock
async def test_redact_text_hides_matches_by_default():
    route = respx.post(REDACT_URL).mock(return_value=httpx.Response(200, json=REDACT_RESPONSE))

    result = await redact_text(SSN_TEXT)

    assert route.called
    sent = json.loads(route.calls.last.request.content)
    assert sent == {
        "content": SSN_TEXT,
        "type": "text",
        "redact_field_mode": "REDACTED",
    }
    assert route.calls.last.request.headers["x-api-key"] == "sk_test_unit_testing_key"

    assert result["redacted_text"] == "Please onboard the user with SSN [REDACTED]"
    assert result["detection_count"] == 1
    assert result["data_element_types"] == ["TAX_ID_NUMBER"]
    detection = result["detections"][0]
    assert "text" not in detection
    assert detection["length"] == len("123-45-6789")
    assert detection["begin_index"] == 33
    assert "123-45-6789" not in json.dumps(result)


@respx.mock
async def test_redact_text_can_return_matches_on_request():
    respx.post(REDACT_URL).mock(return_value=httpx.Response(200, json=REDACT_RESPONSE))
    result = await redact_text(SSN_TEXT, include_matched_text=True)
    assert result["detections"][0]["text"] == "123-45-6789"


@respx.mock
async def test_redact_text_accepts_snake_case_field():
    respx.post(REDACT_URL).mock(
        return_value=httpx.Response(
            200, json={"redacted_content": "masked", "detectedEntities": []}
        )
    )
    result = await redact_text(SSN_TEXT)
    assert result["redacted_text"] == "masked"
    assert result["detection_count"] == 0


@respx.mock
async def test_redact_text_passes_field_mode():
    route = respx.post(REDACT_URL).mock(return_value=httpx.Response(200, json=REDACT_RESPONSE))
    await redact_text(SSN_TEXT, redact_field_mode="MASK_SEVEN_X")
    assert json.loads(route.calls.last.request.content)["redact_field_mode"] == "MASK_SEVEN_X"


@respx.mock
async def test_detect_sensitive_data_sends_text_as_data_url():
    route = respx.post(DETECT_URL).mock(return_value=httpx.Response(200, json=DETECT_RESPONSE))

    result = await detect_sensitive_data(SSN_TEXT)

    sent = json.loads(route.calls.last.request.content)
    assert sent["document_type"] == "text"
    prefix = "data:text/plain;base64,"
    assert sent["document_content"].startswith(prefix)
    decoded = base64.b64decode(sent["document_content"][len(prefix) :]).decode()
    assert decoded == SSN_TEXT

    assert result["has_sensitive_data"] is True
    assert result["data_element_types"] == ["EMAIL", "TAX_ID_NUMBER"]
    assert "123-45-6789" not in json.dumps(result)


@respx.mock
async def test_detect_sensitive_data_reports_clean_text():
    respx.post(DETECT_URL).mock(return_value=httpx.Response(200, json={"detectedEntities": []}))
    result = await detect_sensitive_data("the weather is fine")
    assert result["has_sensitive_data"] is False
    assert result["detections"] == []


async def test_empty_text_is_rejected_without_calling_the_api():
    with pytest.raises(StracError, match="nothing to redact"):
        await redact_text("")
    with pytest.raises(StracError, match="nothing to detect"):
        await detect_sensitive_data("")


@respx.mock
async def test_detect_file_inlines_small_files(tmp_path):
    target = tmp_path / "notes.txt"
    target.write_text(SSN_TEXT)
    route = respx.post(DETECT_URL).mock(return_value=httpx.Response(200, json=DETECT_RESPONSE))

    result = await detect_file(str(target))

    sent = json.loads(route.calls.last.request.content)
    assert sent["document_type"] == "text"
    assert "document_content" in sent
    assert result["stored_document_id"] is None
    assert result["file"] == str(target)
    assert result["detection_count"] == 2


@respx.mock
async def test_detect_file_uses_generic_for_images(tmp_path):
    target = tmp_path / "licence.png"
    target.write_bytes(b"\x89PNG\r\n\x1a\n fake image bytes")
    route = respx.post(DETECT_URL).mock(
        return_value=httpx.Response(200, json={"detectedEntities": []})
    )

    await detect_file(str(target))

    assert json.loads(route.calls.last.request.content)["document_type"] == "generic"


async def test_detect_file_rejects_missing_path(tmp_path):
    with pytest.raises(StracError, match="No such file"):
        await detect_file(str(tmp_path / "nope.txt"))


@respx.mock
async def test_redact_file_round_trip(tmp_path):
    target = tmp_path / "w2.png"
    target.write_bytes(b"\x89PNG original")

    respx.post(DOCUMENTS_URL).mock(
        return_value=httpx.Response(200, json={"id": "doc_abc", "size": 13})
    )
    respx.post(REDACT_URL).mock(return_value=httpx.Response(200, json={"status": "completed"}))
    respx.get(f"{TEST_API_BASE}/redacted-documents/doc_abc").mock(
        return_value=httpx.Response(
            200, content=b"\x89PNG redacted", headers={"content-type": "image/png"}
        )
    )

    result = await redact_file(str(target))

    assert result["document_id"] == "doc_abc"
    assert result["status"] == "completed"
    written = tmp_path / "w2.redacted.png"
    assert result["redacted_file"] == str(written)
    assert written.read_bytes() == b"\x89PNG redacted"
    assert target.read_bytes() == b"\x89PNG original"


@respx.mock
async def test_redact_file_surfaces_failed_status(tmp_path):
    target = tmp_path / "w2.png"
    target.write_bytes(b"\x89PNG original")
    respx.post(DOCUMENTS_URL).mock(return_value=httpx.Response(200, json={"id": "doc_abc"}))
    respx.post(REDACT_URL).mock(return_value=httpx.Response(200, json={"status": "failed"}))

    with pytest.raises(StracError, match="status 'failed'"):
        await redact_file(str(target))


@respx.mock
async def test_detokenize_batches_token_ids():
    route = respx.post(f"{TEST_API_BASE}/tokens-detokenize/batch").mock(
        return_value=httpx.Response(200, json={"tokens": [{"id": "tkn_1", "data": "111-22-3333"}]})
    )

    result = await detokenize(["tkn_1"])

    assert json.loads(route.calls.last.request.content) == {"tokens": [{"id": "tkn_1"}]}
    assert result["tokens"][0]["data"] == "111-22-3333"


async def test_detokenize_enforces_batch_limit():
    with pytest.raises(StracAPIError, match="at most 10 tokens"):
        await detokenize([f"tkn_{i}" for i in range(11)])


@respx.mock
async def test_auth_failure_explains_key_mismatch():
    respx.post(REDACT_URL).mock(return_value=httpx.Response(401, text="unauthorized"))
    with pytest.raises(StracAPIError, match="sk_test_"):
        await redact_text(SSN_TEXT)


async def test_missing_key_error_is_actionable(monkeypatch):
    """The spec'd onboarding message must reach the calling agent verbatim."""
    from strac_mcp_dlp import server as server_module
    from strac_mcp_dlp.errors import StracConfigError

    monkeypatch.delenv("STRAC_API_KEY", raising=False)
    server_module.reset_client()
    with pytest.raises(
        StracConfigError,
        match=r"Set STRAC_API_KEY — request one at https://www\.strac\.io/mcp-integrations",
    ):
        await redact_text("SSN 123-45-6789")


def test_strac_errors_reach_the_model():
    """MCP only forwards the message of a ToolError; anything else is a generic crash."""
    from mcp.server.mcpserver.exceptions import ToolError

    assert issubclass(StracError, ToolError)
    assert issubclass(StracAPIError, ToolError)
