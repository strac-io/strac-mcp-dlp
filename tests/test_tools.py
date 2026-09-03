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

# Shapes below are what the live sandbox API actually returns, captured with a real
# sk_test_ key. They differ from the published OpenAPI spec: /redact uses snake_case
# and repeats each match with a zero span, /detect returns a mapping plus containsPii
# and omits the detections key entirely when nothing is found.
REDACT_RESPONSE = {
    "redacted_content": "Please onboard the user with SSN [REDACTED]",
    "detected_entities": [
        # The API returns each match twice; this zero-span copy is the duplicate.
        {"type": "TAX_ID_NUMBER", "text": "123-45-6789", "begin_index": 0, "end_index": 0},
        {"type": "TAX_ID_NUMBER", "text": "123-45-6789", "begin_index": 33, "end_index": 44},
    ],
}

# The shape the OpenAPI spec documents. Accepted too, so the package keeps working
# if the API is ever brought in line with its docs.
REDACT_RESPONSE_AS_DOCUMENTED = {
    "redactedContent": "Please onboard the user with SSN [REDACTED]",
    "detectedEntities": [
        {"type": "TAX_ID_NUMBER", "text": "123-45-6789", "begin_index": 33, "end_index": 44},
    ],
}

REDACT_CLEAN_RESPONSE = {"redacted_content": "nothing to see here"}

DETECT_RESPONSE = {
    "containsPii": True,
    "piiElementTypes": ["CREDIT_DEBIT_NUMBER", "SSN"],
    "detectedEntities": {
        "SOCIAL_SECURITY_NUMBER": ["123-45-6789"],
        "EMAIL": ["jane@example.com"],
    },
    "shouldRedact": True,
    "status": "completed",
}

DETECT_CLEAN_RESPONSE = {
    "piiElementTypes": [],
    "containsPii": False,
    "shouldRedact": False,
    "status": "completed",
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
    assert result["data_element_types"] == ["EMAIL", "SOCIAL_SECURITY_NUMBER"]
    assert "123-45-6789" not in json.dumps(result)


@respx.mock
async def test_detect_sensitive_data_reports_clean_text():
    respx.post(DETECT_URL).mock(return_value=httpx.Response(200, json=DETECT_CLEAN_RESPONSE))
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
        return_value=httpx.Response(200, json=DETECT_CLEAN_RESPONSE)
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


# --- #3: fail closed on malformed API responses -----------------------------


@respx.mock
async def test_missing_detected_entities_is_an_error_not_a_clean_scan():
    """A response we cannot parse must never look like 'no sensitive data found'."""
    respx.post(DETECT_URL).mock(return_value=httpx.Response(200, json={"unexpected": 1}))
    with pytest.raises(StracError, match="not a verified clean scan"):
        await detect_sensitive_data(SSN_TEXT)


@respx.mock
async def test_null_detected_entities_is_an_error():
    respx.post(DETECT_URL).mock(return_value=httpx.Response(200, json={"detectedEntities": None}))
    with pytest.raises(StracError, match="expected a list or a mapping"):
        await detect_sensitive_data(SSN_TEXT)


@respx.mock
async def test_detected_entities_scalar_is_an_error():
    respx.post(DETECT_URL).mock(
        return_value=httpx.Response(200, json={"containsPii": True, "detectedEntities": "EMAIL"})
    )
    with pytest.raises(StracError, match="expected a list or a mapping"):
        await detect_sensitive_data(SSN_TEXT)


@respx.mock
async def test_detect_mapping_with_non_list_values_is_an_error():
    respx.post(DETECT_URL).mock(
        return_value=httpx.Response(
            200, json={"containsPii": True, "detectedEntities": {"EMAIL": "a@b.c"}}
        )
    )
    with pytest.raises(StracError, match="rather than a list of values"):
        await detect_sensitive_data(SSN_TEXT)


@respx.mock
async def test_malformed_detection_entry_is_not_silently_dropped():
    respx.post(DETECT_URL).mock(
        return_value=httpx.Response(
            200, json={"detectedEntities": [{"type": "EMAIL", "text": "a@b.c"}, "garbage"]}
        )
    )
    with pytest.raises(StracError, match="malformed detection at index 1"):
        await detect_sensitive_data(SSN_TEXT)


@respx.mock
async def test_detection_without_a_type_is_not_silently_dropped():
    respx.post(DETECT_URL).mock(
        return_value=httpx.Response(200, json={"detectedEntities": [{"text": "a@b.c"}]})
    )
    with pytest.raises(StracError, match="no data element type"):
        await detect_sensitive_data(SSN_TEXT)


@respx.mock
async def test_explicit_empty_list_is_still_a_valid_clean_scan():
    """Fail-closed must not turn a genuine clean result into an error."""
    respx.post(DETECT_URL).mock(return_value=httpx.Response(200, json=DETECT_CLEAN_RESPONSE))
    result = await detect_sensitive_data("the weather is fine")
    assert result["has_sensitive_data"] is False
    assert result["detections"] == []


@respx.mock
async def test_redact_text_also_fails_closed():
    respx.post(REDACT_URL).mock(
        return_value=httpx.Response(200, json={"redactedContent": "masked"})
    )
    with pytest.raises(StracError, match="redacted the text but reported no detections"):
        await redact_text(SSN_TEXT)


# --- #6: classify UTF-8 text correctly regardless of MIME guess -------------


@pytest.mark.parametrize(
    "filename",
    [
        "config.json",
        "creds.yaml",
        "app.yml",
        ".env",
        "id_rsa",
        "secrets.toml",
        "Dockerfile",
        "data.xml",
    ],
)
@respx.mock
async def test_utf8_config_files_use_the_text_path(tmp_path, filename):
    """These all guess as application/* and used to be sent down the OCR path."""
    target = tmp_path / filename
    target.write_text('{"aws_secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}')
    route = respx.post(DETECT_URL).mock(
        return_value=httpx.Response(200, json=DETECT_CLEAN_RESPONSE)
    )

    await detect_file(str(target))

    sent = json.loads(route.calls.last.request.content)
    assert sent["document_type"] == "text", f"{filename} should take the text path"
    assert sent["document_content"].startswith("data:text/plain;base64,")


@respx.mock
async def test_real_binary_still_uses_the_generic_path(tmp_path):
    target = tmp_path / "scan.png"
    target.write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR binary bytes")
    route = respx.post(DETECT_URL).mock(
        return_value=httpx.Response(200, json=DETECT_CLEAN_RESPONSE)
    )

    await detect_file(str(target))

    assert json.loads(route.calls.last.request.content)["document_type"] == "generic"


@respx.mock
async def test_undecodable_bytes_use_the_generic_path(tmp_path):
    target = tmp_path / "mystery.dat"
    target.write_bytes(b"\xff\xfe\xfd\xfc not valid utf-8")
    route = respx.post(DETECT_URL).mock(
        return_value=httpx.Response(200, json=DETECT_CLEAN_RESPONSE)
    )

    await detect_file(str(target))

    assert json.loads(route.calls.last.request.content)["document_type"] == "generic"


@respx.mock
async def test_pdf_uses_the_generic_path_even_though_it_may_decode(tmp_path):
    target = tmp_path / "w2.pdf"
    target.write_bytes(b"%PDF-1.4 mostly ascii header")
    route = respx.post(DETECT_URL).mock(
        return_value=httpx.Response(200, json=DETECT_CLEAN_RESPONSE)
    )

    await detect_file(str(target))

    assert json.loads(route.calls.last.request.content)["document_type"] == "generic"


@respx.mock
async def test_redact_file_classifies_by_content_too(tmp_path):
    target = tmp_path / "config.json"
    target.write_text('{"password": "hunter2"}')
    respx.post(DOCUMENTS_URL).mock(return_value=httpx.Response(200, json={"id": "doc_j"}))
    route = respx.post(REDACT_URL).mock(
        return_value=httpx.Response(200, json={"status": "completed"})
    )
    respx.get(f"{TEST_API_BASE}/redacted-documents/doc_j").mock(
        return_value=httpx.Response(200, content=b"{}", headers={"content-type": "text/plain"})
    )

    await redact_file(str(target))

    assert json.loads(route.calls.last.request.content)["document_type"] == "text"


# --- Behaviour pinned against the live API's real responses ------------------


@respx.mock
async def test_duplicate_zero_span_detections_are_collapsed():
    """The live /redact returns each match twice; counting both doubles the total."""
    respx.post(REDACT_URL).mock(return_value=httpx.Response(200, json=REDACT_RESPONSE))
    result = await redact_text(SSN_TEXT)
    assert result["detection_count"] == 1, "the zero-span duplicate must not be counted"
    assert result["detections"][0]["begin_index"] == 33


@respx.mock
async def test_zero_span_detection_is_kept_when_nothing_else_reports_it():
    """Dedupe must never lose a finding that only appears with a zero span."""
    respx.post(REDACT_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "redacted_content": "[REDACTED] and [REDACTED]",
                "detected_entities": [
                    {"type": "EMAIL", "text": "only@zero.span", "begin_index": 0, "end_index": 0},
                    {
                        "type": "TAX_ID_NUMBER",
                        "text": "123-45-6789",
                        "begin_index": 15,
                        "end_index": 26,
                    },
                ],
            },
        )
    )
    result = await redact_text(SSN_TEXT)
    assert result["detection_count"] == 2
    assert result["data_element_types"] == ["EMAIL", "TAX_ID_NUMBER"]


@respx.mock
async def test_documented_camelcase_shape_still_works():
    """Forward compatibility for if the API is brought in line with its spec."""
    respx.post(REDACT_URL).mock(
        return_value=httpx.Response(200, json=REDACT_RESPONSE_AS_DOCUMENTED)
    )
    result = await redact_text(SSN_TEXT)
    assert result["redacted_text"] == "Please onboard the user with SSN [REDACTED]"
    assert result["detection_count"] == 1


@respx.mock
async def test_redact_clean_text_with_no_entities_key_is_a_clean_scan():
    """/redact omits detections entirely when nothing is found."""
    respx.post(REDACT_URL).mock(return_value=httpx.Response(200, json=REDACT_CLEAN_RESPONSE))
    result = await redact_text("nothing to see here")
    assert result["redacted_text"] == "nothing to see here"
    assert result["detection_count"] == 0


@respx.mock
async def test_detect_surfaces_both_type_vocabularies():
    """piiElementTypes and the detection keys use different names for the same element."""
    respx.post(DETECT_URL).mock(return_value=httpx.Response(200, json=DETECT_RESPONSE))
    result = await detect_sensitive_data(SSN_TEXT)
    assert result["data_element_types"] == ["EMAIL", "SOCIAL_SECURITY_NUMBER"]
    assert result["reported_element_types"] == ["CREDIT_DEBIT_NUMBER", "SSN"]


@respx.mock
async def test_contains_pii_true_with_no_detections_is_an_error():
    respx.post(DETECT_URL).mock(
        return_value=httpx.Response(200, json={"containsPii": True, "piiElementTypes": ["SSN"]})
    )
    with pytest.raises(StracError, match="reported sensitive data .* but returned no"):
        await detect_sensitive_data(SSN_TEXT)


@respx.mock
async def test_contains_pii_false_with_detections_is_an_error():
    respx.post(DETECT_URL).mock(
        return_value=httpx.Response(
            200, json={"containsPii": False, "detectedEntities": {"EMAIL": ["a@b.c"]}}
        )
    )
    with pytest.raises(StracError, match="refusing to guess which is correct"):
        await detect_sensitive_data(SSN_TEXT)


@respx.mock
async def test_redact_file_uses_inline_content_when_returned(tmp_path):
    """Live /redact returns text redactions inline; the download endpoint 404s."""
    target = tmp_path / "config.json"
    target.write_text('{"ssn": "123-45-6789"}')
    respx.post(DOCUMENTS_URL).mock(return_value=httpx.Response(200, json={"id": "doc_i"}))
    respx.post(REDACT_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "redactedContent": '{"ssn": "[REDACTED]"}',
                "containsPii": True,
                "detectedEntities": {"SOCIAL_SECURITY_NUMBER": ["123-45-6789"]},
            },
        )
    )
    download = respx.get(f"{TEST_API_BASE}/redacted-documents/doc_i")

    result = await redact_file(str(target))

    assert not download.called, "must not hit the download endpoint when content is inline"
    written = tmp_path / "config.redacted.json"
    assert written.read_text() == '{"ssn": "[REDACTED]"}'
    assert result["redacted_file"] == str(written)


@respx.mock
async def test_error_body_with_success_status_is_treated_as_failure():
    """The API can return HTTP 200 with {"exceptionType": "InternalServerError"}."""
    respx.post(REDACT_URL).mock(
        return_value=httpx.Response(200, json={"exceptionType": "InternalServerError"})
    )
    with pytest.raises(StracAPIError, match="exceptionType"):
        await redact_text(SSN_TEXT)


@respx.mock
async def test_error_code_body_with_success_status_is_treated_as_failure():
    respx.post(DETECT_URL).mock(
        return_value=httpx.Response(200, json={"error_code": "InvalidDocumentId"})
    )
    with pytest.raises(StracAPIError, match="error_code"):
        await detect_sensitive_data(SSN_TEXT)
