# Changelog

## 0.1.1

- Response parsing rewritten against the live Strac API, which differs from the
  published OpenAPI spec: `/redact` returns snake_case keys and repeats each match
  with a zero span, `/detect` returns a mapping plus `containsPii` and omits the
  detections key on a clean scan, and `/redact` with a `document_id` returns content
  inline rather than publishing a downloadable document.
- Fails closed. A response that cannot be parsed raises instead of reporting a clean
  scan, and an HTTP 200 carrying `exceptionType` or `error_code` is treated as failure.
- Text files are classified by content rather than by filename, so `.env`, `.json`,
  `.yaml`, `.toml` and `id_rsa` take Strac's text path instead of its image path.
- `redact_file` refuses an `output_path` that resolves to the source file, including
  through a symlink, and will not replace an existing file without `overwrite=true`.
  The destination is settled before upload, so a bad request leaves nothing in the vault.
- `detect_pii` renamed to `detect_sensitive_data`; it detects PHI, PCI, credentials and
  secrets, not only PII. **Breaking.**
- File size is checked with `stat()` before the file is read into memory.
- `detect_file` verifies the upload returned a document id.
- Added an icon to the registry manifest, an FAQ to the README, and reformatted the
  tool list so directory scrapers can extract it.

## 0.1.0

First release.

- MCP server over stdio (and streamable-http via `--transport`) wrapping the Strac DLP API.
- Tools: `redact_text`, `detect_sensitive_data`, `detect_file`, `redact_file`, `detokenize`.
- Detections omit the matched values by default, so redacting text does not return
  the same sensitive data to the model. Opt in with `include_matched_text`.
- API base URL is inferred from the key prefix (`sk_test_` → sandbox, `sk_live_` →
  production) and can be overridden with `STRAC_API_BASE`.
