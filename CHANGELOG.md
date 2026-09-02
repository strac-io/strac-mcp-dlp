# Changelog

## 0.1.0

First release.

- MCP server over stdio (and streamable-http via `--transport`) wrapping the Strac DLP API.
- Tools: `redact_text`, `detect_pii`, `detect_file`, `redact_file`, `detokenize`.
- Detections omit the matched values by default, so redacting text does not return
  the same sensitive data to the model. Opt in with `include_matched_text`.
- API base URL is inferred from the key prefix (`sk_test_` → sandbox, `sk_live_` →
  production) and can be overridden with `STRAC_API_BASE`.
