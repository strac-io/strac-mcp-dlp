# Strac MCP DLP — PII/PHI/PCI & secret redaction for AI agents (MCP)

An open-source [Model Context Protocol](https://modelcontextprotocol.io) server that gives any AI agent — Claude, Cursor, VS Code, your own — a way to **find and strip sensitive data before it reaches the model.**

Point your agent at it, and `redact_text` turns

```
Please onboard the user with SSN 123-45-6789 and email jane@acme.com
```

into

```
Please onboard the user with SSN [REDACTED] and email [REDACTED]
```

...along with a structured list of what was found. It works the same on images, PDFs and scanned documents.

This is a thin client over the [Strac DLP API](https://docs.strac.io). Bring your own API key; all detection and redaction happens server-side at Strac.

---

## Why

Agents are now wired into inboxes, ticketing systems, CRMs, databases and file stores. Every MCP tool call is a chance for an SSN, a card number, a patient record or an AWS key to be pulled into a prompt — and from there into a model provider's logs, a vector store, a Slack summary or a support ticket.

Filtering that data *after* the model has seen it is too late. This server puts the check in front of the model: detect first, redact, then let the agent reason over text that no longer carries the sensitive values.

---

## 60-second quickstart

**1. Install**

```bash
pip install strac-mcp-dlp
```

**2. Get an API key**

Grab one at [strac.io/mcp-integrations](https://www.strac.io/mcp-integrations). Keys are prefixed `sk_live_` (production) or `sk_test_` (sandbox); the server picks the right endpoint automatically.

**3. Add it to your MCP client**

Claude Desktop — `~/Library/Application Support/Claude/claude_desktop_config.json` on macOS, `%APPDATA%\Claude\claude_desktop_config.json` on Windows:

```json
{
  "mcpServers": {
    "strac-dlp": {
      "command": "strac-mcp-dlp",
      "env": {
        "STRAC_API_KEY": "sk_live_your_key_here"
      }
    }
  }
}
```

Claude Code:

```bash
claude mcp add strac-dlp --env STRAC_API_KEY=sk_live_your_key_here -- strac-mcp-dlp
```

Cursor — `.cursor/mcp.json` in your project, or `~/.cursor/mcp.json` globally: use the same block as Claude Desktop.

**4. Restart your client and ask it to redact something**

> Use Strac to redact this before I paste it into the ticket: "Customer Jane Doe, SSN 123-45-6789, card 4111 1111 1111 1111."

No install at all, if you have [uv](https://docs.astral.sh/uv/):

```json
{
  "mcpServers": {
    "strac-dlp": {
      "command": "uvx",
      "args": ["strac-mcp-dlp"],
      "env": { "STRAC_API_KEY": "sk_live_your_key_here" }
    }
  }
}
```

See [`examples/`](examples/) for ready-to-copy config files.

---

## Tools

| Tool | What it does | Example |
| --- | --- | --- |
| `redact_text` | Redacts PII/PHI/PCI out of a block of text and returns the sanitised string plus what was found. | `redact_text(text="SSN 123-45-6789")` → `"SSN [REDACTED]"` |
| `detect_pii` | Scans text and reports which sensitive data types are present, without changing it. | `detect_pii(text="call me at jane@acme.com")` → `EMAIL` |
| `detect_file` | Scans a local file — image, PDF, scan or text — using Strac's OCR and classifiers. | `detect_file(path="./w2.pdf")` → `TAX_ID_NUMBER, NAME, ADDRESS` |
| `redact_file` | Writes a redacted copy of a local file to disk. The original is never modified. | `redact_file(path="./w2.pdf")` → `./w2.redacted.pdf` |
| `detokenize` | Resolves Strac vault tokens (`tkn_…`) back to their original values, for authorised callers. | `detokenize(token_ids=["tkn_abc"])` → `"111-22-3333"` |

### Redaction styles

`redact_text` takes a `redact_field_mode`:

| Mode | Result |
| --- | --- |
| `REDACTED` (default) | `[REDACTED]` |
| `MASK_SEVEN_X` | `XXXXXXX` |
| `BLANK` | removed entirely |
| `TOKEN_LINK_PLAINTEXT` | `<sensitive_data: https://…/detokenize/tkn_…>` — a link to the value in the Strac vault, so an authorised human can still retrieve it |

### Redaction that doesn't leak

By default these tools return the **types and positions** of what they found, not the values:

```json
{
  "redacted_text": "Please onboard the user with SSN [REDACTED]",
  "detection_count": 1,
  "data_element_types": ["TAX_ID_NUMBER"],
  "detections": [{ "type": "TAX_ID_NUMBER", "begin_index": 33, "end_index": 44, "length": 11 }]
}
```

Returning the matched text alongside the redacted text would hand the model exactly the data you just removed. Pass `include_matched_text=true` when a caller genuinely needs the raw values.

---

## What gets detected

The `/detect` and `/redact` endpoints classify: `NAME`, `ADDRESS`, `EMAIL`, `DATE_OF_BIRTH`, `GENDER`, `TAX_ID_NUMBER` (SSN, ITIN, EIN, PAN, numéro fiscal), `CREDIT_DEBIT_NUMBER`, `DRIVER_LICENSE_NUMBER`, `PASSPORT_NUMBER`, `NATIONAL_ID_NUMBER`, `AADHAAR_NUMBER`, `ISSUE_DATE` and `EXPIRY_DATE`.

The wider Strac platform classifies a much broader set across its SaaS and cloud connectors — bank and routing numbers, CVV, medical and health identifiers, source code, and credentials such as AWS keys, GitHub and GitLab tokens, Slack tokens, GCP and Azure secrets, and database connection strings. See [docs.strac.io](https://docs.strac.io) for the full list.

---

## Configuration

| Variable | Required | Default |
| --- | --- | --- |
| `STRAC_API_KEY` | yes | — |
| `STRAC_API_BASE` | no | `https://api.live.tokenidvault.com` for `sk_live_` keys, `https://api.test.tokenidvault.com` for `sk_test_` keys |
| `STRAC_API_TIMEOUT` | no | `60` seconds |

Without a key, every tool returns: `Set STRAC_API_KEY — get one at https://www.strac.io/mcp-integrations`.

The server speaks **stdio** by default. `strac-mcp-dlp --transport streamable-http` serves HTTP instead.

---

## How it works

Your MCP client spawns this server locally; it forwards each tool call to the Strac API over HTTPS with your `X-Api-Key`, and returns the result. Nothing is classified or redacted on your machine, and this repository contains no detection models.

Your data element definitions, custom policies, remediation rules, audit trail, and the full MCP DLP gateway across your SaaS and cloud connectors live in your Strac account: **[strac.io/mcp-integrations](https://www.strac.io/mcp-integrations)**.

```
MCP client  ──stdio──▶  strac-mcp-dlp  ──HTTPS──▶  Strac DLP API
(Claude, Cursor,        (this repo,                 (classifiers, OCR,
 your agent)             ~600 lines)                 vault, policies, audit)
```

Limits inherited from the API: 4 MB for inline content, 10 MB for document uploads, 10 tokens per detokenize call.

---

## Development

```bash
git clone https://github.com/strac-io/strac-mcp-dlp
cd strac-mcp-dlp
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/python -m pytest
```

The test suite mocks the Strac API with `respx`, so it runs without a key. To try the server by hand:

```bash
STRAC_API_KEY=sk_test_… .venv/bin/python -m strac_mcp_dlp
```

Or point the [MCP Inspector](https://github.com/modelcontextprotocol/inspector) at it:

```bash
STRAC_API_KEY=sk_test_… npx @modelcontextprotocol/inspector strac-mcp-dlp
```

---

## Links

- [Strac MCP integrations](https://www.strac.io/mcp-integrations) — the full MCP DLP gateway, connectors, policies and audit
- [Strac API reference](https://docs.strac.io)
- [MCP DLP: protecting data across Model Context Protocol](https://www.strac.io/blog/mcp-dlp)

## Security

Never commit an API key. `sk_live_` keys are server-side credentials; keep them in your MCP client's `env` block or your secret manager, not in source control. To report a vulnerability, email [security@strac.io](mailto:security@strac.io).

## License

MIT — see [LICENSE](LICENSE).

<!-- mcp-name: io.github.strac-io/strac-mcp-dlp -->
