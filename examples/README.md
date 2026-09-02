# Example MCP client configuration

| File | Use it for |
| --- | --- |
| `claude_desktop_config.json` | Claude Desktop, with the package installed via `pip install strac-mcp-dlp` |
| `claude_desktop_config.uvx.json` | Claude Desktop, with no install — [uv](https://docs.astral.sh/uv/) fetches the package on demand |
| `cursor_mcp.json` | Cursor — save as `.cursor/mcp.json` in your project, or `~/.cursor/mcp.json` globally |

Where the Claude Desktop config lives:

- macOS — `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows — `%APPDATA%\Claude\claude_desktop_config.json`

Replace `sk_live_your_key_here` with your key from [strac.io/mcp-integrations](https://www.strac.io/mcp-integrations), then restart the client.

Claude Code needs no file:

```bash
claude mcp add strac-dlp --env STRAC_API_KEY=sk_live_your_key_here -- strac-mcp-dlp
```
