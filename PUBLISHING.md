# Publishing runbook

Three things have to line up for a release: PyPI, a GitHub release, and the
Official MCP Registry. Glama, PulseMCP and the other directories index from the
official registry, so that is the step that produces discovery.

## One-time setup

1. **PyPI project + trusted publishing.** Create the `strac-mcp-dlp` project on
   PyPI, then add a trusted publisher at
   `https://pypi.org/manage/project/strac-mcp-dlp/settings/publishing/`:
   - Owner `strac-io`, repository `strac-mcp-dlp`
   - Workflow `publish.yml`, environment `pypi`

   After this the release workflow needs no API token.

2. **GitHub environment.** Create an environment named `pypi` in the repo
   settings. Add required reviewers if you want a human gate on releases.

3. **Registry namespace.** `server.json` claims `io.github.strac-io/strac-mcp-dlp`,
   which the registry grants to anyone who can authenticate as the `strac-io`
   GitHub org — the release workflow does this over OIDC, with no stored secret.

   To publish under the shorter, better-branded `io.strac/dlp` instead, add a TXT
   record to `strac.io`:

   ```
   _mcp-registry.strac.io  TXT  "v=MCPv1; k=ed25519; p=<public key>"
   ```

   then `mcp-publisher login dns --domain strac.io --private-key <key>` and change
   the `name` in `server.json`. Worth doing — the registry name is what shows up in
   every downstream directory listing — but it needs DNS access, so v0.1.0 ships
   under the GitHub namespace.

## Cutting a release

1. Bump the version in **three** places, which CI checks agree:
   - `pyproject.toml` → `version`
   - `server.json` → `version` and `packages[0].version`
   - `src/strac_mcp_dlp/__init__.py` → `__version__`
2. Add a `CHANGELOG.md` entry.
3. Merge to `main` and confirm CI is green.
4. Tag and publish a GitHub release:

   ```bash
   git tag v0.1.0 && git push origin v0.1.0
   gh release create v0.1.0 --title "v0.1.0" --notes-file <(sed -n '/## 0.1.0/,/^## /p' CHANGELOG.md)
   ```

5. The `Publish` workflow builds the sdist and wheel, pushes to PyPI, waits for
   PyPI to serve the version, then publishes `server.json` to the registry.

## Publishing by hand

If you would rather not use the workflow:

```bash
pip install build twine
python -m build
twine upload dist/*

curl -sL "https://github.com/modelcontextprotocol/registry/releases/download/v1.8.1/mcp-publisher_darwin_arm64.tar.gz" | tar xz mcp-publisher
./mcp-publisher validate
./mcp-publisher login github      # opens a device-code flow in the browser
./mcp-publisher publish
```

## Gotchas

- **The registry verifies package ownership via the README.** The PyPI long
  description must contain the literal string `mcp-name: io.github.strac-io/strac-mcp-dlp`.
  It is the HTML comment at the bottom of `README.md`; CI fails if it goes missing.
- **`description` in `server.json` is capped at 100 characters.** Longer values are
  rejected with a 422. The PyPI `description` in `pyproject.toml` has no such cap.
- **Publish to PyPI before the registry.** The registry checks that the package and
  version actually exist, so the ordering in the workflow is load-bearing.
- **Versions are immutable** on both PyPI and the registry. A mistake means a new
  patch version, not a re-push.

## Verifying

```bash
curl -s "https://registry.modelcontextprotocol.io/v0/servers?search=strac" | python3 -m json.tool
pip download strac-mcp-dlp --no-deps -d /tmp/check
```
