# Kali MCP v0.1.0-beta.10 — File transfers and human-readable WebUI errors

This prerelease adds file exchange between authenticated MCP clients and the Kali MCP Core through **OpenLink** and **Base64**, and removes raw JSON error pages from common browser forms.

## File transfers: up to 100 MB per file

The new MCP tools are:

- \`files_upload\` — upload Base64 inline or initialize a 100 MB OpenLink/Base64-chunked upload.
- \`files_upload_chunk\` / \`files_upload_finish\` — transfer and finalize Base64 chunks (up to 128 KiB decoded per call).
- \`files_download\` — mint a short-lived one-time HTTPS link, or retrieve a Base64 window with \`next_offset\` and \`done\`.
- \`files_list\` / \`files_delete\` — manage only your authenticated MCP client's private files.
- \`jobs_export\` — export the calling client's existing bounded job stdout/stderr as OpenLink or Base64 (no other clients' jobs or arbitrary host files).

OpenLink uses streamed HTTP PUT/GET with exact byte length; Base64 works without separate file-transfer HTTP access by splitting large files into 128 KiB chunks. The original request JSON limit remains 256 KiB. **Both modes support files up to 100 MB (100,000,000 bytes)**. For very large files, OpenLink generally uses fewer CPU cycles and requests.

See [MCP_FILE_TRANSFERS.md](MCP_FILE_TRANSFERS.md) for precise tool sequences and browser/Cloudflare considerations.

### Security

- Unprivileged Core-only private workspace \`/data/transfers\`; no direct host filesystem access, Docker socket, or Host Root / Host Exec requirement.
- Owner-scoped file IDs; metadata and new signed links require the original OAuth or API-token identity.
- One-use random OpenLink bearer capabilities, hashed in SQLite and valid for 10 minutes.
- 24-hour retention; max 16 files / 300 MB per client, 1 GB globally, and a minimum free disk reserve.
- Strict basename and MIME validation, symlink/path traversal prevention, size enforcement during streaming, SHA-256 file and chunk integrity reporting.
- Browser CORS still applies only to previously authorized origins, including the OpenLink HTTP path; unrelated WebUI/admin routes retain strict same-origin protections.
- Large Base64 messages never bypass the server's JSON body size limit, and text files are not rendered inline on OpenLink downloads.

Cloudflare Access or other proxy policy can block raw PUT/GET on \`/files/openlink/*\` if it has not been configured for that narrow path. It can also impose request-size/timeout limits below 100 MB. **Do not bypass Cloudflare Access across the entire WebUI.** Use Base64 chunks when raw file PUT/GET is unavailable.

## Human-readable WebUI errors

Interactive HTML forms now display navigable, escaped error pages instead of raw JSON when login, token lifecycle or OAuth client revoke operations fail. Administrative session reauthentication from beta.9 remains non-replaying, with CSRF and superuser password confirmation still mandatory. Ingress-origin, size and rate-limit failures also use browser-readable feedback when the browser requests HTML.

OAuth, Streamable HTTP MCP, API clients and programmatic requests continue to receive structured JSON errors under their existing contracts. Error pages do not perform the previously attempted operation.

## Validation

The release must pass CI, legacy Docker smoke and systemd/Docker hybrid smoke. The hybrid gate tests real OAuth and API-token MCP tools, Base64 inline and chunked file transfers, OpenLink PUT/GET, one-time URL consumption, CORS, and the existing privileged Host Agent configuration flows. Physical Raspberry Pi 5, Cloudflare and llama.cpp WebUI integration remain to be confirmed in your environment.

You can update using **WebUI → Updates → Check now**, when authorized, and verify **Installed: v0.1.0-beta.10** after Core restarts. Host Root and Host Exec do not need to be enabled.
