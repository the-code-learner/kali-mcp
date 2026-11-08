# MCP file exchange — Base64 and OpenLink

Starting with v0.1.0-beta.10, Kali MCP supports moving files **from an MCP client to the Core and back to that same client**. It does not grant access to arbitrary Raspberry Pi host files and does not require Host Exec, Host Root, or Package Install.

## Limits and retention

| Property | Limit |
|---|---|
| Maximum single file | **100 MB** (100,000,000 bytes) |
| OpenLink uploads/downloads | Stream raw bytes, HTTP PUT/GET |
| Base64 inline call | 128 KiB decoded bytes |
| Base64 chunked transfer | Up to 100 MB; 128 KiB decoded per call |
| Per-client live storage | 16 files or 300 MB |
| Total Core transfer storage | 1 GB |
| Reserved free disk | At least 128 MiB remaining |
| File retention | 24 hours after completion |
| Chunked Base64 upload idle timeout | 10 minutes, refreshed after each accepted chunk; 2-hour maximum session |
| Signed OpenLink | 10 minutes, single-use |

**Large transfers:** OpenLink is more efficient. Base64 chunking works when the client has access only to MCP tools, but adds ~33% encoding overhead and many JSON-RPC calls. Download and verify the reported full-file SHA-256.

### MCP client → Kali MCP

**Option A: OpenLink**

1. Call \`files_upload(name="evidence.bin", mode="openlink", size_bytes=100000000)\`.
2. Receive \`upload_url\` and \`method="PUT"\`. Make a single HTTP PUT of **exactly** the declared number of raw bytes, with \`Content-Type: application/octet-stream\`. Do not Base64-encode this HTTP body.
3. A successful response returns \`file_id\`, \`bytes\` and \`sha256\`. The signed URL cannot be reused.
4. Retrieve metadata with \`files_list\`, download through \`files_download\`, or delete with \`files_delete\`.

**Option B: Base64**

Small file, up to 128 KiB: call \`files_upload(name="note.txt", mode="base64", data_base64="<encoded>")\`.

Larger file:

1. \`files_upload(name="dataset.bin", mode="base64", size_bytes=100000000)\` reserves a private file and returns a \`file_id\` and \`chunk_bytes=131072\`.
2. Send consecutive parts with \`files_upload_chunk(file_id="...", offset=0, data_base64="...")\`. The offset refers to **decoded raw bytes**, not Base64 characters. Advance by the response's \`written\` field. Each part must decode to at most 128 KiB.
3. Once \`remaining=0\`, call \`files_upload_finish(file_id="...")\`. This checks the full length and computes SHA-256.
4. Incomplete or expired uploads cannot be retrieved.

### Kali MCP → MCP client

\`files_download(file_id="...", mode="openlink")\` returns a one-time HTTPS GET URL with a download attachment.

\`files_download(file_id="...", mode="base64", offset=0)\` returns at most 128 KiB encoded as \`data_base64\`. Repeat with \`offset=next_offset\` until \`done=true\`, then verify the complete reconstructed file's SHA-256 against the returned \`sha256\` field. Request shorter parts by setting \`max_bytes\`.

For command results previously executed by the same MCP client, \`jobs_export(job_id="...", stream="stdout", mode="openlink")\` or \`mode="base64"\` creates a private, bounded transfer file. Existing audit and job stdout/stderr truncation limits still apply.

### Security and Cloudflare deployment

- **Private owner workspace:** File metadata and new download links are accessible only to the original authenticated MCP actor (OAuth client or API-token identity). Different actors cannot list, read, or delete one another's files.
- **No host filesystem mount:** File content is stored only under the unprivileged Core's persistent \`/data/transfers\` (separate from the Host Agent). No arbitrary absolute paths, traversal, or symlink-based reads are supported.
- **One-time URL credentials:** OpenLink URLs contain high-entropy capability secrets stored only as hashes. Anyone possessing an unused URL can consume it. Do not paste URLs into logs, screenshots, tickets, chats or public tools; treat them as passwords. An authorized Origin is additionally required for browser CORS, but requests without an Origin header (e.g. curl) are permitted with the signed URL.
- **Cross-origin browsers:** Only the previously configured exact browser origins have CORS access to the OpenLink URLs. The management dashboard and administrator APIs do not gain cross-origin access.
- **Cloudflare:** Your edge proxy or Cloudflare Access policy must permit the precise \`/files/openlink/*\` requests and HTTP PUT/GET when using this mode. A separate Access login page may interrupt raw PUT/GET; configure *only this narrowly scoped path* if necessary, respecting that its one-time URLs are bearer credentials. Do **not** disable protection for the whole dashboard. Cloudflare plan limits, maximum upload size and timeouts can be lower than the application's own 100 MB ceiling. For such cases use Base64 chunks.
- **Transient capacity:** Very large in-progress transfers count against quota immediately. The worker refuses transfers that would violate the global quota or leave less than the minimum free disk reserve.

Neither OpenLink nor Base64 installs modules, executes files or elevates MCP permissions. Clients must explicitly invoke separate authorized tools to do anything beyond exchanging data.
