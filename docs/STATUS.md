# Kali MCP development status: v0.1.0-dev

This is experimental source code, not a production release.

| Component | Implementation status |
| --- | --- |
| Apache-2.0 LICENSE and Postmaster attribution | Complete; source LICENSE Git SHA matched |
| Single YAML with staged source bootstrap | Implemented; not run on Kali ARM64 |
| Stable/beta release selection and periodic checks | Implemented; unit tests authored |
| Manual install/rollback of new app releases | Not implemented; MCP returns explicit error |
| OAuth code + PKCE S256, refresh and DCR | Implemented; real client not validated |
| Cloudflare policy | Documented; no live zone integration |
| WebUI login, toggle and monitoring | Prototype implemented |
| Job store and redacted audit | Implemented; results persisted |
| Dynamic Kali adapters and apt recipes | Partial catalog |
| Python/Bash Docker sandbox | Implemented; needs Docker integration tests |
| Host process and root PTY support | Experimental; not validated for deployment |
| Target CIDR policy | Implemented |
| Wi-Fi AP, Ethernet NAT and Nexmon management | Not implemented; read-only/status prototype only |
| Robust process cancellation | Not implemented; explicit error |
| PCAP artifact download / visual rendering | Not implemented |

Do NOT publish a stable release yet. End-to-end privileged execution,
network rollback, OAuth behind Cloudflare and Docker Compose startup have not
been verified on a real Kali Raspberry Pi.
