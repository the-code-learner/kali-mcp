# Security model

The user requested a single Compose YAML with an explicitly privileged host
broker. A privileged container with Docker socket and host PID visibility has
effectively host-root authority. The WebUI root toggle is an application policy
for authenticated MCP clients, NOT an isolation boundary for a compromised broker.

The non-root core is separated from the broker on a private Unix socket.
Broker access is not exposed on TCP. Root, package installation, host scripts
and network changes are disabled by default at both YAML and admin levels.

The tool adapters validate an explicit CIDR authorization scope and bounded
arguments. The sandbox uses Docker with network none, no additional Linux
capabilities, read-only root filesystem and resource limits.

Sandbox scripts are passed as bounded Docker command arguments in the first
beta. Administrators with Docker socket access can inspect them while the
sandbox container exists. Do not embed API tokens or passwords directly in
these scripts. A later version will use a confidential script transport.

Known limits: token misuse, host-root commands, container escape, loss of
auditing during host compromise, and process descendants that escape the job
tree require specific additional security controls. An authorized root shell
can modify the machine beyond the control of this MCP.

Never test networks without their owner's explicit permission. Deploy on a
dedicated lab appliance rather than a shared machine until validated.

## Systemd hybrid superuser hardening

The systemd hybrid is the preferred mode; the older privileged-Docker stack
is legacy and must not be exposed publicly. The wizard provisions a named
application superuser in a root-owned scrypt record. No plaintext password is
present in the hybrid Docker Compose environment. WebUI and SSH CLI both
require the application credential; CLI also requires sudo. Agent privilege
changes require a new superuser proof verified directly by the host Agent.

The Core mounts only a read-only salted password hash, and Agent policy
remains root-owned on the Kali host. This mitigates straightforward IPC
permission escalation but **does not make a compromised MCP Core or a
permitted root shell safe**. When root is enabled, an MCP client with the
corresponding OAuth token can intentionally control the host. Anyone with
actual Linux root can modify or bypass these application controls.

Ingress limits body sizes, rate-limits authentication endpoints, validates
Host/Origin, applies response headers and uses CSRF for administrative actions.
Job queues and terminal sessions have bounded concurrency. These are defense
in depth; add upstream Cloudflare Access MFA, WAF/rate limiting, HTTPS and
network firewalling. Never expose a raw HTTP bind to the public Internet.

**Security requirements before production:** independently audit the Agent
socket trust boundary, fuzz MCP/tool arguments, validate ARM64 and Cloudflare,
add more complete agent peer authentication and process/cgroup isolation,
test application update rollback and dependency vulnerability scans.
