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
