# Developer validation

Run on Python 3.12+:

    python -m venv .venv
    . .venv/bin/activate
    pip install -r requirements.txt pytest PyYAML
    python -m compileall -q src scripts tests
    pytest -q

First hardware smoke test must be performed on an isolated Kali lab system.
Do not enable host shell/root, package installs or network changes on a
production Raspberry until the PTY ownership checks, safe timeouts, Docker
sandbox boundaries and rollback paths are validated.

Development YAML uses KALI_MCP_VERSION=main and checks GitHub updates without
installing them. The admin password must be set in the private stack, not in Git.
A stable GitHub Release must NOT be tagged until deployment and OAuth tests pass.

For sandbox tests, pre-pull the configured container image on the Docker host,
preferably pinned to an immutable image digest, and confirm it cannot see
host files or host networking. Verify actual ARM64 compatibility.
