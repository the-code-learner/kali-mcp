from __future__ import annotations

import base64
import hashlib
import io
from pathlib import Path
import tarfile

import pytest
import yaml
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.testclient import TestClient

from kali_mcp.config import Config
from kali_mcp.store import Store
from kali_mcp.policy import Policy, PolicyDenied
from kali_mcp.registry import tool_command, installer_argv
from kali_mcp.releases import select_release
from kali_mcp.oauth import OAuth, redirect_ok
from scripts.bootstrap import safe_extract


@pytest.fixture
def initialized(tmp_path, monkeypatch):
    monkeypatch.setenv("KALI_MCP_PUBLIC_URL", "https://kali.example.test")
    monkeypatch.setenv("KALI_MCP_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("KALI_MCP_ADMIN_PASSWORD", "LONG_TEST_ADMIN_PASSWORD_12345678")
    for var in ("KALI_MCP_ALLOW_HOST_EXEC", "KALI_MCP_ALLOW_HOST_ROOT",
                "KALI_MCP_ALLOW_PACKAGE_INSTALL", "KALI_MCP_ALLOW_NETWORK_CHANGES",
                "KALI_MCP_ALLOW_MCP_HOST_EXEC", "KALI_MCP_ALLOW_MCP_ROOT"):
        monkeypatch.setenv(var, "true")
    cfg = Config.from_env()
    store = Store(tmp_path / "app.db")
    yield cfg, store
    store.close()


def test_policy_ceiling_root_and_scopes(initialized, monkeypatch):
    cfg, store = initialized
    policy = Policy(cfg, store)
    with pytest.raises(PolicyDenied):
        policy.set_webui("host_root", True)
    policy.set_webui("host_exec", True)
    policy.set_webui("host_root", True)
    policy.check_execution("host", root=True, actor="mcp:client")
    with pytest.raises(PolicyDenied):
        policy.check_target("8.8.8.8")
    assert policy.check_target("127.0.0.1") == "127.0.0.1"
    policy.set_webui("host_root", False)
    with pytest.raises(PolicyDenied):
        policy.check_execution("host", root=True, actor="mcp:client")
    monkeypatch.setenv("KALI_MCP_ALLOW_HOST_ROOT", "false")
    with pytest.raises(PolicyDenied, match="KALI_MCP_ALLOW_HOST_ROOT"):
        Policy(Config.from_env(), store).set_webui("host_root", True)


def test_typed_commands_and_installer(initialized):
    cfg, store = initialized
    policy = Policy(cfg, store)
    assert tool_command("nmap", "quick", {"target": "127.0.0.1"}, policy)[-1] == "127.0.0.1"
    with pytest.raises(PolicyDenied):
        tool_command("nmap", "services", {"target": "127.0.0.1", "ports": [0]}, policy)
    assert installer_argv("nmap")[-1] == "nmap"
    with pytest.raises(PolicyDenied):
        installer_argv("nmap; rm -rf /")


def test_release_channels_and_draft_filter():
    rows = [{"tag_name": "v1.2.9", "prerelease": False},
            {"tag_name": "v1.3.0-beta.1", "prerelease": True},
            {"tag_name": "v1.3.0-beta.2", "prerelease": True},
            {"tag_name": "v1.4.0", "draft": True}]
    assert select_release(rows, "stable").tag == "v1.2.9"
    assert select_release(rows, "beta").tag == "v1.3.0-beta.2"


def _archive(name, is_link=False):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        info = tarfile.TarInfo(name)
        if is_link:
            info.type = tarfile.SYMTYPE
            info.linkname = "/etc/shadow"
            tar.addfile(info)
        else:
            raw = b"hello"
            info.size = len(raw)
            tar.addfile(info, io.BytesIO(raw))
    return buf.getvalue()


def test_bootstrap_safe_extraction(tmp_path):
    safe_extract(_archive("repo/README.md"), tmp_path)
    assert (tmp_path / "README.md").read_bytes() == b"hello"
    with pytest.raises(RuntimeError):
        safe_extract(_archive("repo/../../oops"), tmp_path)
    with pytest.raises(RuntimeError):
        safe_extract(_archive("repo/link", is_link=True), tmp_path)


def test_oauth_pkce_and_rotation(initialized):
    cfg, store = initialized
    oauth = OAuth(cfg, store)
    app = Starlette(routes=[Route("/register", oauth.register, methods=["POST"]),
                            Route("/token", oauth.token, methods=["POST"])])
    client = TestClient(app)
    assert not redirect_ok("http://evil.example/return")
    reg = client.post("/register", json={"client_name": "test",
                          "redirect_uris": ["https://chatgpt.com/oauth/callback"]})
    assert reg.status_code == 201
    cid = reg.json()["client_id"]
    verifier = "a" * 43
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    with store.transaction():
        store.db.execute("INSERT INTO oauth_codes VALUES(?,?,?,?,?,?,?)",
            (hashlib.sha256(b"testcode").hexdigest(), cid,
             "https://chatgpt.com/oauth/callback", challenge,
             cfg.resource, "mcp:tools", 2000000000))
    form = {"grant_type": "authorization_code", "client_id": cid,
            "redirect_uri": "https://chatgpt.com/oauth/callback",
            "code": "testcode", "code_verifier": verifier, "resource": cfg.resource}
    ok = client.post("/token", data=form)
    assert ok.status_code == 200, ok.text
    access = ok.json()["access_token"]
    refresh = ok.json()["refresh_token"]
    assert oauth.verify_bearer(access) == cid
    assert oauth.verify_bearer(refresh) is None
    assert client.post("/token", data=form).status_code == 400
    rotated = client.post("/token", data={"grant_type": "refresh_token",
        "client_id": cid, "refresh_token": refresh, "resource": cfg.resource})
    assert rotated.status_code == 200
    assert rotated.json()["refresh_token"] != refresh
    assert client.post("/token", data={"grant_type": "refresh_token",
        "client_id": cid, "refresh_token": refresh, "resource": cfg.resource}).status_code == 400


def test_compose_is_single_yml_and_broker_only_privileged():
    root = Path(__file__).resolve().parents[1]
    deployment = yaml.safe_load((root / "kali-mcp.yml").read_text())
    services = deployment["services"]
    assert services["kali-mcp-broker"]["privileged"] is True
    assert not services["kali-mcp-core"].get("privileged")
    assert not any("docker.sock" in mount for mount in services["kali-mcp-core"]["volumes"])
    assert "KALI_MCP_RELEASE_CHANNEL" in services["kali-mcp-bootstrap"]["environment"]


def test_runtime_oauth_gate(initialized):
    from kali_mcp.runtime import app
    client = TestClient(app, base_url="https://kali.example.test")
    response = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert response.status_code == 401
    assert "resource_metadata=" in response.headers["www-authenticate"]
    assert client.get("/.well-known/oauth-authorization-server").status_code == 200
    assert client.get("/", follow_redirects=False).status_code == 303
    # The same origin is protected by a separate administrator login.
    login = client.post("/login", data={"password": "LONG_TEST_ADMIN_PASSWORD_12345678", "next": "/"},
                        follow_redirects=False)
    assert login.status_code == 303
    dashboard = client.get("/")
    assert dashboard.status_code == 200
    assert "Execution capabilities" in dashboard.text
    from re import search
    csrf_match = search(r'name="csrf" value="([^"]+)"', dashboard.text)
    assert csrf_match
    csrf = csrf_match.group(1)
    # Host execution can be enabled independently of MCP root privileges.
    enabled = client.post("/api/v1/settings", data={
        "csrf": csrf, "feature": "host_exec", "enabled": "true"}, follow_redirects=False)
    assert enabled.status_code == 303
    assert initialized[1].get_setting("host_exec")
    # Disclaimers are mandatory when enabling root.
    denied = client.post("/api/v1/settings", data={
        "csrf": csrf, "feature": "host_root", "enabled": "true"}, follow_redirects=False)
    assert denied.status_code == 400
    assert not initialized[1].get_setting("host_root")
    accepted = client.post("/api/v1/settings", data={
        "csrf": csrf, "feature": "host_root", "enabled": "true", "disclaimer": "yes"},
        follow_redirects=False)
    assert accepted.status_code == 303
    assert initialized[1].get_setting("host_root")
    no_csrf = client.post("/api/v1/settings", data={
        "csrf": "wrong", "feature": "host_root", "enabled": "false"},
        follow_redirects=False)
    assert no_csrf.status_code == 403
    assert initialized[1].get_setting("host_root")
