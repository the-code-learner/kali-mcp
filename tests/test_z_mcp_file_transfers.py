"""MCP file exchange has per-client isolation and independently bounded modes."""
from __future__ import annotations

import asyncio
import base64
import json
from urllib.parse import urlparse

import pytest
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.testclient import TestClient

from kali_mcp.config import Config
from kali_mcp.store import Store
from kali_mcp.transfers import (
    TransferVault, TransferError, MAX_BASE64_FILE, MAX_OPENLINK_FILE,
    file_name
)

OWNER = "mcp:api:alice"
OTHER = "mcp:api:bob"


def make_vault(tmp_path):
    store = Store(tmp_path / "database.db")
    vault = TransferVault(tmp_path / "private", store, "https://kali.example.test")
    return store, vault


def ticket_from_url(url: str) -> str:
    return url.rsplit("/", 1)[-1]


def test_base64_roundtrip_and_client_isolation(tmp_path):
    store, vault = make_vault(tmp_path)
    data = b"port,service\n443,https\n" + bytes([0, 255])
    encoded = base64.b64encode(data).decode()
    obj = vault.put_base64(OWNER, "results.csv", "text/csv", encoded)
    assert obj["ok"] and obj["bytes"] == len(data)
    file_id = obj["file_id"]
    result = vault.get_file(OWNER, file_id, "base64")
    assert base64.b64decode(result["data_base64"]) == data
    assert vault.list_files(OWNER)["files"][0]["name"] == "results.csv"
    assert vault.list_files(OTHER)["files"] == []
    with pytest.raises(TransferError, match="not found"):
        vault.get_file(OTHER, file_id, "openlink")
    with pytest.raises(TransferError, match="not found"):
        vault.delete(OTHER, file_id)
    with pytest.raises(TransferError, match="256 KiB"):
        vault.put_base64(OWNER, "too-big.bin", "application/octet-stream",
                         base64.b64encode(bytes(MAX_BASE64_FILE + 1)).decode())
    for invalid in ("../../etc/passwd", "/root/.ssh/id_rsa", "../x",
                    "nested/file.txt", "..", "", "bad\nname"):
        with pytest.raises(TransferError):
            file_name(invalid)
    assert vault.delete(OWNER, file_id)["ok"] is True
    with pytest.raises(TransferError, match="not found"):
        vault.get_file(OWNER, file_id, "base64")
    store.close()


def test_openlink_file_capability_one_time_exact_bytes_and_expiration(tmp_path):
    store, vault = make_vault(tmp_path)
    payload = b"1234\x00\xff"
    prepared = vault.begin_upload(OWNER, "scan.bin", "application/octet-stream", len(payload))
    assert prepared["method"] == "PUT"
    assert prepared["expires_in"] == 600
    secret = ticket_from_url(prepared["upload_url"])
    assert secret.encode() not in (tmp_path / "database.db").read_bytes()

    async def stream():
        yield payload[:3]
        yield payload[3:]
    stored = asyncio.run(vault.receive_upload(secret, stream(), len(payload)))
    assert stored["file_id"] == prepared["file_id"]
    assert vault.get_file(OWNER, prepared["file_id"], "base64")["data_base64"] == (
        base64.b64encode(payload).decode())
    with pytest.raises(TransferError, match="already used"):
        asyncio.run(vault.receive_upload(secret, stream(), len(payload)))

    download = vault.get_file(OWNER, prepared["file_id"], "openlink")
    dl_secret = ticket_from_url(download["url"])
    selected = vault.consume_download(dl_secret)
    assert selected and selected[1] == "scan.bin"
    assert selected[0].read_bytes() == payload
    assert vault.consume_download(dl_secret) is None

    expired = vault.get_file(OWNER, prepared["file_id"], "openlink")
    with store.transaction():
        store.db.execute("UPDATE transfer_tickets SET expires=0 WHERE ticket_hash=?",
                         (__import__("hashlib").sha256(ticket_from_url(expired["url"]).encode()).hexdigest(),))
    assert vault.consume_download(ticket_from_url(expired["url"])) is None

    bad_size = vault.begin_upload(OWNER, "bad.bin", "application/octet-stream", 3)
    async def too_many():
        yield b"longer than three"
    with pytest.raises(TransferError, match="declared size"):
        asyncio.run(vault.receive_upload(ticket_from_url(bad_size["upload_url"]),
                                         too_many(), None))
    assert not any(x["file_id"] == bad_size["file_id"]
                   for x in vault.list_files(OWNER)["files"])
    with pytest.raises(TransferError, match="8 MiB"):
        vault.begin_upload(OWNER, "huge.bin", "application/octet-stream",
                           MAX_OPENLINK_FILE + 1)
    store.close()


def test_http_openlink_upload_download_and_origin_denials(tmp_path, monkeypatch):
    monkeypatch.setenv("KALI_MCP_DATA_DIR", str(tmp_path))
    from kali_mcp import runtime
    monkeypatch.setenv("KALI_MCP_PUBLIC_URL", "https://kali.example.test")
    monkeypatch.setenv("KALI_MCP_BROWSER_ORIGINS", "https://llm.example.test")
    cfg = Config.from_env()
    store, vault = make_vault(tmp_path)
    monkeypatch.setattr(runtime, "cfg", cfg)
    monkeypatch.setattr(runtime.core, "vault", vault)

    app = runtime.SecurityGate(Starlette(routes=[
        Route("/files/openlink/{ticket}", runtime.openlink_get, methods=["GET"]),
        Route("/files/openlink/{ticket}", runtime.openlink_put, methods=["PUT"]),
    ]))

    prepared = vault.begin_upload(OWNER, "report.html", "text/html", 4)
    url_path = urlparse(prepared["upload_url"]).path
    with TestClient(app, base_url=cfg.base_url, follow_redirects=False) as client:
        cors = client.options(url_path, headers={
            "Origin": "https://llm.example.test",
            "Access-Control-Request-Method": "PUT",
            "Access-Control-Request-Headers": "content-type",
        })
        assert cors.status_code == 204
        assert cors.headers["access-control-allow-origin"] == "https://llm.example.test"

        cross = client.options(url_path, headers={
            "Origin": "https://attacker.example",
            "Access-Control-Request-Method": "PUT",
        })
        assert cross.status_code == 403

        denied = client.put(url_path, content=b"test", headers={
            "Origin": "https://attacker.example",
            "Content-Type": "application/octet-stream",
        })
        assert denied.status_code == 403

        valid = client.put(url_path, content=b"test", headers={
            "Origin": "https://llm.example.test",
            "Content-Type": "application/octet-stream",
        })
        assert valid.status_code == 201, valid.text
        assert valid.json()["file_id"] == prepared["file_id"]
        assert valid.headers["access-control-allow-origin"] == "https://llm.example.test"
        assert client.put(url_path, content=b"test", headers={
            "Origin": "https://llm.example.test",
            "Content-Type": "application/octet-stream",
        }).status_code == 400

        receipt = vault.get_file(OWNER, prepared["file_id"], "openlink")
        path = urlparse(receipt["url"]).path
        blocked = client.get(path, headers={"Origin": "https://attacker.example"})
        assert blocked.status_code == 403
        ok = client.get(path, headers={"Origin": "https://llm.example.test"})
        assert ok.status_code == 200
        assert ok.content == b"test"
        assert ok.headers["content-type"] == "application/octet-stream"
        assert "attachment" in ok.headers["content-disposition"]
        assert ok.headers["cache-control"] == "private, no-store"
        assert ok.headers["access-control-allow-origin"] == "https://llm.example.test"
        assert client.get(path).status_code == 404
        assert client.get(path, headers={"Host": "attacker.example"}).status_code == 400
    store.close()
