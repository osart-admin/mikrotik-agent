"""Diagnostics behind "Проверить связь": ping parsing, TCP/SSH-banner states and the verdict."""
from __future__ import annotations

import asyncio
import socket

import pytest

from app import netcheck


def test_parse_ping_statistics():
    out = ("3 packets transmitted, 2 received, 33.3333% packet loss, time 2003ms\n"
           "rtt min/avg/max/mdev = 11.201/12.456/13.002/0.700 ms\n")
    assert netcheck.parse_ping(out) == {"sent": 3, "received": 2, "avg_ms": 12.5}
    lost = "3 packets transmitted, 0 received, 100% packet loss, time 2051ms\n"
    assert netcheck.parse_ping(lost) == {"sent": 3, "received": 0, "avg_ms": None}


async def _serve(handler):
    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


def test_tcp_ssh_states():
    async def scenario():
        async def ssh(reader, writer):
            writer.write(b"SSH-2.0-ROSSSH\r\n"); await writer.drain(); writer.close()

        async def drop(reader, writer):
            writer.close()

        s1, p1 = await _serve(ssh)
        s2, p2 = await _serve(drop)
        with socket.socket() as sock:           # a port that nothing listens on
            sock.bind(("127.0.0.1", 0)); free = sock.getsockname()[1]
        try:
            return (await netcheck.tcp_ssh("127.0.0.1", p1), await netcheck.tcp_ssh("127.0.0.1", p2),
                    await netcheck.tcp_ssh("127.0.0.1", free))
        finally:
            s1.close(); s2.close()

    ok, dropped, refused = asyncio.run(scenario())
    assert ok["state"] == "open" and ok["banner"] == "ok" and ok["banner_text"] == "SSH-2.0-ROSSSH"
    assert dropped["state"] == "open" and dropped["banner"] == "closed"
    assert refused["state"] == "refused"


@pytest.mark.parametrize("ping_ok,tcp,expected", [
    (True, {"state": "refused"}, "порт 22 закрыт"),
    (True, {"state": "timeout"}, "режет файрвол"),
    (False, {"state": "timeout"}, "ни на ping, ни по SSH"),
    (None, {"state": "timeout"}, "Ping проверить не удалось"),
    (False, {"state": "open", "banner": "closed"}, "/ip service ssh address"),
    (True, {"state": "open", "banner": "ok"}, "на этапе входа"),
    (False, {"state": "unreachable", "error": "No route to host"}, "No route to host"),
])
def test_verdict(ping_ok, tcp, expected):
    assert expected in netcheck.verdict({"ok": ping_ok}, tcp, 22)


def test_connection_test_endpoint_includes_diagnostics(monkeypatch):
    from fastapi.testclient import TestClient
    import asyncssh
    from app import db
    from app.main import app

    async def timeout_probe(*args, **kwargs):
        raise asyncio.TimeoutError

    async def fake_diagnose(host, port):
        return {"ping": {"ok": True}, "tcp": {"state": "refused"}, "port": port, "verdict": "порт закрыт"}

    monkeypatch.setattr(asyncssh, "get_server_host_key", timeout_probe)
    monkeypatch.setattr(netcheck, "diagnose", fake_diagnose)
    with TestClient(app) as client:
        if db.user_count() == 0:
            client.post("/setup", data={"username": "tester", "password": "testpass123", "password2": "testpass123"})
        else:
            client.post("/login", data={"username": "tester", "password": "testpass123", "next": "/"})
        dev_id = db.create_device({"slug": "diag-me", "name": "Diag", "host": "192.0.2.82", "port": 22,
                                   "username": "agent", "auth": "key"})
        try:
            body = client.post(f"/api/devices/{dev_id}/test").json()
            assert body["ok"] is False and body["kind"] == "timeout"
            assert body["diag"]["verdict"] == "порт закрыт"
        finally:
            db.delete_device(dev_id)
