"""The algorithm wish-lists must actually survive the intersection with asyncssh.

A str/bytes mismatch here is silent: _connect_kwargs() comes back empty, asyncssh falls back to
its modern defaults, and every RouterOS 6 device fails to negotiate.
"""
from __future__ import annotations

from app import ssh


def test_connect_kwargs_are_populated():
    kw = ssh._connect_kwargs()
    for key in ("kex_algs", "server_host_key_algs", "encryption_algs", "mac_algs", "signature_algs"):
        assert kw.get(key), f"{key} is empty - the wish-list did not intersect"


def test_legacy_algorithms_offered_for_routeros6():
    kw = ssh._connect_kwargs()
    assert "ssh-rsa" in kw["server_host_key_algs"]
    assert "diffie-hellman-group14-sha1" in kw["kex_algs"]
    assert "aes128-cbc" in kw["encryption_algs"]
    assert "hmac-sha1" in kw["mac_algs"]


def test_modern_algorithms_are_preferred_first():
    kw = ssh._connect_kwargs()
    assert kw["kex_algs"][0].startswith("curve25519")
    assert kw["server_host_key_algs"][0] == "ssh-ed25519"


def test_normalize_strips_ansi_and_crlf():
    assert ssh.normalize("\x1b[32mname: HSH-D\x1b[0m\r\n\r\n") == "name: HSH-D"


def test_parse_print_terse_handles_flags_and_quotes():
    rows = ssh.parse_print_terse(' 0   comment="a b" address=10.0.3.254/24 interface=bridge\n 2 D address=10.0.5.245/32 interface=l2tp\n')
    assert rows[0]["_id"] == "0" and rows[0]["comment"] == "a b" and rows[0]["_flags"] == ""
    assert rows[1]["_flags"] == "D" and rows[1]["address"] == "10.0.5.245/32"


def test_parse_print_key_values():
    out = ssh.parse_print("           uptime: 5d16h35m59s\n          version: 7.22.1 (stable)\n       board-name: hAP ax^3\n")
    assert out["version"] == "7.22.1 (stable)" and out["board-name"] == "hAP ax^3"


def test_host_key_probe_kwargs_are_accepted_by_asyncssh():
    """_pin_host_key passes a filtered kwarg set; keep it in sync with asyncssh's signature."""
    import inspect

    import asyncssh

    accepted = set(inspect.signature(asyncssh.get_server_host_key).parameters)
    kw = ssh._connect_kwargs()
    probe_kw = {k: v for k, v in kw.items() if k in ("kex_algs", "server_host_key_algs")}
    assert probe_kw, "probe would send no algorithm preferences at all"
    assert set(probe_kw) <= accepted


def test_connect_kwargs_are_accepted_by_asyncssh_connect():
    import inspect

    import asyncssh

    accepted = set(inspect.signature(asyncssh.SSHClientConnectionOptions.prepare).parameters)
    assert set(ssh._connect_kwargs()) <= accepted
