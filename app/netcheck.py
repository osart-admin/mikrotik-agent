"""Network diagnostics for "Проверить связь": ping, TCP port and SSH banner.

An SSH failure alone does not tell a dead host from a closed port, a firewall drop or a router
that refuses our source address. These three cheap checks do, and they never log in - so they
cannot trip RouterOS's failed-login protection.
"""
from __future__ import annotations

import asyncio
import re
import shutil
import time
from typing import Any

PING_COUNT = 3
PING_WAIT_S = 2
TCP_TIMEOUT_S = 5
BANNER_TIMEOUT_S = 5

_RECEIVED_RE = re.compile(r"(\d+)\s+packets transmitted,\s+(\d+)\s+(?:packets )?received")
_RTT_RE = re.compile(r"=\s*[\d.]+/([\d.]+)/[\d.]+")


def parse_ping(output: str) -> dict[str, Any]:
    sent = received = 0
    m = _RECEIVED_RE.search(output)
    if m:
        sent, received = int(m.group(1)), int(m.group(2))
    rtt = _RTT_RE.search(output)
    return {"sent": sent, "received": received, "avg_ms": round(float(rtt.group(1)), 1) if rtt else None}


async def ping(host: str) -> dict[str, Any]:
    binary = shutil.which("ping")
    if not binary:
        return {"ok": None, "error": "утилита ping не установлена в контейнере"}
    try:
        proc = await asyncio.create_subprocess_exec(
            binary, "-n", "-c", str(PING_COUNT), "-W", str(PING_WAIT_S), host,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
        )
    except OSError as exc:
        return {"ok": None, "error": f"ping не запустился: {exc}"}
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), PING_COUNT * (PING_WAIT_S + 1) + 5)
    except asyncio.TimeoutError:
        proc.kill()
        return {"ok": False, "sent": PING_COUNT, "received": 0, "avg_ms": None, "error": "ping не завершился вовремя"}
    text = out.decode("utf-8", "replace")
    res = parse_ping(text)
    if not res["sent"]:
        # Name resolution failure and similar: ping prints a message instead of statistics.
        return {"ok": False, **res, "error": text.strip().splitlines()[-1][:200] if text.strip() else "нет ответа"}
    return {"ok": res["received"] > 0, **res, "error": ""}


async def tcp_ssh(host: str, port: int) -> dict[str, Any]:
    """state: open | refused | timeout | unreachable; banner: ok | closed | silent (only when open)."""
    started = time.monotonic()
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), TCP_TIMEOUT_S)
    except asyncio.TimeoutError:
        return {"state": "timeout", "banner": None, "banner_text": "", "error": ""}
    except ConnectionRefusedError:
        return {"state": "refused", "banner": None, "banner_text": "", "error": ""}
    except OSError as exc:
        return {"state": "unreachable", "banner": None, "banner_text": "", "error": exc.strerror or str(exc)}
    connect_ms = round((time.monotonic() - started) * 1000)
    banner, text = "silent", ""
    try:
        line = await asyncio.wait_for(reader.readline(), BANNER_TIMEOUT_S)
        if line.startswith(b"SSH-"):
            banner, text = "ok", line.decode("ascii", "replace").strip()[:80]
        elif not line:
            banner = "closed"
        else:
            text = line.decode("ascii", "replace").strip()[:80]  # something answered, but not SSH
    except asyncio.TimeoutError:
        banner = "silent"
    except (ConnectionResetError, BrokenPipeError, OSError):
        banner = "closed"
    finally:
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), 2)
        except Exception:
            pass
    return {"state": "open", "connect_ms": connect_ms, "banner": banner, "banner_text": text, "error": ""}


def verdict(p: dict[str, Any], t: dict[str, Any], port: int) -> str:
    replies = p.get("ok")
    state, banner = t.get("state"), t.get("banner")
    if state == "open" and banner == "ok":
        return (f"Сеть и SSH в порядке: порт {port} открыт и роутер отвечает по SSH. "
                "Проблема на этапе входа — см. сообщение об ошибке выше.")
    if state == "open" and banner == "closed":
        return (f"Роутер доступен, порт {port} открыт, но соединение закрывается сразу, до SSH. "
                "Обычно адрес этого сервиса не входит в /ip service ssh address=..., попал в список "
                "блокировки файрвола или исчерпан лимит SSH-сессий.")
    if state == "open":
        return (f"Порт {port} принимает соединение, но SSH не отвечает. Возможно, на этом порту "
                "работает другой сервис или роутер перегружен.")
    if state == "refused":
        return (f"Роутер доступен, но порт {port} закрыт: SSH выключен (/ip service) или работает "
                "на другом порту.")
    if state == "unreachable":
        return f"Нет маршрута до роутера: {t.get('error') or 'узел недостижим'}."
    # timeout
    if replies:
        return (f"Роутер отвечает на ping, но порт {port} не отвечает: подключения режет файрвол "
                "на роутере или по пути.")
    if replies is None:
        return f"Порт {port} не отвечает. Ping проверить не удалось, поэтому неясно, жив ли узел."
    return ("Роутер не отвечает ни на ping, ни по SSH: он выключен, нет маршрута или туннель лежит. "
            "Также возможно, что файрвол режет всё, включая ping.")


async def diagnose(host: str, port: int) -> dict[str, Any]:
    p, t = await asyncio.gather(ping(host), tcp_ssh(host, port))
    return {"ping": p, "tcp": t, "port": port, "verdict": verdict(p, t, port)}
