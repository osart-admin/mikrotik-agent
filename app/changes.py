"""Change plans: validation and risk assessment.

Nothing here applies anything - this module decides whether a proposed set of RouterOS commands
is allowed to reach the approval queue at all, and how dangerous it is once there.

Design rules:

* **Deterministic, not model judgement.** The model writes the plan; plain Python decides whether
  it may be queued. A model cannot argue its way past a regex.
* **Deny by default on the destructive set.** Anything that can brick a device, lock the operator
  out, or erase state is rejected outright - not flagged, rejected. Those changes stay a human's
  job at the console.
* **Reject, don't sanitise.** A plan is never silently edited to make it safe; a rejected plan
  comes back with the reason so a human decides.

Command text arriving here is untrusted: it originates from an LLM that has read router
configuration written by third parties.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# Commands that are never allowed through the queue, whatever the justification.
FORBIDDEN: list[tuple[str, str]] = [
    (r"/system\s+reset-configuration", "сброс конфигурации устройства"),
    (r"/system\s+(reboot|shutdown)", "перезагрузка или выключение"),
    (r"/system\s+routerboard\s+upgrade", "перепрошивка загрузчика"),
    (r"/system\s+package", "операции с пакетами и обновление RouterOS"),
    (r"/system\s+backup\s+load", "восстановление из бэкапа (делает откат, а не изменение)"),
    (r"/system\s+script\s+(add|set|run)", "скрипты на устройстве"),
    (r"/system\s+scheduler\s+(add|set)", "планировщик на устройстве (используется механизмом отката)"),
    (r"/user\b(?!\s+(print|export))", "управление пользователями и ключами"),
    (r"/file\s+(remove|set|add)", "операции с файлами устройства"),
    (r"/certificate", "операции с сертификатами"),
    (r"/tool\s+(fetch|bandwidth-test|flood|traffic-generator|sniffer)", "загрузка данных и генерация трафика"),
    (r"/import\b", "исполнение .rsc с устройства"),
    (r"/interface\s+wireguard\s+.*private-key", "смена приватного ключа WireGuard"),
    (r":execute|:parse|\[\s*:", "исполнение скриптовых выражений"),
]

# Changes that are legitimate but can cut the agent off from the device, so they need the operator
# to look twice. Flagged, not blocked.
RISKY: list[tuple[str, str]] = [
    (r"/ip\s+address\s+(remove|set)", "правка IP-адресов — можно потерять управление"),
    (r"/ip\s+service\s+set.*\bdisabled=yes", "отключение сервиса управления"),
    (r"/ip\s+firewall\s+filter\s+add.*action=drop(?!.*\bsrc-address=)", "drop без ограничения источника"),
    (r"/ip\s+firewall\s+filter\s+add.*chain=input", "правило в цепочке input — влияет на доступ к роутеру"),
    (r"/interface\s+\w+\s+(remove|disable)", "отключение или удаление интерфейса"),
    (r"/interface\s+ethernet\s+(reset-mac-address\b|set\b.*\bmac-address=)",
     "смена MAC — если через этот порт идёт управление, связь пропадёт, пока не обновятся ARP-кэши"),
    (r"/ipv?6?\s+firewall\s+(filter|nat|mangle|raw)\s+(disable|remove)\b",
     "отключение или удаление правил firewall — снимает запреты, а у разрешений отнимает доступ"),
    (r"/ip\s+route\s+(remove|set)", "правка маршрутов"),
    (r"\bremove\b", "удаление записи"),
    (r"/ip\s+dhcp-server", "изменение DHCP-сервера"),
    (r"/interface\s+bridge\s+port", "изменение портов бриджа"),
]

# Only these top-level menus may be touched at all. Anything else is out of scope for automated
# change, even if it is not explicitly forbidden above.
ALLOWED_MENUS = (
    "/ip/firewall", "/ipv6/firewall", "/ip/address", "/ip/route", "/ip/dns", "/ip/pool",
    "/ip/dhcp-server", "/ip/dhcp-client", "/ip/service", "/ip/neighbor", "/ip/cloud",
    "/interface", "/routing", "/queue", "/system/identity", "/system/ntp", "/system/logging",
    "/system/note", "/snmp", "/ip/firewall/address-list",
)

MAX_COMMANDS = 40

# A value that only exists once another plan has run - the public key WireGuard generates on the
# other device - is written as <name> and typed in by the operator before the plan can be run.
_PLACEHOLDER = re.compile(r"<([^<>\"\n]{1,60})>")
# One token with nothing that could close a quote, start a script or a second command: the filled
# text is re-validated, but a value must not be able to change what the command is.
_VALUE = re.compile(r'^[^\s"\\;\[\]<>{}$]{1,200}$')

# Verbs beyond add/set/remove/enable/disable, recognised only in the menu they belong to. An
# unknown verb anywhere else still fails to parse and is rejected.
MENU_VERBS: dict[str, tuple[str, ...]] = {
    "/interface/ethernet": ("reset-mac-address",),
}


@dataclass
class Finding:
    command: str
    line: int
    reason: str


@dataclass
class Validation:
    ok: bool
    blocked: list[Finding] = field(default_factory=list)
    risky: list[Finding] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)

    @property
    def risk(self) -> str:
        if self.blocked:
            return "blocked"
        return "high" if self.risky else "normal"

    def summary(self) -> str:
        if self.blocked:
            return "; ".join(f"строка {f.line}: {f.reason}" for f in self.blocked)
        if self.risky:
            return "; ".join(f"строка {f.line}: {f.reason}" for f in self.risky)
        return "явных рисков не выявлено"


def _menu_path(raw: str) -> str:
    return "/" + "/".join(p for p in re.split(r"[ /]+", raw) if p)


def normalize_menu(command: str) -> str:
    m = re.match(r"^(/[a-z0-9][a-z0-9 /-]*?)\s+(add|set|remove|enable|disable|print|export)\b", command)
    if m:
        return _menu_path(m.group(1))
    for menu, verbs in MENU_VERBS.items():
        m = re.match(r"^(/[a-z0-9][a-z0-9 /-]*?)\s+(?:" + "|".join(map(re.escape, verbs)) + r")(?:\s|$)", command)
        if m and _menu_path(m.group(1)) == menu:
            return menu
    return ""


def placeholders(text: str) -> list[str]:
    """Names of the <placeholders> still to be filled, in order of first appearance."""
    return list(dict.fromkeys(m.group(1) for m in _PLACEHOLDER.finditer(text)))


def fill(text: str, values: dict[str, str]) -> str:
    """Substitute operator-supplied values; raises ValueError for a value that is not one plain token."""
    for name, value in values.items():
        if not _VALUE.match(value):
            raise ValueError(f"значение для <{name}> должно быть одним словом без пробелов, кавычек, "
                             f"скобок, ; и $")
        text = text.replace(f"<{name}>", value)
    return text


def parse_commands(text: str) -> list[str]:
    """One command per line; blanks and # comments dropped."""
    out = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        out.append(line)
    return out


def dead_additions(commands: list[str], export: str) -> list[Finding]:
    """Rules a plan appends behind a terminal rule with no conditions, where nothing ever reaches them.

    `add` without place-before goes to the end of the chain. A plan that adds an accept for the
    overlay network to a chain ending in `drop chain=input` has queued a rule that cannot match.
    A plan that also disables, removes or edits rules in that table is not simulated: which rule
    ends the chain after it runs is not known here.
    """
    from . import audit, rsc

    def ends_chain(e: rsc.Entry) -> bool:
        return (e.verb == "add" and e.path in audit.ORDERED_CHAINS and not e.is_disabled()
                and e.args.get("action", "") in audit.TERMINAL and set(audit.matchers(e)) <= {"chain"})

    planned = rsc.parse("\n".join(commands))
    edited = {e.path for e in planned if e.verb != "add"}
    enders = [(e, f"строка {e.line_no} конфигурации") for e in rsc.parse(export) if ends_chain(e)]
    out: list[Finding] = []
    for e in planned:
        if e.verb != "add" or e.path not in audit.ORDERED_CHAINS or e.path in edited or e.is_disabled():
            continue
        chain = e.args.get("chain", "")
        blocker = next(((b, where) for b, where in enders
                        if b.path == e.path and b.args.get("chain", "") == chain), None)
        if blocker is not None and "place-before" not in e.args:
            b, where = blocker
            out.append(Finding(e.raw, e.line_no,
                               f"встанет в конец chain={chain} после «{b.raw}» ({where}) и никогда не "
                               f"сработает — нужен place-before"))
        if ends_chain(e) and "place-before" not in e.args:
            enders.append((e, f"строка {e.line_no} этого плана"))
    return out


def validate(text: str, export: str | None = None) -> Validation:
    commands = parse_commands(text)
    v = Validation(ok=False, commands=commands)

    if not commands:
        v.blocked.append(Finding("", 0, "план пуст"))
        return v
    if len(commands) > MAX_COMMANDS:
        v.blocked.append(Finding("", 0, f"слишком много команд: {len(commands)} при лимите {MAX_COMMANDS}"))
        return v

    for i, cmd in enumerate(commands, 1):
        if "\n" in cmd or "\r" in cmd:
            v.blocked.append(Finding(cmd, i, "перенос строки внутри команды"))
            continue
        if not cmd.startswith("/"):
            v.blocked.append(Finding(cmd, i, "команда должна начинаться с пути меню"))
            continue
        if ";" in cmd:
            v.blocked.append(Finding(cmd, i, "несколько команд в одной строке"))
            continue

        for pattern, reason in FORBIDDEN:
            if re.search(pattern, cmd, re.IGNORECASE):
                v.blocked.append(Finding(cmd, i, f"запрещено: {reason}"))
                break
        else:
            menu = normalize_menu(cmd)
            if not menu:
                v.blocked.append(Finding(cmd, i, "не удалось разобрать команду"))
                continue
            if not any(menu == a or menu.startswith(a + "/") for a in ALLOWED_MENUS):
                v.blocked.append(Finding(cmd, i, f"меню {menu} вне разрешённого списка"))
                continue
            if menu.endswith("/print") or " print" in cmd:
                v.blocked.append(Finding(cmd, i, "план изменений не должен содержать чтение"))
                continue
            for pattern, reason in RISKY:
                if re.search(pattern, cmd, re.IGNORECASE):
                    v.risky.append(Finding(cmd, i, reason))
                    break

    v.ok = not v.blocked
    if v.ok and export:
        v.risky.extend(dead_additions(commands, export))
    return v
