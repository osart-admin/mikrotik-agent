"""Git-backed config store: /data/configs/<slug>/export.rsc (+ facts.json).

One commit per collection run, and only when something actually changed - the export header
(timestamp, software id) is stripped by the collector before it gets here, so an unchanged
router produces no commit. All git calls are synchronous subprocess calls guarded by a lock;
the repo is tiny so this is fine inside the event loop.
"""
from __future__ import annotations

import re
import subprocess
import threading
from datetime import datetime, timezone
from pathlib import Path

from .config import CONFIGS_DIR

EXPORT_FILE = "export.rsc"
FACTS_FILE = "facts.json"
_lock = threading.Lock()


def _git(*args: str, check: bool = True) -> str:
    proc = subprocess.run(["git", "-C", str(CONFIGS_DIR), *args], capture_output=True, text=True)
    if check and proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)}: {proc.stderr.strip()}")
    return proc.stdout


def ensure_repo() -> None:
    CONFIGS_DIR.mkdir(parents=True, exist_ok=True)
    if not (CONFIGS_DIR / ".git").exists():
        _git("init", "-q")
        _git("config", "user.name", "mikrotik-agent")
        _git("config", "user.email", "mikrotik-agent@localhost")
        _git("config", "core.autocrlf", "false")
        (CONFIGS_DIR / ".gitattributes").write_text("* text eol=lf\n")


def device_dir(slug: str) -> Path:
    return CONFIGS_DIR / slug


def read_export(slug: str) -> str | None:
    p = device_dir(slug) / EXPORT_FILE
    return p.read_text() if p.exists() else None


def read_facts(slug: str) -> str | None:
    p = device_dir(slug) / FACTS_FILE
    return p.read_text() if p.exists() else None


def write_device(slug: str, export_text: str, facts_json: str) -> bool:
    """Write files; return True if the export differs from what was stored."""
    d = device_dir(slug)
    d.mkdir(parents=True, exist_ok=True)
    old = read_export(slug)
    changed = old != export_text
    (d / EXPORT_FILE).write_text(export_text)
    (d / FACTS_FILE).write_text(facts_json)
    return changed


def remove_device(slug: str) -> None:
    d = device_dir(slug)
    if d.exists():
        for f in d.iterdir():
            f.unlink()
        d.rmdir()


def rename_device(old: str, new: str) -> None:
    if device_dir(old).exists() and old != new:
        device_dir(old).rename(device_dir(new))


def commit(message: str) -> str | None:
    """Stage everything and commit; return the sha, or None when the tree is unchanged."""
    with _lock:
        _git("add", "-A")
        if subprocess.run(["git", "-C", str(CONFIGS_DIR), "diff", "--cached", "--quiet"]).returncode == 0:
            return None
        _git("commit", "-q", "-m", message)
        return _git("rev-parse", "HEAD").strip()


def has_commits() -> bool:
    return subprocess.run(["git", "-C", str(CONFIGS_DIR), "rev-parse", "-q", "--verify", "HEAD"], capture_output=True).returncode == 0


def history(slug: str | None = None, limit: int = 20) -> list[dict[str, str]]:
    if not has_commits():
        return []
    args = ["log", f"-n{limit}", "--format=%H%x1f%cI%x1f%s"]
    if slug:
        args += ["--", f"{slug}/{EXPORT_FILE}"]
    out = []
    for line in _git(*args).splitlines():
        sha, date, subject = line.split("\x1f", 2)
        out.append({"sha": sha, "short": sha[:8], "date": date, "subject": subject})
    return out


_BLAME_HEAD = re.compile(r"^([0-9a-f]{40}) \d+ (\d+)")
_UNCOMMITTED = "0" * 40


def blame_dates(slug: str) -> dict[int, str]:
    """export.rsc line number -> ISO date git last saw that line change.

    Lines only in the working tree (not yet committed) come back under the all-zero sha with
    committer-time set to *now*; they are dropped, so a caller must treat a missing line as
    "unknown", not "new".
    """
    if not has_commits():
        return {}
    out = _git("blame", "--porcelain", "--", f"{slug}/{EXPORT_FILE}", check=False)
    commit_time: dict[str, int] = {}
    dates: dict[int, str] = {}
    sha, line_no = "", 0
    for line in out.splitlines():
        head = _BLAME_HEAD.match(line)
        if head:
            sha, line_no = head.group(1), int(head.group(2))
        elif line.startswith("committer-time "):
            commit_time[sha] = int(line.split(maxsplit=1)[1])
        elif line.startswith("\t") and sha in commit_time and sha != _UNCOMMITTED:
            dates[line_no] = datetime.fromtimestamp(commit_time[sha], timezone.utc).date().isoformat()
    return dates


def first_commit_date() -> str | None:
    if not has_commits():
        return None
    roots = _git("rev-list", "--max-parents=0", "HEAD").split()
    return _git("show", "-s", "--format=%cI", roots[-1]).strip() if roots else None


def show(slug: str, sha: str) -> str | None:
    proc = subprocess.run(["git", "-C", str(CONFIGS_DIR), "show", f"{sha}:{slug}/{EXPORT_FILE}"], capture_output=True, text=True)
    return proc.stdout if proc.returncode == 0 else None


def diff(slug: str, rev_a: str, rev_b: str | None = None, context: int = 3) -> str:
    """Unified diff of a device export between two commits (rev_b=None -> working tree)."""
    args = ["diff", f"-U{context}", "--no-color", rev_a]
    if rev_b:
        args.append(rev_b)
    args += ["--", f"{slug}/{EXPORT_FILE}"]
    return _git(*args, check=False)


def diff_prev(slug: str, sha: str) -> str:
    """Diff of the commit against its parent for one device."""
    return _git("diff", "-U3", "--no-color", f"{sha}~1", sha, "--", f"{slug}/{EXPORT_FILE}", check=False)


def changed_in_commit(sha: str) -> list[str]:
    """Device slugs whose export changed in this commit."""
    out = _git("diff-tree", "--no-commit-id", "--name-only", "-r", sha, check=False)
    return sorted({p.split("/")[0] for p in out.split() if p.endswith(EXPORT_FILE)})
