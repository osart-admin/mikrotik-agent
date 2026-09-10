"""Periodic collection. Interval is a UI setting; 0 disables it."""
from __future__ import annotations

import logging

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

from . import collector, db
from .config import APP_TIMEZONE

log = logging.getLogger("scheduler")
_scheduler: AsyncIOScheduler | None = None
JOB_ID = "collect"


async def _job() -> None:
    try:
        await collector.collect_all(trigger="schedule")
    except Exception:  # noqa: BLE001
        log.exception("scheduled collection failed")


def start() -> None:
    global _scheduler
    if _scheduler is None:
        _scheduler = AsyncIOScheduler(timezone=APP_TIMEZONE)
        _scheduler.start()
    apply_settings()


def apply_settings() -> None:
    if _scheduler is None:
        return
    minutes = int(db.get_setting("collect_interval_minutes", "0") or 0)
    if _scheduler.get_job(JOB_ID):
        _scheduler.remove_job(JOB_ID)
    if minutes > 0:
        _scheduler.add_job(_job, IntervalTrigger(minutes=minutes), id=JOB_ID, max_instances=1, coalesce=True)
        log.info("collection scheduled every %d minutes", minutes)
    else:
        log.info("scheduled collection disabled")


def next_run() -> str | None:
    if _scheduler is None:
        return None
    job = _scheduler.get_job(JOB_ID)
    return job.next_run_time.isoformat(timespec="seconds") if job and job.next_run_time else None


def stop() -> None:
    global _scheduler
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        _scheduler = None
