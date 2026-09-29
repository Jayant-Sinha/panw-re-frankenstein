"""Incremental ingestion for the simulator's newline-delimited JSON log."""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime

from bridge.config import Settings
from bridge.models import ensure_timezone, utc_now
from bridge.normalize import normalize_attack_sim_event
from bridge.scoring import score_event
from bridge.state import BridgeState


logger = logging.getLogger(__name__)


async def watch_live_log(settings: Settings, state: BridgeState, stop_event: asyncio.Event) -> None:
    path = settings.live_stream_path
    offset, pending_fragment = _load_cursor(settings.live_log_offset_path)
    last_event_at: datetime | None = None
    pid_path = settings.attack_sim_pid_path

    await state.record_source_health(
        "attack_sim",
        available=False,
        status="waiting",
        error=None if path.exists() and pid_path.exists() else "Log file or PID file not found yet.",
        details={"path": str(path), "pid_path": str(pid_path)},
    )

    while not stop_event.is_set():
        try:
            if not path.exists():
                offset = 0
                pending_fragment = ""
                _save_cursor(settings.live_log_offset_path, offset, pending_fragment)
                await state.record_source_health(
                    "attack_sim",
                    available=False,
                    status="waiting",
                    error="Log file not found yet.",
                    details={"path": str(path)},
                )
                await _wait_for_next_cycle(stop_event, settings.live_log_poll_interval_seconds)
                continue

            current_size = path.stat().st_size
            if current_size < offset:
                logger.info("Simulator log was truncated or replaced. Resetting file offset.")
                offset = 0
                pending_fragment = ""
                _save_cursor(settings.live_log_offset_path, offset, pending_fragment)

            with path.open("r", encoding="utf-8", newline="") as handle:
                handle.seek(offset)
                chunk = handle.read()
                offset = handle.tell()

            current_status = await state.get_source_status("attack_sim")
            health_status = _log_health_status(
                last_event_at,
                settings.live_log_stale_seconds,
                current_status,
                pid_path.exists(),
            )
            await state.record_source_health(
                "attack_sim",
                available=health_status["available"],
                status=health_status["status"],
                error=health_status["error"],
                details={
                    "path": str(path),
                    "pid_path": str(pid_path),
                    "offset": offset,
                    "last_event_at": last_event_at.isoformat() if last_event_at else None,
                },
            )

            if not chunk:
                await _wait_for_next_cycle(stop_event, settings.live_log_poll_interval_seconds)
                continue

            previous_last_event_at = last_event_at
            pending_fragment, last_event_at = await _process_chunk(chunk, pending_fragment, state, last_event_at)
            _save_cursor(settings.live_log_offset_path, offset, pending_fragment)
            if last_event_at is not None and last_event_at != previous_last_event_at and pid_path.exists():
                await state.record_source_health(
                    "attack_sim",
                    available=True,
                    status="online",
                    error=None,
                    details={
                        "activity_resumed": True,
                        "path": str(path),
                        "pid_path": str(pid_path),
                        "offset": offset,
                        "last_event_at": last_event_at.isoformat(),
                    },
                )
        except UnicodeDecodeError as exc:
            logger.warning("Failed to decode simulator log as UTF-8: %s", exc)
            await state.record_source_health(
                "attack_sim",
                available=False,
                status="decode-error",
                error=str(exc),
                details={"path": str(path)},
            )
        except Exception as exc:  # pragma: no cover - defensive runtime guard.
            logger.exception("Unexpected simulator ingestion failure.")
            await state.record_source_health(
                "attack_sim",
                available=False,
                status="error",
                error=str(exc),
                details={"path": str(path)},
            )

        await _wait_for_next_cycle(stop_event, settings.live_log_poll_interval_seconds)


async def _process_chunk(
    chunk: str,
    pending_fragment: str,
    state: BridgeState,
    last_event_at: datetime | None,
) -> tuple[str, datetime | None]:
    buffer = pending_fragment + chunk
    lines = buffer.splitlines(keepends=True)
    next_pending_fragment = ""
    newest_event_at = last_event_at

    for line in lines:
        if line.endswith(("\n", "\r")):
            stripped = line.rstrip("\r\n")
            if stripped:
                processed_at = await _process_line(stripped, state)
                if processed_at is not None:
                    newest_event_at = processed_at
            continue

        next_pending_fragment = line

    return next_pending_fragment, newest_event_at


async def _process_line(line: str, state: BridgeState) -> datetime | None:
    try:
        payload = json.loads(line)
    except json.JSONDecodeError:
        logger.warning("Ignoring malformed simulator log line: %s", line)
        return None

    if not isinstance(payload, dict):
        logger.warning("Ignoring simulator log payload that is not an object: %s", payload)
        return None

    processed_at = utc_now()
    event = score_event(normalize_attack_sim_event(payload, ingested_at=processed_at))
    await state.add_event(event)
    return ensure_timezone(processed_at)


def _log_health_status(
    last_event_at: datetime | None,
    stale_seconds: float,
    current_status: str | None,
    pid_file_exists: bool,
) -> dict[str, object]:
    if current_status == "mitigated" and not pid_file_exists:
        return {
            "available": False,
            "status": "mitigated",
            "error": "Attack simulator was terminated by the mitigation control.",
        }

    if not pid_file_exists:
        return {
            "available": False,
            "status": "waiting",
            "error": "Attack simulator PID file not found.",
        }

    if last_event_at is None:
        return {
            "available": False,
            "status": "waiting",
            "error": "Waiting for simulator events.",
        }

    idle_seconds = (utc_now() - ensure_timezone(last_event_at)).total_seconds()
    if idle_seconds > stale_seconds:
        return {
            "available": False,
            "status": "waiting",
            "error": "No new simulator events have arrived recently.",
        }

    return {
        "available": True,
        "status": "online",
        "error": None,
    }


async def _wait_for_next_cycle(stop_event: asyncio.Event, seconds: float) -> None:
    try:
        await asyncio.wait_for(stop_event.wait(), timeout=seconds)
    except asyncio.TimeoutError:
        return


def _load_cursor(cursor_path) -> tuple[int, str]:
    try:
        payload = json.loads(cursor_path.read_text(encoding="utf-8"))
        offset = max(0, int(payload.get("offset", 0)))
        pending = str(payload.get("pending_fragment", ""))
        return offset, pending
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return 0, ""


def _save_cursor(cursor_path, offset: int, pending_fragment: str) -> None:
    try:
        cursor_path.parent.mkdir(parents=True, exist_ok=True)
        temporary_path = cursor_path.with_suffix(cursor_path.suffix + ".tmp")
        temporary_path.write_text(
            json.dumps({"offset": offset, "pending_fragment": pending_fragment}),
            encoding="utf-8",
        )
        temporary_path.replace(cursor_path)
    except OSError as exc:
        logger.warning("Could not persist simulator log cursor: %s", exc)
