"""In-memory state and event fan-out for the bridge."""

from __future__ import annotations

import asyncio
from collections import deque
from dataclasses import replace
from typing import Any

from bridge.models import RiskLevel, SourceHealth, ThreatEvent, ThreatPosture, ensure_timezone, utc_now
from bridge.history import HistoryStore


ACTIVE_STATUSES = {"active", "failed", "denied"}


def _mark_event_mitigated(event: ThreatEvent) -> ThreatEvent:
    summary = f"{event.risk_level.capitalize()} risk {event.title} observed from {event.origin} (mitigated)."
    return replace(event, status="mitigated", summary=summary)


class BridgeState:
    def __init__(
        self,
        event_buffer_size: int,
        posture_decay_seconds: float,
        history: HistoryStore,
        auto_mitigate_threshold: int = 199,
        auto_mitigate_batch_size: int = 5,
    ) -> None:
        self._event_buffer_size = event_buffer_size
        self._posture_decay_seconds = posture_decay_seconds
        self._history = history
        self._auto_mitigate_threshold = max(1, auto_mitigate_threshold)
        self._auto_mitigate_batch_size = max(1, auto_mitigate_batch_size)
        self._auto_mitigate_enabled = True
        self._total_events_added = 0
        self._last_auto_mitigate_total = 0
        self._last_auto_mitigation: dict[str, Any] = {
            "count": 0,
            "event_ids": [],
            "message": "Auto-mitigation is on: at 200 buffered events, mark up to five oldest unresolved critical alerts; while full, repeat after each five new events. This does not stop a source.",
            "triggered_at": None,
        }
        self._events: deque[ThreatEvent] = deque(maxlen=event_buffer_size)
        self._source_health: dict[str, SourceHealth] = {}
        self._subscribers: set[asyncio.Queue[dict[str, Any]]] = set()
        self._lock = asyncio.Lock()

    async def add_event(self, event: ThreatEvent) -> None:
        async with self._lock:
            if event.status != "mitigated" and self._history.is_mitigated(event.id):
                event = _mark_event_mitigated(event)
            self._history.upsert_event(event.to_dict())
            self._events.append(event)
            self._total_events_added += 1
            auto_mitigated: list[ThreatEvent] = []
            should_auto_mitigate = (
                self._auto_mitigate_enabled
                and self._total_events_added > self._auto_mitigate_threshold
                and (
                    self._total_events_added == self._auto_mitigate_threshold + 1
                    or self._total_events_added - self._last_auto_mitigate_total >= self._auto_mitigate_batch_size
                )
            )
            if should_auto_mitigate:
                candidates = sorted(
                    (
                        candidate for candidate in self._events
                        if candidate.risk_level == "critical"
                        and candidate.status != "mitigated"
                    ),
                    key=lambda candidate: ensure_timezone(candidate.observed_at),
                )[: self._auto_mitigate_batch_size]
                for candidate in candidates:
                    for index, buffered in enumerate(self._events):
                        if buffered.id == candidate.id:
                            updated = _mark_event_mitigated(buffered)
                            self._events[index] = updated
                            self._history.upsert_event(updated.to_dict())
                            auto_mitigated.append(updated)
                            break
                self._last_auto_mitigate_total = self._total_events_added
                count = len(auto_mitigated)
                message = (
                    f"Buffer at capacity ({len(self._events)}/{self._event_buffer_size}). "
                    f"Auto-mitigation marked {count} oldest critical alert(s) as mitigated. This changes alert status only; it does not stop a source."
                    if count
                    else f"Buffer at capacity ({len(self._events)}/{self._event_buffer_size}). "
                    "No unresolved critical alerts were available to auto-mitigate."
                )
                self._last_auto_mitigation = {
                    "count": count,
                    "event_ids": [item.id for item in auto_mitigated],
                    "message": message,
                    "triggered_at": utc_now().isoformat(),
                }
            state_snapshot = self._build_state_locked()
            subscribers = list(self._subscribers)

        await self._publish(subscribers, "event", event.to_dict())
        for updated in auto_mitigated:
            await self._publish(subscribers, "event", updated.to_dict())
        await self._publish(subscribers, "state", state_snapshot)

    async def mitigate_event(self, event_id: str) -> dict[str, Any] | None:
        async with self._lock:
            updated_event = None
            for index, event in enumerate(self._events):
                if event.id == event_id:
                    if event.status != "mitigated":
                        updated_event = _mark_event_mitigated(event)
                        self._events[index] = updated_event
                        self._history.upsert_event(updated_event.to_dict())
                    else:
                        updated_event = event
                    break

            if updated_event is None:
                return None

            state_snapshot = self._build_state_locked()
            subscribers = list(self._subscribers)

        await self._publish(subscribers, "event", updated_event.to_dict())
        await self._publish(subscribers, "state", state_snapshot)
        return updated_event.to_dict()

    async def mitigate_all_events(self) -> list[dict[str, Any]]:
        async with self._lock:
            updated_events = []
            for index, event in enumerate(self._events):
                if event.status == "mitigated":
                    continue
                updated_event = _mark_event_mitigated(event)
                self._events[index] = updated_event
                self._history.upsert_event(updated_event.to_dict())
                updated_events.append(updated_event)

            state_snapshot = self._build_state_locked()
            subscribers = list(self._subscribers)

        for event in updated_events:
            await self._publish(subscribers, "event", event.to_dict())
        await self._publish(subscribers, "state", state_snapshot)
        return [event.to_dict() for event in updated_events]

    async def get_events(self) -> list[dict[str, Any]]:
        async with self._lock:
            return [event.to_dict() for event in reversed(self._events)]

    async def get_state(self) -> dict[str, Any]:
        async with self._lock:
            return self._build_state_locked()

    async def get_health_snapshot(self) -> dict[str, Any]:
        async with self._lock:
            return {
                name: health.to_dict()
                for name, health in sorted(self._source_health.items())
            }

    async def set_auto_mitigation(self, enabled: bool) -> dict[str, Any]:
        async with self._lock:
            self._auto_mitigate_enabled = bool(enabled)
            if enabled:
                message = "Auto-mitigation is on: at 200 buffered events, mark up to five oldest unresolved critical alerts; while full, repeat after each five new events. This does not stop a source."
            else:
                message = "Auto-mitigation is off. Alerts will not be marked automatically; use per-alert controls or Mitigate All."
            self._last_auto_mitigation = {
                **self._last_auto_mitigation,
                "message": message,
            }
            state_snapshot = self._build_state_locked()
            subscribers = list(self._subscribers)
        await self._publish(subscribers, "state", state_snapshot)
        return state_snapshot["auto_mitigation"]

    async def record_source_health(
        self,
        source: str,
        *,
        available: bool,
        status: str,
        error: str | None,
        details: dict[str, Any] | None = None,
    ) -> None:
        details = details or {}
        now = utc_now()

        async with self._lock:
            previous = self._source_health.get(source)
            last_success_at = now if available else previous.last_success_at if previous else None
            effective_status = status
            effective_error = error

            if (
                source == "attack_sim"
                and previous is not None
                and previous.status == "mitigated"
            ):
                activity_resumed = bool(details.get("activity_resumed"))
                if not (available and status == "online" and activity_resumed):
                    effective_status = "mitigated"
                    effective_error = previous.last_error

            self._source_health[source] = SourceHealth(
                source=source,
                available=available,
                status=effective_status,
                checked_at=now,
                last_success_at=last_success_at,
                last_error=effective_error,
                details=details,
            )
            state_snapshot = self._build_state_locked()
            subscribers = list(self._subscribers)

        await self._publish(subscribers, "state", state_snapshot)

    async def mark_source_mitigated(self, source: str, message: str, details: dict[str, Any] | None = None) -> None:
        details = details or {}
        now = utc_now()

        async with self._lock:
            previous = self._source_health.get(source)
            self._source_health[source] = SourceHealth(
                source=source,
                available=False,
                status="mitigated",
                checked_at=now,
                last_success_at=previous.last_success_at if previous else None,
                last_error=message,
                details={**details, "mitigated_at": now.isoformat()},
            )
            state_snapshot = self._build_state_locked()
            subscribers = list(self._subscribers)

        await self._publish(subscribers, "state", state_snapshot)

    async def get_source_status(self, source: str) -> str | None:
        async with self._lock:
            health = self._source_health.get(source)
            return health.status if health else None

    async def subscribe(self) -> asyncio.Queue[dict[str, Any]]:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=50)
        async with self._lock:
            self._subscribers.add(queue)
        return queue

    async def unsubscribe(self, queue: asyncio.Queue[dict[str, Any]]) -> None:
        async with self._lock:
            self._subscribers.discard(queue)

    def _build_state_locked(self) -> dict[str, Any]:
        posture = self._calculate_posture_locked()
        return {
            "events": [event.to_dict() for event in reversed(self._events)],
            "global_risk_score": posture.global_risk_score,
            "global_threat_level": posture.global_threat_level,
            "active_event_count": posture.active_event_count,
            "event_count": len(self._events),
            "auto_mitigation": {
                "enabled": self._auto_mitigate_enabled,
                "threshold": self._auto_mitigate_threshold,
                "batch_size": self._auto_mitigate_batch_size,
                **self._last_auto_mitigation,
            },
            "source_health": {
                name: health.to_dict()
                for name, health in sorted(self._source_health.items())
            },
        }

    def _calculate_posture_locked(self) -> ThreatPosture:
        if not self._events:
            return ThreatPosture(global_risk_score=0, global_threat_level="low", active_event_count=0)

        recent_events = list(self._events)[-20:]
        weighted_scores = [
            event.risk_score * self._event_recency_weight(event)
            for event in recent_events
            if event.status != "mitigated"
        ]
        active_scores = [score for score in weighted_scores if score > 0]

        if not active_scores:
            return ThreatPosture(global_risk_score=0, global_threat_level="low", active_event_count=0)

        average_score = sum(active_scores) / len(active_scores)
        peak_score = max(active_scores)

        # Weighted toward the hottest event so the posture reacts to spikes,
        # while still considering the average of the recent stream. Each event's
        # contribution decays over time so containment reduces posture naturally.
        global_risk_score = round((peak_score * 0.6) + (average_score * 0.4))

        level = self._risk_level_for_score(global_risk_score)

        active_event_count = sum(
            1
            for event in self._events
            if event.status in ACTIVE_STATUSES and self._event_recency_weight(event) > 0.1
        )
        return ThreatPosture(
            global_risk_score=global_risk_score,
            global_threat_level=level,
            active_event_count=active_event_count,
        )

    def _event_recency_weight(self, event: ThreatEvent) -> float:
        event_time = ensure_timezone(event.ingested_at)
        age_seconds = max((utc_now() - event_time).total_seconds(), 0)
        if age_seconds >= self._posture_decay_seconds:
            return 0.0
        return max(0.0, 1 - (age_seconds / self._posture_decay_seconds))

    def _risk_level_for_score(self, score: int) -> RiskLevel:
        if score >= 75:
            return "critical"
        if score >= 50:
            return "high"
        if score >= 25:
            return "medium"
        return "low"

    async def _publish(
        self,
        subscribers: list[asyncio.Queue[dict[str, Any]]],
        event_name: str,
        payload: dict[str, Any],
    ) -> None:
        message = {"event": event_name, "data": payload}
        for subscriber in subscribers:
            if subscriber.full():
                try:
                    subscriber.get_nowait()
                except asyncio.QueueEmpty:
                    pass

            try:
                subscriber.put_nowait(message)
            except asyncio.QueueFull:
                continue
