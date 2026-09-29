"""Normalization for raw simulator and legacy payloads."""

from __future__ import annotations

import hashlib
import json
from datetime import date, datetime
from typing import Any, Mapping

from bridge.models import ThreatCategory, ThreatEvent, ThreatStatus, utc_now


TITLE_TO_CATEGORY: dict[str, ThreatCategory] = {
    "Brute Force": "identity",
    "Credential Stuffing": "identity",
    "Login Attempt": "identity",
    "Port Scan": "network",
    "SSH Connection": "network",
    "SQL Injection": "application",
    "File Access": "endpoint",
}

STATUS_MAP: dict[str, ThreatStatus] = {
    "active": "active",
    "failed": "failed",
    "success": "success",
    "denied": "denied",
    "mitigated": "mitigated",
}


def _build_event_id(source_system: str, raw_payload: dict[str, Any], ingested_at: datetime) -> str:
    canonical = json.dumps(raw_payload, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha1(f"{source_system}|{canonical}|{ingested_at.isoformat()}".encode("utf-8")).hexdigest()[:16]
    return f"evt_{digest}"


def _build_stable_event_id(source_system: str, raw_payload: dict[str, Any]) -> str:
    canonical = json.dumps(raw_payload, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha1(f"{source_system}|{canonical}".encode("utf-8")).hexdigest()[:16]
    return f"evt_{digest}"


def _category_for_title(title: str) -> ThreatCategory:
    return TITLE_TO_CATEGORY.get(title, "unknown")


def _normalize_status(status: str | None, default: ThreatStatus = "active") -> ThreatStatus:
    if not status:
        return default
    return STATUS_MAP.get(status.strip().lower(), default)


def _parse_legacy_timestamp(value: Any, fallback: datetime) -> datetime:
    if isinstance(value, datetime):
        return value.astimezone(fallback.tzinfo) if value.tzinfo else value.replace(tzinfo=fallback.tzinfo)

    if isinstance(value, str) and value.strip():
        normalized = value.replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(normalized)
            return parsed.astimezone(fallback.tzinfo) if parsed.tzinfo else parsed.replace(tzinfo=fallback.tzinfo)
        except ValueError:
            return fallback

    return fallback


def _parse_simulator_timestamp(value: Any, ingested_at: datetime) -> datetime:
    if not isinstance(value, str) or not value.strip():
        return ingested_at

    try:
        parsed_time = datetime.strptime(value.strip(), "%H:%M:%S").time()
    except ValueError:
        return ingested_at

    local_now = datetime.now().astimezone()
    combined = datetime.combine(date.today(), parsed_time, tzinfo=local_now.tzinfo)
    return combined.astimezone(ingested_at.tzinfo)


def normalize_attack_sim_event(
    payload: Mapping[str, Any],
    ingested_at: datetime | None = None,
) -> ThreatEvent:
    ingested_at = ingested_at or utc_now()
    raw_payload = dict(payload)
    title = str(raw_payload.get("type", "Unknown Activity")).strip() or "Unknown Activity"
    origin = str(raw_payload.get("origin", "unknown")).strip() or "unknown"
    raw_severity = raw_payload.get("severity")
    severity = int(raw_severity) if raw_severity is not None else None

    return ThreatEvent(
        id=_build_event_id("attack_sim", raw_payload, ingested_at),
        source_system="attack_sim",
        source_type="simulator",
        observed_at=_parse_simulator_timestamp(raw_payload.get("time"), ingested_at),
        ingested_at=ingested_at,
        title=title,
        category=_category_for_title(title),
        origin=origin,
        status="active",
        raw_severity=severity,
        risk_score=0,
        risk_level="low",
        summary="",
        recommended_action="",
        raw=raw_payload,
    )


def normalize_legacy_event(
    payload: Mapping[str, Any],
    ingested_at: datetime | None = None,
) -> ThreatEvent:
    ingested_at = ingested_at or utc_now()
    raw_payload = dict(payload)
    title = str(raw_payload.get("Event", "Legacy Activity")).strip() or "Legacy Activity"
    origin = str(raw_payload.get("Source", "unknown")).strip() or "unknown"
    status = _normalize_status(raw_payload.get("Status"), default="active")

    return ThreatEvent(
        id=_build_stable_event_id("legacy_api", raw_payload),
        source_system="legacy_api",
        source_type="legacy",
        observed_at=_parse_legacy_timestamp(raw_payload.get("Timestamp"), ingested_at),
        ingested_at=ingested_at,
        title=title,
        category=_category_for_title(title),
        origin=origin,
        status=status,
        raw_severity=None,
        risk_score=0,
        risk_level="low",
        summary="",
        recommended_action="",
        raw=raw_payload,
    )
