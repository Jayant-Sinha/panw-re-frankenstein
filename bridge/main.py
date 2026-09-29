"""FastAPI entry point for the analytics bridge."""

from __future__ import annotations

import asyncio
import json
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from bridge.analyst import (
    AIResponseError,
    AIUnavailableError,
    generate_incident_brief,
    get_ai_status,
)
from bridge.config import settings
from bridge.control import stop_attack_simulator
from bridge.history import HistoryStore
from bridge.ingest_legacy import poll_legacy_source
from bridge.ingest_live_log import watch_live_log
from bridge.simulators import (
    ATTACK_TYPES,
    attack_simulator_status,
    legacy_service_status,
    start_attack_simulator,
    start_legacy_service,
    stop_attack_simulator_only,
    stop_legacy_service,
)
from bridge.state import BridgeState


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)


class AttackSimulationRequest(BaseModel):
    attack_types: list[str] = Field(min_length=1, max_length=len(ATTACK_TYPES))


class AutoMitigationRequest(BaseModel):
    enabled: bool


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    history = HistoryStore(settings.history_db_path)
    bridge_state = BridgeState(
        event_buffer_size=settings.event_buffer_size,
        posture_decay_seconds=settings.posture_decay_seconds,
        history=history,
        auto_mitigate_threshold=settings.auto_mitigate_threshold,
        auto_mitigate_batch_size=settings.auto_mitigate_batch_size,
    )
    stop_event = asyncio.Event()
    tasks = [
        asyncio.create_task(watch_live_log(settings, bridge_state, stop_event), name="watch-live-log"),
        asyncio.create_task(poll_legacy_source(settings, bridge_state, stop_event), name="poll-legacy-source"),
    ]

    app.state.bridge_state = bridge_state
    app.state.history = history
    app.state.stop_event = stop_event
    app.state.background_tasks = tasks

    yield

    stop_event.set()
    await asyncio.gather(*tasks, return_exceptions=True)


app = FastAPI(title="Project Frankenstein Analytics Bridge", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=settings.static_dir), name="static")
INDEX_FILE = Path(settings.static_dir) / "index.html"


@app.get("/", include_in_schema=False)
async def root() -> FileResponse:
    return FileResponse(INDEX_FILE)


@app.get("/api/health")
async def health(request: Request) -> JSONResponse:
    bridge_state: BridgeState = request.app.state.bridge_state
    source_health = await bridge_state.get_health_snapshot()
    return JSONResponse(
        {
            "bridge": {"status": "online"},
            "sources": source_health,
        }
    )


@app.get("/api/state")
async def state(request: Request) -> JSONResponse:
    bridge_state: BridgeState = request.app.state.bridge_state
    return JSONResponse(await bridge_state.get_state())


@app.get("/api/events")
async def events(request: Request) -> JSONResponse:
    bridge_state: BridgeState = request.app.state.bridge_state
    return JSONResponse({"events": await bridge_state.get_events()})


@app.post("/api/events/{event_id}/mitigate")
async def mitigate_event(event_id: str, request: Request) -> JSONResponse:
    bridge_state: BridgeState = request.app.state.bridge_state
    event = await bridge_state.mitigate_event(event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="Event is no longer in the active event buffer.")
    return JSONResponse({"success": True, "event": event})


@app.get("/api/ai/status")
async def ai_status() -> JSONResponse:
    return JSONResponse(await get_ai_status(settings))


@app.post("/api/ai/brief")
async def ai_incident_brief(request: Request) -> JSONResponse:
    bridge_state: BridgeState = request.app.state.bridge_state
    snapshot = await bridge_state.get_state()
    posture = {
        "global_risk_score": snapshot["global_risk_score"],
        "global_threat_level": snapshot["global_threat_level"],
        "active_event_count": snapshot["active_event_count"],
    }

    try:
        brief = await generate_incident_brief(settings, snapshot["events"], posture)
    except AIUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except AIResponseError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return JSONResponse(brief)


@app.get("/api/history/summary")
async def history_summary(request: Request, days: int = 30) -> JSONResponse:
    if days < 1 or days > 365:
        raise HTTPException(status_code=422, detail="Days must be between 1 and 365.")
    history: HistoryStore = request.app.state.history
    return JSONResponse(history.summary(days))


@app.get("/api/history/events")
async def history_events(request: Request, limit: int = 200, offset: int = 0) -> JSONResponse:
    history: HistoryStore = request.app.state.history
    return JSONResponse({"events": history.events(limit, offset)})


@app.get("/api/history/export.csv")
async def export_history(request: Request) -> Response:
    history: HistoryStore = request.app.state.history
    return Response(
        content=history.export_csv(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=frankenstein-investigation-history.csv"},
    )


@app.post("/api/automation/auto-mitigate")
async def set_auto_mitigation(payload: AutoMitigationRequest, request: Request) -> JSONResponse:
    bridge_state: BridgeState = request.app.state.bridge_state
    return JSONResponse(await bridge_state.set_auto_mitigation(payload.enabled))


@app.get("/api/simulators/status")
async def simulator_status(request: Request) -> JSONResponse:
    bridge_state: BridgeState = request.app.state.bridge_state
    source_status = await bridge_state.get_source_status("legacy_api")
    legacy = legacy_service_status(settings)
    legacy["online"] = bool(legacy["running"] or source_status == "online")
    legacy["managed"] = bool(legacy["managed"])
    return JSONResponse({
        "attack_types": list(ATTACK_TYPES),
        "attack_sim": attack_simulator_status(settings),
        "legacy_api": legacy,
    })


@app.post("/api/simulators/attack/start")
async def start_attack(payload: AttackSimulationRequest, request: Request) -> JSONResponse:
    result = start_attack_simulator(settings, payload.attack_types)
    if result.get("success"):
        bridge_state: BridgeState = request.app.state.bridge_state
        await bridge_state.record_source_health(
            "attack_sim", available=False, status="waiting", error="Waiting for first generated event.",
            details={"pid": result.get("pid"), "attack_types": result.get("attack_types", [])},
        )
    return JSONResponse(result, status_code=200 if result.get("success") else 409)


@app.post("/api/simulators/attack/stop")
async def stop_attack(request: Request) -> JSONResponse:
    result = stop_attack_simulator_only(settings)
    if result.get("success"):
        bridge_state: BridgeState = request.app.state.bridge_state
        await bridge_state.record_source_health(
            "attack_sim", available=False, status="offline", error="Attack simulator stopped from the dashboard.",
            details={"action": "stop"},
        )
    return JSONResponse(result, status_code=200 if result.get("success") else 409)


@app.post("/api/simulators/legacy/start")
async def start_legacy(request: Request) -> JSONResponse:
    bridge_state: BridgeState = request.app.state.bridge_state
    source_online = await bridge_state.get_source_status("legacy_api") == "online"
    result = start_legacy_service(settings, source_online)
    if result.get("success") and not source_online:
        await bridge_state.record_source_health(
            "legacy_api", available=False, status="waiting", error="Legacy API starting.",
            details={"pid": result.get("pid")},
        )
    return JSONResponse(result, status_code=200 if result.get("success") else 409)


@app.post("/api/simulators/legacy/stop")
async def stop_legacy(request: Request) -> JSONResponse:
    result = stop_legacy_service(settings)
    if result.get("success"):
        bridge_state: BridgeState = request.app.state.bridge_state
        await bridge_state.record_source_health(
            "legacy_api", available=False, status="offline", error="Legacy API stopped from the dashboard.",
            details={"action": "stop"},
        )
    return JSONResponse(result, status_code=200 if result.get("success") else 409)


@app.get("/api/events/stream")
async def event_stream(request: Request) -> StreamingResponse:
    bridge_state: BridgeState = request.app.state.bridge_state
    subscriber = await bridge_state.subscribe()

    async def stream() -> AsyncIterator[str]:
        try:
            initial_state = await bridge_state.get_state()
            yield _format_sse("state", initial_state)

            while True:
                if await request.is_disconnected():
                    break

                try:
                    message = await asyncio.wait_for(
                        subscriber.get(),
                        timeout=settings.state_stream_interval_seconds,
                    )
                except asyncio.TimeoutError:
                    yield _format_sse("state", await bridge_state.get_state())
                    continue

                yield _format_sse(message["event"], message["data"])
        finally:
            await bridge_state.unsubscribe(subscriber)

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


def _format_sse(event_name: str, payload: dict[str, object]) -> str:
    return f"event: {event_name}\ndata: {json.dumps(payload)}\n\n"


@app.post("/api/control/mitigate")
async def mitigate_attack(request: Request) -> JSONResponse:
    bridge_state: BridgeState = request.app.state.bridge_state
    current_status = await bridge_state.get_source_status("attack_sim")
    result = stop_attack_simulator(settings, current_status=current_status)

    if result.simulator_status == "mitigated":
        await bridge_state.mark_source_mitigated(
            "attack_sim",
            result.message,
            details={"pid": result.pid, "action": result.action},
        )
    elif result.simulator_status in {"offline", "waiting"}:
        await bridge_state.record_source_health(
            "attack_sim",
            available=False,
            status=result.simulator_status,
            error=result.message,
            details={"pid": result.pid, "action": result.action},
        )

    mitigated_events = await bridge_state.mitigate_all_events() if result.success else []
    response = result.to_dict()
    response["events_mitigated"] = len(mitigated_events)
    response["message"] = (
        f"All attacks mitigated. Simulator {result.simulator_status}; "
        f"{len(mitigated_events)} event(s) marked mitigated."
        if result.success
        else result.message
    )
    return JSONResponse(response, status_code=200 if result.success else 409)


def main() -> None:
    uvicorn.run(
        "bridge.main:app",
        host=settings.host,
        port=settings.port,
        reload=False,
    )


if __name__ == "__main__":
    main()
