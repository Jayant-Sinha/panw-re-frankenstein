# Project Frankenstein 2.0

Project Frankenstein is a defensive cybersecurity simulation and incident-response command center. It correlates legacy ASP.NET telemetry with a controlled PowerShell attack simulator, enriches and scores events in a Python analytics bridge, and streams the operational picture to a live dashboard. Operators can start or stop each source, mitigate individual alerts, or stop the attack simulator and mitigate the active buffer. A hosted Gemini model generates evidence-linked SOC analyst briefs; the system also preserves investigation history in a local SQLite archive.

## Architecture

- `legacy/LegacyLogger`: intentionally simple ASP.NET Minimal API that exposes `GET /api/raw-logs`.
- `simulator/AttackSim.ps1`: external live threat generator that appends one JSON event per line to `live_stream.log` using UTF-8 encoding and writes its process ID to `runtime/attack-sim.pid`.
- `bridge/`: Python analytics bridge that ingests source data, normalizes and scores events, serves the UI, streams state with SSE, and owns the mitigation control path.
- `scripts/start-demo.ps1`: convenience launcher for local demo setup.

## Current Status

The current implementation includes dual-source ingestion, normalized event scoring, live posture and source health, SSE updates, per-alert mitigation, threshold-based auto-mitigation, Mitigate All, source launch controls, a Gemini incident intelligence brief, and durable investigation history. The operational live buffer remains in memory and is capped at 200 events; the separate SQLite archive retains events and response status across restarts. This remains a local simulation platform rather than a production endpoint-protection product.

## Dashboard Overview

The dashboard is served by the Python bridge at `http://127.0.0.1:8000/` and updates from the bridge's event stream. Its main areas are:

- **Global risk overview:** current risk score and level, active and recent event counts, high/critical event count, source health, and short trend indicators.
- **Priority action and incident focus:** the highest-priority unresolved event, its risk score, origin, source, observed time, status, explanation, and recommended action. Expand **Investigation context** for event identifiers and normalized fields; the raw source payload is available separately for inspection.
- **Simulator launchers:** expand the panel to start or stop the legacy ASP.NET source and to select one or more attack types (Brute Force, SQL Injection, Port Scan, and Credential Stuffing) for the PowerShell simulator. Running types are shown as selected and locked while that simulator is active.
- **Response controls:** use an event-row **Mitigate** to update one alert, **Mitigate All** to stop the tracked local attack simulator and mark buffered events mitigated, or the adjacent auto-mitigation switch to enable or disable automatic status updates.
- **Pipeline status:** see whether the bridge, legacy API, and attack simulator are available.
- **Incident intelligence brief:** request an optional evidence-linked advisory from the hosted Gemini API when a key is configured and Gemini is available. The brief includes findings, possible correlations, defensive next steps, and limitations.
- **Operator queue:** browse normalized live events; filter by severity and source, search title/source/origin IP, sort by newest or risk, inspect an event, and apply per-event mitigation.
- **Investigation history:** expand the persistent archive to select a 7-, 30-, or 90-day window, view attack volume, severity/category/source distributions and archived events, load more records, or download the CSV report.
- **Recent telemetry patterns:** view live risk movement and event distributions by category and source.

The live queue is an in-memory buffer. The SQLite archive stores normalized event history and mitigation status beyond the queue's 200-event limit and across bridge restarts. Charts summarize the available records for the selected window; they are descriptive views of the simulated telemetry, not independent detections.

## Start The Legacy Service

From the repository root:

```powershell
dotnet run --project .\legacy\LegacyLogger
```

The service exposes:

- `GET http://localhost:5042/api/raw-logs`

## Start The Simulator

From the repository root:

```powershell
powershell -ExecutionPolicy Bypass -File .\simulator\AttackSim.ps1
```

By default, the simulator writes newline-delimited JSON to `./live_stream.log` at the repository root using UTF-8 without BOM so the Python bridge can read it reliably.

The simulator also writes its PowerShell process ID to `./runtime/attack-sim.pid` so the bridge can identify and stop the correct process during mitigation.

## Bridge Role

The Python bridge:

- watches `live_stream.log`
- polls the legacy API
- normalizes both inputs into a single event contract
- scores threat severity deterministically
- exposes real-time data to the frontend
- provides a control endpoint that stops the simulator process for the live demo

## Start The Bridge

After creating the local virtual environment and installing dependencies:

```powershell
.\.venv\Scripts\python -m bridge.main
```

The bridge exposes:

- `GET http://127.0.0.1:8000/api/health`
- `GET http://127.0.0.1:8000/api/state`
- `GET http://127.0.0.1:8000/api/events`
- `GET http://127.0.0.1:8000/api/events/stream`
- `POST http://127.0.0.1:8000/api/control/mitigate`
- `POST http://127.0.0.1:8000/api/events/{event_id}/mitigate`
- `GET http://127.0.0.1:8000/api/ai/status`
- `POST http://127.0.0.1:8000/api/ai/brief`
- `GET http://127.0.0.1:8000/api/simulators/status`
- `POST http://127.0.0.1:8000/api/simulators/attack/start`
- `POST http://127.0.0.1:8000/api/simulators/attack/stop`
- `POST http://127.0.0.1:8000/api/simulators/legacy/start`
- `POST http://127.0.0.1:8000/api/simulators/legacy/stop`
- `POST http://127.0.0.1:8000/api/automation/auto-mitigate`
- `GET http://127.0.0.1:8000/api/history/summary`
- `GET http://127.0.0.1:8000/api/history/events`
- `GET http://127.0.0.1:8000/api/history/export.csv`

## Response controls

- Each feed row has **Mitigate**. It changes that event's status to `mitigated` in the bridge's active state and SQLite archive, then updates the feed/posture. It does not stop either source or change a real endpoint.
- **Mitigate All** uses the existing control path: the bridge validates the PID/process identity and stops the local `AttackSim.ps1` process, then marks all buffered events from both sources mitigated. If simulator termination fails, it does not report all alerts as mitigated.
- The source launcher at the top of the dashboard starts/stops the local ASP.NET Legacy API and starts/stops `AttackSim.ps1` for selected attack types. Only processes tracked and validated by the bridge can be stopped from the UI.
- Auto-mitigation is on by default. When the live buffer reaches 200 events, it resolves up to five oldest unresolved critical events; while full it checks again after each five newly ingested events. It changes event status only and does not stop either source. Toggle it off beside **Mitigate All** to disable it.
- Investigation history is stored in `runtime/investigation-history.sqlite3`, separate from the in-memory 200-event buffer. The archive view includes time, severity, category, source charts, paged event records, and a CSV report.

This is a genuine local process-control action against the demo simulator, not production endpoint containment. Keep the bridge bound to loopback unless an authenticated and authorized control plane is added.

## Hosted Gemini analyst

The incident intelligence brief uses Google's Gemini API. It analyzes up to 30 bounded, normalized recent events and the current posture, then returns an assessment, key findings, possible correlations linked to event IDs, defensive next steps, and limitations. The API key stays in the bridge environment and is never sent to the browser. Raw event payloads are excluded. The model is advisory only: it has no tools and cannot trigger mitigation.

Create a Gemini API key in [Google AI Studio](https://aistudio.google.com/apikey), copy `.env.example` to `.env`, and replace the placeholder with the key:

```powershell
Copy-Item .env.example .env
notepad .env
```

Restart the Python bridge after saving `.env`. The dashboard checks that a key is configured and enables **Generate brief**. The default model is `gemini-3.8-flash`; set `BRIDGE_GEMINI_MODEL` in `.env` to change it. Gemini's free tier has quotas and may change; never use this demo key as a production credential.

## Demo Sequence

1. Start the legacy API.
2. Start the attack simulator.
3. Start the Python bridge.
4. Open `http://127.0.0.1:8000/` and wait for several threats.
5. Allow a high or critical event to appear in the feed.
6. Optionally generate the hosted Gemini incident brief and inspect its event-linked evidence and caveats. This feature requires a configured API key, internet access, and Gemini availability; it can be unavailable during provider outages or quota limits.
7. Use a row-level **Mitigate** to close one alert while both sources continue running.
8. Click **Mitigate All** to stop the simulator and mark all buffered events from both feeds mitigated.
9. Restart the simulator to demonstrate recovery and live attack activity returning.

## Prerequisites

- .NET SDK (for the legacy ASP.NET demo)
- Python 3.10+ (virtualenv recommended)
- PowerShell (for running the simulator)
- A Gemini API key from Google AI Studio (required only for the AI brief)

## Setup

Create a local virtual environment and install Python dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt
```

## Run (recommended terminal layout)

Terminal 1 — Legacy API:

```powershell
dotnet run --project .\legacy\LegacyLogger
```

Terminal 2 — Simulator:

```powershell
powershell -ExecutionPolicy Bypass -File .\simulator\AttackSim.ps1
```

Terminal 3 — Analytics Bridge:

```powershell
.\.venv\Scripts\python -m bridge.main
```

Browser:

[http://127.0.0.1:8000](http://127.0.0.1:8000/)

## Architecture Decisions (brief)

- Python / FastAPI bridge: lightweight ingestion, normalization, deterministic scoring, and SSE streaming to keep the demo self-contained.
- Deterministic scoring: ensures repeatable demo behavior and predictable escalation.
- SSE: simple server-push model for the live dashboard without complex realtime infra.
- In-memory live state with a separate SQLite investigation archive: keeps the active queue bounded while retaining historical event records and response status.
- Normalized event contract: keeps UI rendering consistent across legacy and live simulator inputs.

## Configuration

The bridge reads `BRIDGE_GEMINI_API_KEY` and `BRIDGE_GEMINI_MODEL=gemini-3.8-flash` from the environment or ignored local `.env` file. The API call timeout defaults to 90 seconds. `BRIDGE_EVENT_BUFFER_SIZE=200`, `BRIDGE_AUTO_MITIGATE_THRESHOLD=199`, and `BRIDGE_AUTO_MITIGATE_BATCH_SIZE=5` configure the active feed and threshold behavior. Other polling and posture settings are listed in `bridge/config.py`.

## Operational boundary

This platform simulates security telemetry and response. Event-level and automatic mitigation update dashboard status; **Mitigate All** terminates only the local PowerShell simulator. The project does not block IPs, change firewall rules, or contain activity on external/customer endpoints. Event history is durable, but the app has no authentication, multi-user authorization, or production-grade audit trail; do not expose its control routes to an untrusted network. The Gemini brief sends bounded normalized telemetry to Google's API; the free tier's data handling differs from paid services, so use only synthetic demo records.

## Long-term build direction

The current changes are the first expansion step, not a claim of production readiness. The next development phases should build toward:

1. Scenario-driven, repeatable multi-stage attack campaigns with synthetic identities and assets, clear reset/replay controls, and ATT&CK technique references.
2. Richer incident and action history, source-health monitoring, deduplication/correlation, and exportable investigation timelines.
3. Authenticated operator access, role-based response permissions, approval gates, and auditable playbooks before any real integrations.
4. A deployment profile with secrets/configuration management, migrations, backups, observability, CI, and security review.

Keep the default range isolated and simulation-only as these phases are developed. Treat each capability as planned until it exists in code and has documented validation.
