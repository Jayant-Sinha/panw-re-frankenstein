# Project Frankenstein 2.0 — Demo Instructions

## Prerequisites

- Windows + PowerShell
- .NET SDK
- Python 3.10+
- Chrome or Edge
- A Gemini API key from Google AI Studio (only needed for the AI brief)
- Repository root: `C:\PANW-L2\tc-Frankenstein`

## Setup

From the repository root:

```powershell
python -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt
```

For Gemini, create an API key at [Google AI Studio](https://aistudio.google.com/apikey), then copy and edit the ignored local configuration file:

```powershell
Copy-Item .env.example .env
notepad .env
```

Replace the key placeholder, save, and restart the bridge. Keep `.env` private; it is excluded from Git.

## Start the Bridge

```powershell
.\.venv\Scripts\python -m bridge.main
```

Open `http://127.0.0.1:8000/`. The bridge and dashboard run on loopback.

## Start Data Sources from the Dashboard

1. Expand **Simulator launchers** in the top panel.
2. Use **Start legacy source** to start the local ASP.NET API.
3. Select one or more attack types under **Attack simulation**, then choose **Start selected attacks**.
4. A running attack type is checked and locked until you stop the simulation. The selected set runs in one PowerShell process and writes to `live_stream.log`.

The source launchers manage only local demo processes. The legacy source can still be started from a terminal. A service already launched externally is shown as online but cannot be stopped by the dashboard.

## Demo Walkthrough

1. Start one or both sources from the dashboard and wait for events.
2. Select an incident and review its risk, origin, explanation, and recommended action.
3. Optionally choose **Generate brief** for a Gemini-generated advisory correlation summary linked to event IDs.
4. Use a row-level **Mitigate** to resolve one event while its source keeps running.
5. Leave **Auto-mitigate** on to resolve up to five oldest unresolved critical events when the 200-event buffer reaches capacity, then after each five additional events while full. The slider beside **Mitigate All** turns this behavior off or on and displays its latest action.
6. Use **Mitigate All** to stop the PowerShell attack simulator and mark all events in the live buffer mitigated.
7. Expand **Investigation history** below the live queue for archived timelines, severity and source distributions, the event log, and a downloadable CSV report.

The live queue remains a 200-event in-memory buffer. Every normalized event and status change is also written to `runtime/investigation-history.sqlite3`, so the investigation history remains after events roll out of the queue and after the bridge restarts.

The Gemini analyst receives only bounded normalized event fields, not raw payloads. It cannot call tools or mitigate events. The API key stays server-side. The Gemini free tier has quotas and different data-use terms from paid services; this demo uses synthetic training events only.

## Useful Checks

```powershell
curl.exe http://127.0.0.1:5042/api/raw-logs
curl.exe http://127.0.0.1:8000/api/health
curl.exe http://127.0.0.1:8000/api/state
curl.exe http://127.0.0.1:8000/api/history/summary
```

## Troubleshooting

If port `5042` or `8000` is already in use:

```powershell
netstat -ano | findstr ":5042"
netstat -ano | findstr ":8000"
```

If a dashboard-started source fails to launch, inspect `runtime/legacy-api.log` or `runtime/attack-sim.log`. If a simulator process exits unexpectedly, check for an older `AttackSim.ps1` process before deleting its stale `runtime/attack-sim.pid` file.
