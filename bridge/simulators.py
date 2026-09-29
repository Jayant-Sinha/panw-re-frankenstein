"""Validated lifecycle controls for the local demo sources."""

from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

from bridge.config import Settings
from bridge.control import (
    _get_process_metadata,
    _is_attack_simulator_process,
    _matches_pid_marker_process,
    _terminate_process,
)


ATTACK_TYPES = ("Brute Force", "SQL Injection", "Port Scan", "Credential Stuffing")


def start_attack_simulator(settings: Settings, attack_types: list[str]) -> dict[str, Any]:
    selected = list(dict.fromkeys(attack_types))
    if not selected or any(item not in ATTACK_TYPES for item in selected):
        return {"success": False, "message": "Select one or more supported attack types."}
    current = attack_simulator_status(settings)
    if current["running"]:
        return {"success": False, "message": "The attack simulator is already running. Stop it before changing attack types.", **current}

    settings.attack_sim_pid_path.parent.mkdir(parents=True, exist_ok=True)
    types_path = settings.attack_sim_pid_path.with_name("attack-sim-types.json")
    log_path = settings.attack_sim_pid_path.with_name("attack-sim.log")
    command = [
        "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(settings.attack_simulator_path),
        "-AttackTypes", *selected,
    ]
    try:
        with log_path.open("ab") as log_file:
            flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            process = subprocess.Popen(
                command,
                cwd=settings.attack_simulator_path.parent.parent,
                stdin=subprocess.DEVNULL,
                stdout=log_file,
                stderr=subprocess.STDOUT,
                creationflags=flags,
            )
        settings.attack_sim_pid_path.write_text(str(process.pid), encoding="utf-8")
        types_path.write_text(json.dumps(selected), encoding="utf-8")
        time.sleep(0.25)
        if process.poll() is not None:
            settings.attack_sim_pid_path.unlink(missing_ok=True)
            types_path.unlink(missing_ok=True)
            return {"success": False, "message": f"Attack simulator exited during startup. See {log_path} for details."}
    except OSError as exc:
        return {"success": False, "message": f"Could not start the attack simulator: {exc}"}
    return {
        "success": True,
        "running": True,
        "attack_types": selected,
        "pid": process.pid,
        "message": f"Started attack simulation: {', '.join(selected)}.",
    }


def attack_simulator_status(settings: Settings) -> dict[str, Any]:
    pid = _read_pid(settings.attack_sim_pid_path)
    metadata = _get_process_metadata(pid) if pid else None
    running = bool(
        (metadata and _is_attack_simulator_process(metadata))
        or (pid and _matches_pid_marker_process(settings.attack_sim_pid_path, pid, {"powershell", "pwsh"}))
    )
    if not running and pid:
        settings.attack_sim_pid_path.unlink(missing_ok=True)
        settings.attack_sim_pid_path.with_name("attack-sim-types.json").unlink(missing_ok=True)
    types: list[str] = []
    type_path = settings.attack_sim_pid_path.with_name("attack-sim-types.json")
    if running and type_path.exists():
        try:
            payload = json.loads(type_path.read_text(encoding="utf-8"))
            types = [item for item in payload if item in ATTACK_TYPES] if isinstance(payload, list) else []
        except (OSError, ValueError):
            types = []
    return {"running": running, "attack_types": types, "pid": pid if running else None}


def stop_attack_simulator_only(settings: Settings) -> dict[str, Any]:
    status = attack_simulator_status(settings)
    if not status["running"]:
        return {"success": True, "running": False, "message": "Attack simulator is already stopped."}
    pid = status["pid"]
    if not _terminate_process(pid):
        return {"success": False, **status, "message": "Could not stop the attack simulator."}
    settings.attack_sim_pid_path.unlink(missing_ok=True)
    settings.attack_sim_pid_path.with_name("attack-sim-types.json").unlink(missing_ok=True)
    return {"success": True, "running": False, "message": "Attack simulator stopped."}


def start_legacy_service(settings: Settings, source_online: bool) -> dict[str, Any]:
    current = legacy_service_status(settings)
    if current["running"] or source_online or _legacy_api_reachable(settings):
        return {"success": True, **current, "running": True, "message": "Legacy API is already online."}
    settings.legacy_pid_path.parent.mkdir(parents=True, exist_ok=True)
    log_path = settings.legacy_pid_path.with_name("legacy-api.log")
    command = ["dotnet", "run", "--no-launch-profile", "--project", str(settings.legacy_project_path)]
    try:
        with log_path.open("ab") as log_file:
            flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            process = subprocess.Popen(
                command,
                cwd=settings.legacy_project_path.parent,
                stdin=subprocess.DEVNULL,
                stdout=log_file,
                stderr=subprocess.STDOUT,
                creationflags=flags,
            )
        settings.legacy_pid_path.write_text(str(process.pid), encoding="utf-8")
        time.sleep(0.25)
        if process.poll() is not None:
            settings.legacy_pid_path.unlink(missing_ok=True)
            return {"success": False, "running": False, "message": f"Legacy API exited during startup. See {log_path} for details."}
    except OSError as exc:
        return {"success": False, "running": False, "message": f"Could not start the legacy API: {exc}"}
    return {"success": True, "running": True, "managed": True, "pid": process.pid, "message": "Started the Legacy API."}


def legacy_service_status(settings: Settings) -> dict[str, Any]:
    pid = _read_pid(settings.legacy_pid_path)
    metadata = _get_process_metadata(pid) if pid else None
    command_line = str(metadata.get("CommandLine", "")).lower() if metadata else ""
    process_name = str(metadata.get("Name", "")).lower() if metadata else ""
    running = bool(
        (metadata and process_name in {"dotnet.exe", "dotnet"} and "legacylogger" in command_line)
        or (pid and _matches_pid_marker_process(settings.legacy_pid_path, pid, {"dotnet"}))
    )
    if pid and not running:
        settings.legacy_pid_path.unlink(missing_ok=True)
    return {"running": running, "managed": running, "pid": pid if running else None}


def stop_legacy_service(settings: Settings) -> dict[str, Any]:
    status = legacy_service_status(settings)
    if not status["running"]:
        return {"success": False, **status, "message": "Legacy API is not managed by this dashboard. Stop it from the terminal that started it."}
    if not _terminate_process(status["pid"]):
        return {"success": False, **status, "message": "Could not stop the managed Legacy API process."}
    settings.legacy_pid_path.unlink(missing_ok=True)
    return {"success": True, "running": False, "managed": False, "message": "Legacy API stopped."}


def _read_pid(path: Path) -> int | None:
    try:
        return int(path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None


def _legacy_api_reachable(settings: Settings) -> bool:
    try:
        with urlopen(settings.legacy_api_url, timeout=1):
            return True
    except HTTPError:
        return True
    except (OSError, URLError, TimeoutError, ValueError):
        return False
