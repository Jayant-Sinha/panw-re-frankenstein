"""Local control actions for the demo stack."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from bridge.config import Settings


@dataclass(frozen=True, slots=True)
class MitigationResult:
    success: bool
    action: str
    message: str
    simulator_status: str
    terminated: bool
    pid: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "action": self.action,
            "message": self.message,
            "simulator_status": self.simulator_status,
            "terminated": self.terminated,
            "pid": self.pid,
        }


def stop_attack_simulator(settings: Settings, current_status: str | None = None) -> MitigationResult:
    pid_path = settings.attack_sim_pid_path
    current_status = (current_status or "").lower()

    pid_value = _read_pid_file(pid_path)
    if pid_value is None:
        simulator_status = "mitigated" if current_status == "mitigated" else "offline"
        message = "Attack simulator already stopped." if simulator_status == "mitigated" else "Attack simulator PID file was not found."
        return MitigationResult(
            success=True,
            action="mitigate",
            message=message,
            simulator_status=simulator_status,
            terminated=False,
        )

    metadata = _get_process_metadata(pid_value)
    if metadata is None:
        _cleanup_pid_file(pid_path)
        simulator_status = "mitigated" if current_status == "mitigated" else "offline"
        return MitigationResult(
            success=True,
            action="mitigate",
            message="Attack simulator was already stopped. Cleaned up stale PID file.",
            simulator_status=simulator_status,
            terminated=False,
            pid=pid_value,
        )

    if not _is_attack_simulator_process(metadata) and not _matches_pid_marker_process(
        pid_path, pid_value, {"powershell", "pwsh"}
    ):
        return MitigationResult(
            success=False,
            action="mitigate",
            message="PID file does not point to the expected attack simulator process.",
            simulator_status="offline",
            terminated=False,
            pid=pid_value,
        )

    if not _terminate_process(pid_value):
        return MitigationResult(
            success=False,
            action="mitigate",
            message="Attack simulator termination failed.",
            simulator_status="offline",
            terminated=False,
            pid=pid_value,
        )

    _cleanup_pid_file(pid_path)
    return MitigationResult(
        success=True,
        action="mitigate",
        message="Attack simulator terminated.",
        simulator_status="mitigated",
        terminated=True,
        pid=pid_value,
    )


def _read_pid_file(pid_path: Path) -> int | None:
    if not pid_path.exists():
        return None

    raw_value = pid_path.read_text(encoding="utf-8").strip()
    if not raw_value:
        _cleanup_pid_file(pid_path)
        return None

    try:
        return int(raw_value)
    except ValueError:
        _cleanup_pid_file(pid_path)
        return None


def _get_process_metadata(pid: int) -> dict[str, Any] | None:
    powershell_script = (
        f"$process = Get-CimInstance Win32_Process -Filter \"ProcessId = {pid}\"; "
        "if ($null -eq $process) { exit 0 }; "
        "$process | Select-Object ProcessId, Name, CommandLine | ConvertTo-Json -Compress"
    )

    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", powershell_script],
        capture_output=True,
        text=True,
        check=False,
    )

    stdout = result.stdout.strip()
    if not stdout:
        return None

    try:
        metadata = json.loads(stdout)
    except json.JSONDecodeError:
        return None

    return metadata if isinstance(metadata, dict) else None


def _is_attack_simulator_process(metadata: dict[str, Any]) -> bool:
    process_name = str(metadata.get("Name", "")).lower()
    command_line = str(metadata.get("CommandLine", "")).lower()

    if process_name not in {"powershell.exe", "pwsh.exe"}:
        return False

    return "attacksim.ps1" in command_line and "simulator" in command_line


def _matches_pid_marker_process(pid_path: Path, pid: int, process_names: set[str]) -> bool:
    """Verify a PID marker against process name and its recorded start time.

    Some managed Windows environments deny Win32_Process command-line queries.
    The simulator writes its own PID marker immediately after process start, so
    matching that marker's timestamp against Get-Process provides a safe fallback
    without treating an unrelated process that later reused the PID as managed.
    """
    try:
        if int(pid_path.read_text(encoding="utf-8").strip()) != pid:
            return False
        marker_time = pid_path.stat().st_mtime
    except (OSError, ValueError):
        return False

    powershell_script = (
        f"$process = Get-Process -Id {pid} -ErrorAction SilentlyContinue; "
        "if ($null -eq $process) { exit 0 }; "
        "$process | Select-Object Id, ProcessName, @{Name='StartedUtc';Expression={$_.StartTime.ToUniversalTime().ToString('o')}} | ConvertTo-Json -Compress"
    )
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", powershell_script],
        capture_output=True,
        text=True,
        check=False,
    )
    try:
        metadata = json.loads(result.stdout.strip())
        process_name = str(metadata.get("ProcessName", "")).lower()
        process_id = int(metadata.get("Id", -1))
        started = datetime.fromisoformat(str(metadata.get("StartedUtc", "")).replace("Z", "+00:00")).timestamp()
    except (json.JSONDecodeError, AttributeError, TypeError, ValueError):
        return False

    return process_id == pid and process_name in process_names and abs(started - marker_time) <= 15


def _terminate_process(pid: int) -> bool:
    result = subprocess.run(
        ["taskkill", "/PID", str(pid), "/T", "/F"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode == 0:
        return True

    powershell_script = (
        f"Stop-Process -Id {pid} -Force -ErrorAction SilentlyContinue; "
        "Start-Sleep -Milliseconds 150; "
        f"if (Get-Process -Id {pid} -ErrorAction SilentlyContinue) {{ exit 1 }}"
    )
    fallback = subprocess.run(
        ["powershell", "-NoProfile", "-Command", powershell_script],
        capture_output=True,
        text=True,
        check=False,
    )
    return fallback.returncode == 0


def _cleanup_pid_file(pid_path: Path) -> None:
    try:
        pid_path.unlink(missing_ok=True)
        if pid_path.name == "attack-sim.pid":
            pid_path.with_name("attack-sim-types.json").unlink(missing_ok=True)
    except OSError:
        return
