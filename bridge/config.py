"""Small environment-based configuration for the bridge."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = Path(__file__).resolve().parent / "static"
RUNTIME_DIR = BASE_DIR / "runtime"


def _load_project_env() -> None:
    env_path = BASE_DIR / ".env"
    if not env_path.is_file():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        value = line.strip()
        if not value or value.startswith("#") or "=" not in value:
            continue
        name, content = value.split("=", 1)
        name = name.strip()
        content = content.strip().strip("\"'")
        if name and content:
            os.environ.setdefault(name, content)


def _env_float(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None:
        return default

    try:
        return float(value)
    except ValueError as exc:
        raise ValueError(f"Environment variable {name} must be a number.") from exc


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default

    try:
        return int(value)
    except ValueError as exc:
        raise ValueError(f"Environment variable {name} must be an integer.") from exc


@dataclass(frozen=True, slots=True)
class Settings:
    legacy_api_url: str
    legacy_poll_interval_seconds: float
    live_stream_path: Path
    live_log_offset_path: Path
    attack_sim_pid_path: Path
    event_buffer_size: int
    auto_mitigate_threshold: int
    auto_mitigate_batch_size: int
    history_db_path: Path
    http_timeout_seconds: float
    live_log_poll_interval_seconds: float
    live_log_stale_seconds: float
    posture_decay_seconds: float
    state_stream_interval_seconds: float
    attack_simulator_path: Path
    legacy_project_path: Path
    legacy_pid_path: Path
    ai_api_key: str
    ai_model: str
    ai_timeout_seconds: float
    host: str
    port: int
    static_dir: Path


def load_settings() -> Settings:
    ai_api_key = os.getenv("BRIDGE_GEMINI_API_KEY", "").strip()
    if ai_api_key.lower().startswith(("replace-", "your-")):
        ai_api_key = ""
    return Settings(
        legacy_api_url=os.getenv("BRIDGE_LEGACY_API_URL", "http://localhost:5042/api/raw-logs"),
        legacy_poll_interval_seconds=_env_float("BRIDGE_LEGACY_POLL_INTERVAL", 5.0),
        live_stream_path=Path(os.getenv("BRIDGE_LIVE_STREAM_PATH", str(BASE_DIR / "live_stream.log"))),
        live_log_offset_path=Path(os.getenv("BRIDGE_LIVE_LOG_OFFSET_PATH", str(RUNTIME_DIR / "live-stream-cursor.json"))),
        attack_sim_pid_path=Path(os.getenv("BRIDGE_ATTACK_SIM_PID_PATH", str(RUNTIME_DIR / "attack-sim.pid"))),
        event_buffer_size=_env_int("BRIDGE_EVENT_BUFFER_SIZE", 200),
        auto_mitigate_threshold=_env_int("BRIDGE_AUTO_MITIGATE_THRESHOLD", 199),
        auto_mitigate_batch_size=_env_int("BRIDGE_AUTO_MITIGATE_BATCH_SIZE", 5),
        history_db_path=Path(os.getenv("BRIDGE_HISTORY_DB_PATH", str(RUNTIME_DIR / "investigation-history.sqlite3"))),
        http_timeout_seconds=_env_float("BRIDGE_HTTP_TIMEOUT", 3.0),
        live_log_poll_interval_seconds=_env_float("BRIDGE_LOG_POLL_INTERVAL", 0.5),
        live_log_stale_seconds=_env_float("BRIDGE_LOG_STALE_SECONDS", 6.0),
        posture_decay_seconds=_env_float("BRIDGE_POSTURE_DECAY_SECONDS", 24.0),
        state_stream_interval_seconds=_env_float("BRIDGE_STATE_STREAM_INTERVAL", 2.0),
        attack_simulator_path=BASE_DIR / "simulator" / "AttackSim.ps1",
        legacy_project_path=BASE_DIR / "legacy" / "LegacyLogger",
        legacy_pid_path=Path(os.getenv("BRIDGE_LEGACY_PID_PATH", str(RUNTIME_DIR / "legacy-api.pid"))),
        ai_api_key=ai_api_key,
        ai_model=os.getenv("BRIDGE_GEMINI_MODEL", "gemini-3.8-flash"),
        ai_timeout_seconds=_env_float("BRIDGE_AI_TIMEOUT", 90.0),
        host=os.getenv("BRIDGE_HOST", "127.0.0.1"),
        port=_env_int("BRIDGE_PORT", 8000),
        static_dir=STATIC_DIR,
    )


_load_project_env()
settings = load_settings()
