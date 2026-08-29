"""Centralized environment-backed configuration for the backend."""

from dataclasses import dataclass
import os
from dotenv import load_dotenv

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(_BASE_DIR, ".env"))

def _positive_int(name: str, default: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        return default
    return value if value > 0 else default


@dataclass(frozen=True)
class Settings:
    rate_limit_scan_per_hour: int
    rate_limit_read_per_hour: int
    allowed_origins: list[str]


settings = Settings(
    rate_limit_scan_per_hour=_positive_int("RATE_LIMIT_SCAN_PER_HOUR", 5),
    rate_limit_read_per_hour=_positive_int("RATE_LIMIT_READ_PER_HOUR", 60),
    allowed_origins=[
        origin.strip()
        for origin in os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(",")
        if origin.strip()
    ],
)
