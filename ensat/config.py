"""Central configuration for ENSAT.

All settings can be overridden with environment variables (or a ``.env`` file
in the project root). Nothing secret is ever hard-coded.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from logging.handlers import RotatingFileHandler
from pathlib import Path

try:  # python-dotenv is optional at runtime
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover
    load_dotenv = None

ROOT = Path(__file__).resolve().parent.parent
if load_dotenv:
    load_dotenv(ROOT / ".env")


def _env_path(name: str, default: Path) -> Path:
    value = os.getenv(name)
    return Path(value).expanduser().resolve() if value else default


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class Settings:
    data_dir: Path = field(default_factory=lambda: _env_path("ENSAT_DATA_DIR", ROOT / "data"))
    report_dir: Path = field(default_factory=lambda: _env_path("ENSAT_REPORT_DIR", ROOT / "reports"))
    log_dir: Path = field(default_factory=lambda: _env_path("ENSAT_LOG_DIR", ROOT / "logs"))
    db_path: Path | None = field(default_factory=lambda: _env_path("ENSAT_DB", Path()) if os.getenv("ENSAT_DB") else None)
    scope_file: Path = field(default_factory=lambda: _env_path("ENSAT_SCOPE_FILE", ROOT / "scope.txt"))

    nvd_api_key: str = field(default_factory=lambda: os.getenv("NVD_API_KEY", "").strip())
    nvd_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    epss_url: str = "https://api.first.org/data/v1/epss"
    kev_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    http_timeout: int = field(default_factory=lambda: _env_int("ENSAT_HTTP_TIMEOUT", 15))
    nvd_cache_days: int = field(default_factory=lambda: _env_int("ENSAT_NVD_CACHE_DAYS", 7))
    kev_cache_hours: int = field(default_factory=lambda: _env_int("ENSAT_KEV_CACHE_HOURS", 24))
    max_cves_per_service: int = field(default_factory=lambda: _env_int("ENSAT_MAX_CVES_PER_SERVICE", 25))
    max_hosts: int = field(default_factory=lambda: _env_int("ENSAT_MAX_HOSTS", 4096))
    scan_timeout: int = field(default_factory=lambda: _env_int("ENSAT_SCAN_TIMEOUT", 1800))
    offline: bool = field(default_factory=lambda: _env_bool("ENSAT_OFFLINE", False))
    operator: str = field(default_factory=lambda: os.getenv("ENSAT_OPERATOR", "") or os.getenv("USERNAME", "") or os.getenv("USER", "") or "operator")

    def __post_init__(self) -> None:
        if self.db_path is None:
            self.db_path = self.data_dir / "ensat.db"
        for d in (self.data_dir, self.report_dir, self.log_dir):
            d.mkdir(parents=True, exist_ok=True)

    @property
    def kev_cache_path(self) -> Path:
        return self.data_dir / "kev.json"


settings = Settings()

_LOGGING_READY = False


def setup_logging(verbose: bool = False) -> logging.Logger:
    """Configure the ``ensat`` logger once: rotating file + optional console."""
    global _LOGGING_READY
    logger = logging.getLogger("ensat")
    if not _LOGGING_READY:
        logger.setLevel(logging.DEBUG)
        fh = RotatingFileHandler(settings.log_dir / "ensat.log", maxBytes=2_000_000, backupCount=3, encoding="utf-8")
        fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s"))
        fh.setLevel(logging.DEBUG)
        logger.addHandler(fh)
        _LOGGING_READY = True
    if verbose and not any(isinstance(h, logging.StreamHandler) and not isinstance(h, RotatingFileHandler) for h in logger.handlers):
        sh = logging.StreamHandler()
        sh.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
        sh.setLevel(logging.INFO)
        logger.addHandler(sh)
    return logger
