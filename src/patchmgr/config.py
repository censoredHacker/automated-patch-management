"""Configuration models for patchmgr.

Two distinct concepts live here:

* :class:`Settings` — global tool behaviour (logging level, retry
  policy, timeouts, vulnerability source). Loaded from
  ``config/settings.yaml`` and/or environment variables.

* :class:`InventoryHost` / :class:`Inventory` — the schema for the YAML
  file that lists hosts to operate on in batch mode.

We use pydantic v2 because it gives us clear validation errors,
JSON-schema-friendly definitions, and easy ``.model_dump()`` for
reporting.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Literal, Optional

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator


OSType = Literal["linux", "windows", "aix"]
Severity = Literal["low", "medium", "high", "critical"]
RebootMode = Literal["auto", "scheduled", "manual"]


# ---------------------------------------------------------------------------
# Settings (global tool configuration)
# ---------------------------------------------------------------------------
class LoggingSettings(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
 
    level: str = "INFO"
    # Renamed from `json` to avoid shadowing BaseModel.json(); the
    # YAML key stays `json` for backward compatibility via the alias.
    json_format: bool = Field(default=True, alias="json")
    console: bool = True


class RetrySettings(BaseModel):
    max_attempts: int = Field(default=3, ge=1, le=10)
    initial_backoff_seconds: float = Field(default=2.0, ge=0)
    max_backoff_seconds: float = Field(default=30.0, ge=0)


class NetworkSettings(BaseModel):
    command_timeout_seconds: int = Field(default=600, ge=1)
    connect_timeout_seconds: int = Field(default=30, ge=1)
    ssh_strict_host_key_checking: bool = True
    winrm_server_cert_validation: Literal["validate", "ignore"] = "validate"


class VulnSourceSettings(BaseModel):
    provider: Literal["nvd", "local_json"] = "nvd"
    cache_ttl_hours: int = Field(default=24, ge=0)
    local_path: Optional[Path] = None


class ReportingSettings(BaseModel):
    output_dir: Path = Path("./reports")
    formats: list[Literal["json", "html"]] = Field(default_factory=lambda: ["json", "html"])


class Settings(BaseModel):
    """Top-level settings document."""

    model_config = ConfigDict(extra="forbid")

    logging: LoggingSettings = LoggingSettings()
    retries: RetrySettings = RetrySettings()
    network: NetworkSettings = NetworkSettings()
    vulnerability_source: VulnSourceSettings = VulnSourceSettings()
    reporting: ReportingSettings = ReportingSettings()

    @classmethod
    def load(cls, path: Path | None) -> "Settings":
        """Load settings from a YAML file. Returns defaults if *path* is None."""
        if path is None:
            return cls()
        if not path.exists():
            raise FileNotFoundError(f"settings file not found: {path}")
        with path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        return cls.model_validate(data)


# ---------------------------------------------------------------------------
# Inventory (batch mode)
# ---------------------------------------------------------------------------
_ENV_VAR_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _expand_env(value: object) -> object:
    """Recursively replace ``${VAR}`` tokens in strings using ``os.environ``.

    Unknown variables expand to an empty string and a warning is left
    for the caller to surface — we do *not* raise, because empty values
    will fail validation downstream with a clear message anyway.
    """
    if isinstance(value, str):
        return _ENV_VAR_RE.sub(lambda m: os.environ.get(m.group(1), ""), value)
    if isinstance(value, list):
        return [_expand_env(v) for v in value]
    if isinstance(value, dict):
        return {k: _expand_env(v) for k, v in value.items()}
    return value


class InventoryDefaults(BaseModel):
    model_config = ConfigDict(extra="forbid")

    severity_min: Severity = "high"
    reboot: RebootMode = "manual"
    timeout: int = 600
    dry_run: bool = True


class InventoryHost(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    os: OSType
    address: str
    port: Optional[int] = None
    username: str
    password: Optional[str] = None
    key_path: Optional[str] = None
    key_passphrase: Optional[str] = None
    winrm_transport: Literal["ntlm", "kerberos", "basic"] = "ntlm"
    winrm_verify_ssl: bool = True
    severity_min: Optional[Severity] = None
    reboot: Optional[RebootMode] = None
    timeout: Optional[int] = None
    dry_run: Optional[bool] = None

    @field_validator("password", "key_path")
    @classmethod
    def _empty_to_none(cls, v: Optional[str]) -> Optional[str]:
        # YAML may surface an empty string after ${VAR} expansion when
        # the env var is unset — treat that as "not provided".
        if v is None or v == "":
            return None
        return v


class Inventory(BaseModel):
    model_config = ConfigDict(extra="forbid")

    defaults: InventoryDefaults = InventoryDefaults()
    hosts: list[InventoryHost]

    @classmethod
    def load(cls, path: Path) -> "Inventory":
        if not path.exists():
            raise FileNotFoundError(f"inventory file not found: {path}")
        with path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        data = _expand_env(data)
        return cls.model_validate(data)

    def effective(self, host: InventoryHost) -> dict[str, object]:
        """Merge per-host overrides on top of the inventory defaults."""
        return {
            "severity_min": host.severity_min or self.defaults.severity_min,
            "reboot": host.reboot or self.defaults.reboot,
            "timeout": host.timeout or self.defaults.timeout,
            "dry_run": self.defaults.dry_run if host.dry_run is None else host.dry_run,
        }


__all__ = (
    "OSType",
    "Severity",
    "RebootMode",
    "Settings",
    "Inventory",
    "InventoryHost",
    "InventoryDefaults",
)
