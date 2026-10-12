"""Daemon configuration (/etc/localpasskey/localpasskeyd.conf)."""

from __future__ import annotations

import configparser
from dataclasses import dataclass

DEFAULT_PATH = "/etc/localpasskey/localpasskeyd.conf"


@dataclass
class Config:
    prompt_timeout: float = 120.0
    notifications: bool = True
    activity_notifications: bool = True
    log_level: str = "info"
    device_name: str = "LocalPasskey Virtual FIDO2 Authenticator"
    vendor_id: int = 0x1209
    product_id: int = 0x4C50


def load_config(path: str = DEFAULT_PATH) -> Config:
    parser = configparser.ConfigParser()
    parser.read(path)  # a missing file just means "use the defaults"
    config = Config()
    if parser.has_section("daemon"):
        section = parser["daemon"]
        config.prompt_timeout = section.getfloat("prompt_timeout", config.prompt_timeout)
        config.notifications = section.getboolean("notifications", config.notifications)
        config.activity_notifications = section.getboolean(
            "activity_notifications", config.activity_notifications
        )
        config.log_level = section.get("log_level", config.log_level).strip().lower()
    if parser.has_section("device"):
        section = parser["device"]
        config.device_name = section.get("name", config.device_name).strip()
        config.vendor_id = int(section.get("vendor_id", str(config.vendor_id)), 0)
        config.product_id = int(section.get("product_id", str(config.product_id)), 0)
    if not 5 <= config.prompt_timeout <= 600:
        raise ValueError("prompt_timeout must be between 5 and 600 seconds")
    if config.log_level not in ("debug", "info", "warning", "error"):
        raise ValueError(f"unknown log_level {config.log_level!r}")
    if not config.device_name:
        raise ValueError("device name must not be empty")
    if not 0 <= config.vendor_id <= 0xffff or not 0 <= config.product_id <= 0xffff:
        raise ValueError("vendor_id and product_id must be between 0 and 65535")
    return config
