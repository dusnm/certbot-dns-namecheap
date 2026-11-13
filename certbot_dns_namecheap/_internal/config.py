"""Namecheap API settings, read from environment variables."""
from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass
from typing import Mapping

from certbot import errors

PRODUCTION_ENDPOINT = "https://api.namecheap.com/xml.response"
SANDBOX_ENDPOINT = "https://api.sandbox.namecheap.com/xml.response"

_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"", "0", "false", "no", "off"}


@dataclass(frozen=True)
class NamecheapConfig:
    api_user: str
    api_key: str
    username: str
    client_ip: str
    sandbox: bool = False

    @property
    def endpoint(self) -> str:
        return SANDBOX_ENDPOINT if self.sandbox else PRODUCTION_ENDPOINT

    def __repr__(self) -> str:  # never leak the API key into logs
        return (
            f"NamecheapConfig(api_user={self.api_user!r}, username={self.username!r}, "
            f"client_ip={self.client_ip!r}, sandbox={self.sandbox!r}, api_key='***')"
        )

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "NamecheapConfig":
        env = os.environ if env is None else env

        def get(name: str) -> str:
            return env.get(name, "").strip()

        missing = [
            name
            for name in ("NAMECHEAP_API_USER", "NAMECHEAP_API_KEY", "NAMECHEAP_CLIENT_IP")
            if not get(name)
        ]
        if missing:
            raise errors.PluginError(
                "Missing required environment variable(s): " + ", ".join(missing)
            )

        client_ip = get("NAMECHEAP_CLIENT_IP")
        try:
            ipaddress.IPv4Address(client_ip)
        except ValueError:
            raise errors.PluginError(
                f"NAMECHEAP_CLIENT_IP must be an IPv4 address, got {client_ip!r}"
            ) from None

        sandbox_raw = get("NAMECHEAP_SANDBOX").lower()
        if sandbox_raw in _TRUE:
            sandbox = True
        elif sandbox_raw in _FALSE:
            sandbox = False
        else:
            raise errors.PluginError(
                f"NAMECHEAP_SANDBOX must be true/false, got {sandbox_raw!r}"
            )

        api_user = get("NAMECHEAP_API_USER")
        return cls(
            api_user=api_user,
            api_key=get("NAMECHEAP_API_KEY"),
            username=get("NAMECHEAP_USERNAME") or api_user,
            client_ip=client_ip,
            sandbox=sandbox,
        )
