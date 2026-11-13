"""Minimal Namecheap XML API client: getHosts / setHosts only.

Every request is sent as an HTTP POST with all parameters (including the API
key) in the form body, so the key never appears in a URL and therefore never in
urllib3/certbot debug logs.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Mapping, Optional
from xml.etree.ElementTree import Element

import requests
from certbot import errors
from defusedxml import ElementTree

from certbot_dns_namecheap._internal.config import NamecheapConfig
from certbot_dns_namecheap._internal.domains import DomainParts
from certbot_dns_namecheap._internal.records import HostRecord, Zone

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 30

_HINTS = (
    (re.compile(r"\b(client ?ip|request ?ip|ip)\b"),
     "Is NAMECHEAP_CLIENT_IP correct and whitelisted under Profile > Tools > API Access?"),
    (re.compile(r"\bapi ?key\b"),
     "Check NAMECHEAP_API_KEY and that API access is enabled for the account."),
    (re.compile(r"\bdomain\b"),
     "Is the domain in this Namecheap account (NAMECHEAP_USERNAME)?"),
)


class NamecheapApiError(errors.PluginError):
    def __init__(self, command: str, number: str, message: str) -> None:
        self.command = command
        self.number = number
        self.api_message = message
        text = f"Namecheap API {command} failed: [{number}] {message}"
        lowered = message.lower()
        for pattern, hint in _HINTS:
            if pattern.search(lowered):
                text += f" ({hint})"
                break
        super().__init__(text)


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _find(parent: Element, name: str) -> Optional[Element]:
    for child in parent.iter():
        if _local(child.tag) == name:
            return child
    return None


def build_set_hosts_params(parts: DomainParts, zone: Zone) -> dict[str, str]:
    """Build the numbered setHosts parameters for the complete record list."""
    if not zone.records:
        raise errors.PluginError(
            f"Refusing to call setHosts for {parts.zone} with an empty record list"
        )
    params: dict[str, str] = {"SLD": parts.sld, "TLD": parts.tld}
    if zone.email_type:
        params["EmailType"] = zone.email_type
    for i, rec in enumerate(zone.records, start=1):
        params[f"HostName{i}"] = rec.name
        params[f"RecordType{i}"] = rec.type
        params[f"Address{i}"] = rec.address
        params[f"TTL{i}"] = rec.ttl
        if rec.type.upper() == "MX" and rec.mx_pref is not None:
            params[f"MXPref{i}"] = rec.mx_pref
    return params


class NamecheapClient:
    def __init__(
        self,
        config: NamecheapConfig,
        session: Optional[requests.Session] = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self._config = config
        self._session = session or requests.Session()
        self._timeout = timeout

    def _call(self, command: str, params: Mapping[str, str]) -> Element:
        data: dict[str, Any] = {
            "ApiUser": self._config.api_user,
            "ApiKey": self._config.api_key,
            "UserName": self._config.username,
            "ClientIp": self._config.client_ip,
            "Command": command,
            **params,
        }
        logger.debug("Namecheap %s (%d params)", command, len(params))
        try:
            resp = self._session.post(self._config.endpoint, data=data, timeout=self._timeout)
        except requests.RequestException as exc:
            raise errors.PluginError(f"Namecheap API {command}: request failed: {exc}") from None
        if not 200 <= resp.status_code < 300:
            raise errors.PluginError(
                f"Namecheap API {command}: unexpected HTTP status {resp.status_code}"
            )
        try:
            root = ElementTree.fromstring(resp.content)
        except Exception as exc:  # ParseError and defusedxml's security errors
            raise errors.PluginError(f"Namecheap API {command}: invalid XML response: {exc}") from None

        if root.get("Status", "").upper() != "OK":
            err = _find(root, "Error")
            if err is None:
                raise NamecheapApiError(command, "?", "Status is not OK and no error given")
            raise NamecheapApiError(command, err.get("Number", "?"), (err.text or "").strip())

        result = _find(root, "CommandResponse")
        if result is None:
            raise errors.PluginError(f"Namecheap API {command}: response has no CommandResponse")
        return result

    def get_hosts(self, parts: DomainParts) -> Zone:
        command = "namecheap.domains.dns.getHosts"
        resp = self._call(command, {"SLD": parts.sld, "TLD": parts.tld})
        result = _find(resp, "DomainDNSGetHostsResult")
        if result is None:
            raise errors.PluginError(f"{command}: response has no DomainDNSGetHostsResult")

        if result.get("IsUsingOurDNS", "true").lower() != "true":
            raise errors.PluginError(
                f"{parts.zone} does not use Namecheap DNS (custom nameservers), "
                "so its records cannot be managed through the Namecheap API"
            )

        records = []
        for host in result:
            if _local(host.tag).lower() != "host":
                continue
            name, rtype, address = host.get("Name"), host.get("Type"), host.get("Address")
            if not name or not rtype or address is None:
                raise errors.PluginError(
                    f"{command}: incomplete host record in response for {parts.zone}: "
                    f"{dict(host.attrib)!r}"
                )
            records.append(
                HostRecord(
                    name=name,
                    type=rtype,
                    address=address,
                    ttl=host.get("TTL") or "1800",
                    mx_pref=host.get("MXPref"),
                )
            )
        return Zone(
            domain=result.get("Domain", parts.zone),
            email_type=result.get("EmailType", ""),
            records=tuple(records),
        )

    def set_hosts(self, parts: DomainParts, zone: Zone) -> None:
        command = "namecheap.domains.dns.setHosts"
        resp = self._call(command, build_set_hosts_params(parts, zone))
        result = _find(resp, "DomainDNSSetHostsResult")
        if result is None or result.get("IsSuccess", "").lower() != "true":
            raise errors.PluginError(f"{command} for {parts.zone} did not report success")
