"""Certbot DNS-01 Authenticator for Namecheap."""
from __future__ import annotations

import dataclasses
import json
import logging
import os
from collections import defaultdict
from datetime import datetime, timezone
from time import sleep
from typing import Any, Callable, Optional

from acme import challenges
from certbot import achallenges, errors
from certbot.display import util as display_util
from certbot.plugins import dns_common

from certbot_dns_namecheap._internal.client import NamecheapClient
from certbot_dns_namecheap._internal.config import NamecheapConfig
from certbot_dns_namecheap._internal.domains import DomainParts, split_domain
from certbot_dns_namecheap._internal.records import HostRecord, Zone, add_txt, remove_txt

logger = logging.getLogger(__name__)

BACKUP_DIR_NAME = "namecheap-backups"
BACKUPS_KEPT_PER_ZONE = 50

# (host relative to the zone, TXT value)
_Item = tuple[str, str]


class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Namecheap.

    Fulfils dns-01 challenges (including wildcard names) by writing TXT records
    through the Namecheap API. Credentials come from NAMECHEAP_* environment
    variables, not from a credentials file.

    Namecheap's setHosts replaces a whole zone, so all challenges for one zone
    are applied with a single read-modify-write, the zone is backed up before
    every write, and a write is refused unless the only difference from the
    current zone is our own TXT records.
    """

    description = (
        "Obtain certificates using a DNS TXT record (if you are using Namecheap for DNS)."
    )

    client_factory: Callable[[NamecheapConfig], NamecheapClient] = NamecheapClient

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.ncconfig: Optional[NamecheapConfig] = None
        self._client: Optional[NamecheapClient] = None
        self._pending: dict[tuple[str, str], list[_Item]] = defaultdict(list)

    @classmethod
    def add_parser_arguments(
        cls, add: Callable[..., None], default_propagation_seconds: int = 120
    ) -> None:
        super().add_parser_arguments(add, default_propagation_seconds)

    def more_info(self) -> str:
        return (
            "This plugin configures a DNS TXT record to respond to a dns-01 challenge "
            "using the Namecheap API. Configure it with the NAMECHEAP_API_USER, "
            "NAMECHEAP_API_KEY, NAMECHEAP_CLIENT_IP (and optionally NAMECHEAP_USERNAME, "
            "NAMECHEAP_SANDBOX) environment variables."
        )

    def _setup_credentials(self) -> None:
        self.ncconfig = NamecheapConfig.from_env()
        logger.debug("Using %r", self.ncconfig)
        self._client = type(self).client_factory(self.ncconfig)

    # --- certbot entry points -------------------------------------------------

    def perform(
        self, achalls: list[achallenges.AnnotatedChallenge]
    ) -> list[challenges.ChallengeResponse]:
        # Same as DNSAuthenticator.perform, except that the queued records are
        # written (one setHosts per zone) before waiting for propagation.
        self._setup_credentials()
        self._attempt_cleanup = True
        self._pending = defaultdict(list)

        responses = []
        for achall in achalls:
            domain = achall.identifier.value
            self._perform(
                domain,
                achall.validation_domain_name(domain),
                achall.validation(achall.account_key),
            )
            responses.append(achall.response(achall.account_key))

        self._flush(adding=True)

        seconds = self.conf("propagation-seconds")
        display_util.notify(f"Waiting {seconds} seconds for DNS changes to propagate")
        sleep(seconds)
        return responses

    def cleanup(self, achalls: list[achallenges.AnnotatedChallenge]) -> None:
        self._pending = defaultdict(list)  # drop anything left over from a failed perform
        super().cleanup(achalls)  # queues removals through _cleanup
        if self._attempt_cleanup:
            self._flush(adding=False)

    def _perform(self, domain: str, validation_name: str, validation: str) -> None:
        self._queue(validation_name, validation)

    def _cleanup(self, domain: str, validation_name: str, validation: str) -> None:
        self._queue(validation_name, validation)

    # --- internals ------------------------------------------------------------

    def _queue(self, validation_name: str, validation: str) -> None:
        parts = split_domain(validation_name)
        self._pending[(parts.sld, parts.tld)].append((parts.host, validation))

    def _flush(self, adding: bool) -> None:
        pending, self._pending = self._pending, defaultdict(list)
        for (sld, tld), items in pending.items():
            parts = DomainParts(sld=sld, tld=tld, host="@")
            try:
                self._update_zone(parts, items, adding)
            except errors.PluginError as exc:
                if adding:
                    raise
                logger.warning(
                    "Could not remove challenge TXT record(s) from %s: %s. "
                    "Remove them manually: %s",
                    parts.zone, exc, ", ".join(sorted({h for h, _ in items})),
                )

    def _update_zone(self, parts: DomainParts, items: list[_Item], adding: bool) -> None:
        assert self._client is not None
        action = "add" if adding else "remove"

        zone = self._client.get_hosts(parts)
        old = list(zone.records)
        new = old
        by_host: dict[str, list[str]] = defaultdict(list)
        for host, value in items:
            by_host[host].append(value)
        for host, values in by_host.items():
            new = add_txt(new, host, values) if adding else remove_txt(new, host, values)

        if new == old:
            logger.info("%s: nothing to %s", parts.zone, action)
            return

        _check_only_ours_changed(parts, old, new, items)
        self._backup(zone, action)
        logger.info(
            "%s: %s %d challenge TXT record(s), writing %d records",
            parts.zone, action, len(items), len(new),
        )
        self._client.set_hosts(parts, zone.with_records(new))

        if adding:
            written = self._client.get_hosts(parts).records
            missing = [
                f"{h}={v}" for h, v in items if not any(r.is_txt(h, v) for r in written)
            ]
            if missing:
                raise errors.PluginError(
                    f"{parts.zone}: setHosts reported success but these TXT records "
                    f"are missing afterwards: {', '.join(missing)}"
                )

    def _backup(self, zone: Zone, action: str) -> None:
        directory = os.path.join(self.config.work_dir, BACKUP_DIR_NAME)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        path = os.path.join(directory, f"{zone.domain}_{stamp}_before-{action}.json")
        payload = {
            "domain": zone.domain,
            "email_type": zone.email_type,
            "taken_at": stamp,
            "records": [dataclasses.asdict(r) for r in zone.records],
        }
        try:
            os.makedirs(directory, mode=0o700, exist_ok=True)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as f:
                json.dump(payload, f, indent=2)
        except OSError as exc:
            raise errors.PluginError(
                f"Refusing to modify {zone.domain}: could not write zone backup {path}: {exc}"
            ) from None
        logger.info("Backed up %s to %s", zone.domain, path)
        _prune_backups(directory, zone.domain)


def _check_only_ours_changed(
    parts: DomainParts, old: list[HostRecord], new: list[HostRecord], items: list[_Item]
) -> None:
    """Refuse to write unless old and new differ only in our own TXT records."""
    ours = {(h.lower(), v) for h, v in items}

    def others(records: list[HostRecord]) -> list[HostRecord]:
        return [
            r for r in records
            if not (r.type.upper() == "TXT" and (r.name.lower(), r.address) in ours)
        ]

    if others(old) != others(new):
        raise errors.PluginError(
            f"Internal safety check failed for {parts.zone}: the update would change "
            "records other than the challenge TXT records. Nothing was written."
        )


def _prune_backups(directory: str, domain: str) -> None:
    prefix = f"{domain}_"
    try:
        files = sorted(f for f in os.listdir(directory) if f.startswith(prefix))
        for name in files[:-BACKUPS_KEPT_PER_ZONE]:
            os.remove(os.path.join(directory, name))
    except OSError as exc:
        logger.warning("Could not prune old backups in %s: %s", directory, exc)
