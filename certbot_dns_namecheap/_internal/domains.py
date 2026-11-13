"""Split DNS names into the SLD / TLD / host parts the Namecheap API expects.

Uses the ICANN section of the Public Suffix List bundled with the
``publicsuffixlist`` package, so no network access is needed at runtime.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

from certbot import errors
from publicsuffixlist import PublicSuffixList


@dataclass(frozen=True)
class DomainParts:
    sld: str   # "example"            (Namecheap: SLD)
    tld: str   # "co.uk"              (Namecheap: TLD)
    host: str  # "_acme-challenge.sub" or "@" for the zone apex

    @property
    def zone(self) -> str:
        return f"{self.sld}.{self.tld}"


@lru_cache(maxsize=1)
def _psl() -> PublicSuffixList:
    return PublicSuffixList(only_icann=True)


def split_domain(name: str) -> DomainParts:
    """Split a fully-qualified name, e.g. ``_acme-challenge.sub.example.co.uk``."""
    fqdn = name.strip().rstrip(".").lower()
    if fqdn.startswith("*."):
        fqdn = fqdn[2:]
    if not fqdn or ".." in fqdn:
        raise errors.PluginError(f"Invalid domain name: {name!r}")

    registrable = _psl().privatesuffix(fqdn)
    if registrable is None:
        raise errors.PluginError(
            f"{name!r} is a public suffix, not a domain that can be registered"
        )

    sld, tld = registrable.split(".", 1)
    if fqdn == registrable:
        host = "@"
    else:
        host = fqdn[: -(len(registrable) + 1)]
    return DomainParts(sld=sld, tld=tld, host=host)
