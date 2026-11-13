"""Pure (no I/O) manipulation of a Namecheap zone's host records.

Namecheap's setHosts replaces the *whole* zone, so every change is done as
"take the full record list, return a new full record list". These helpers only
ever add or remove TXT records with an exact (name, value) match; every other
record is passed through untouched.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Optional

DEFAULT_TXT_TTL = "60"  # Namecheap's minimum


@dataclass(frozen=True)
class HostRecord:
    name: str
    type: str
    address: str
    ttl: str
    mx_pref: Optional[str] = None

    def is_txt(self, name: str, value: Optional[str] = None) -> bool:
        return (
            self.type.upper() == "TXT"
            and self.name.lower() == name.lower()
            and (value is None or self.address == value)
        )


@dataclass(frozen=True)
class Zone:
    domain: str
    email_type: str
    records: tuple[HostRecord, ...] = field(default_factory=tuple)

    def with_records(self, records: Iterable[HostRecord]) -> "Zone":
        return Zone(self.domain, self.email_type, tuple(records))


def add_txt(
    records: Iterable[HostRecord], name: str, values: Iterable[str], ttl: str = DEFAULT_TXT_TTL
) -> list[HostRecord]:
    """Return ``records`` plus a TXT record per value; existing identical ones are not duplicated."""
    result = list(records)
    for value in values:
        if not any(r.is_txt(name, value) for r in result):
            result.append(HostRecord(name=name, type="TXT", address=value, ttl=ttl))
    return result


def remove_txt(
    records: Iterable[HostRecord], name: str, values: Iterable[str]
) -> list[HostRecord]:
    """Return ``records`` without TXT records at ``name`` whose value is in ``values``."""
    drop = set(values)
    return [r for r in records if not (r.is_txt(name) and r.address in drop)]
