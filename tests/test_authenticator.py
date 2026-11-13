import json
import os
from types import SimpleNamespace
from unittest import mock

import pytest
from certbot import errors

from certbot_dns_namecheap._internal import dns_namecheap
from certbot_dns_namecheap._internal.dns_namecheap import Authenticator
from certbot_dns_namecheap._internal.records import HostRecord, Zone

ENV = {
    "NAMECHEAP_API_USER": "apiuser",
    "NAMECHEAP_API_KEY": "SECRETKEY",
    "NAMECHEAP_CLIENT_IP": "203.0.113.10",
}

BASE_RECORDS = (
    HostRecord("@", "A", "203.0.113.1", "1800", "10"),
    HostRecord("@", "MX", "mail.example.com.", "1800", "10"),
    HostRecord("@", "TXT", "v=spf1 mx ~all", "1799", "10"),
)


class FakeClient:
    """In-memory Namecheap: zones keyed by 'sld.tld'."""

    def __init__(self, zones):
        self.zones = zones
        self.calls = []
        self.drop_writes = False
        self.fail_set = False

    def get_hosts(self, parts):
        self.calls.append(("get", parts.zone))
        if parts.zone not in self.zones:
            raise errors.PluginError(f"domain {parts.zone} not found")
        return self.zones[parts.zone]

    def set_hosts(self, parts, zone):
        self.calls.append(("set", parts.zone))
        if self.fail_set:
            raise errors.PluginError("setHosts failed")
        if not self.drop_writes:
            self.zones[parts.zone] = zone


class FakeAchall:
    def __init__(self, domain, token):
        self.identifier = SimpleNamespace(value=domain)
        self.account_key = object()
        self._token = token

    def validation_domain_name(self, domain):
        return "_acme-challenge." + domain.removeprefix("*.")

    def validation(self, key):
        return self._token

    def response(self, key):
        return ("response", self._token)


@pytest.fixture
def setup(tmp_path, monkeypatch):
    for k, v in ENV.items():
        monkeypatch.setenv(k, v)
    zones = {
        "example.com": Zone("example.com", "MX", BASE_RECORDS),
        "example.co.uk": Zone("example.co.uk", "FWD", BASE_RECORDS[:1]),
    }
    client = FakeClient(zones)
    monkeypatch.setattr(Authenticator, "client_factory", lambda cfg: client)
    config = SimpleNamespace(work_dir=str(tmp_path), dns_namecheap_propagation_seconds=0)
    auth = Authenticator(config, "dns-namecheap")
    with mock.patch.object(dns_namecheap, "sleep") as fake_sleep, \
         mock.patch.object(dns_namecheap.display_util, "notify"):
        yield auth, client, tmp_path, fake_sleep


def txt(zone, name):
    return sorted(r.address for r in zone.records if r.type == "TXT" and r.name == name)


def backups(tmp_path):
    d = tmp_path / "namecheap-backups"
    return sorted(os.listdir(d)) if d.exists() else []


def test_apex_and_wildcard_single_write(setup):
    auth, client, tmp_path, fake_sleep = setup
    achalls = [FakeAchall("example.com", "apex"), FakeAchall("*.example.com", "wild")]

    responses = auth.perform(achalls)

    assert responses == [("response", "apex"), ("response", "wild")]
    zone = client.zones["example.com"]
    assert txt(zone, "_acme-challenge") == ["apex", "wild"]
    assert zone.records[: len(BASE_RECORDS)] == BASE_RECORDS
    assert zone.email_type == "MX"
    # one read, one write, one verification read
    assert client.calls == [("get", "example.com"), ("set", "example.com"), ("get", "example.com")]
    fake_sleep.assert_called_once_with(0)

    auth.cleanup(achalls)
    assert client.zones["example.com"].records == BASE_RECORDS
    assert client.calls[-2:] == [("get", "example.com"), ("set", "example.com")]


def test_multiple_zones_and_subdomain(setup):
    auth, client, _, _ = setup
    achalls = [
        FakeAchall("example.com", "a"),
        FakeAchall("www.example.co.uk", "b"),
        FakeAchall("*.example.co.uk", "c"),
    ]
    auth.perform(achalls)
    uk = client.zones["example.co.uk"]
    assert txt(uk, "_acme-challenge.www") == ["b"]
    assert txt(uk, "_acme-challenge") == ["c"]
    assert uk.email_type == "FWD"
    assert sum(1 for c in client.calls if c[0] == "set") == 2

    auth.cleanup(achalls)
    assert client.zones["example.com"].records == BASE_RECORDS
    assert client.zones["example.co.uk"].records == BASE_RECORDS[:1]


def test_backups_written_before_each_change(setup):
    auth, client, tmp_path, _ = setup
    achalls = [FakeAchall("example.com", "tok")]
    auth.perform(achalls)
    auth.cleanup(achalls)

    files = backups(tmp_path)
    assert len(files) == 2
    assert files[0].endswith("before-add.json") and files[1].endswith("before-remove.json")
    before_add = json.loads((tmp_path / "namecheap-backups" / files[0]).read_text())
    assert before_add["email_type"] == "MX"
    assert len(before_add["records"]) == len(BASE_RECORDS)
    assert oct(os.stat(tmp_path / "namecheap-backups" / files[0]).st_mode & 0o777) == "0o600"


def test_backup_failure_blocks_write(setup):
    auth, client, tmp_path, _ = setup
    (tmp_path / "namecheap-backups").write_text("a file, not a directory")
    with pytest.raises(errors.PluginError, match="zone backup"):
        auth.perform([FakeAchall("example.com", "tok")])
    assert ("set", "example.com") not in client.calls


def test_backups_are_pruned(setup, monkeypatch):
    auth, client, tmp_path, _ = setup
    monkeypatch.setattr(dns_namecheap, "BACKUPS_KEPT_PER_ZONE", 3)
    for i in range(4):
        achalls = [FakeAchall("example.com", f"tok{i}")]
        auth.perform(achalls)
        auth.cleanup(achalls)
    assert len(backups(tmp_path)) == 3


def test_write_not_visible_afterwards_is_an_error(setup):
    auth, client, _, _ = setup
    client.drop_writes = True
    with pytest.raises(errors.PluginError, match="missing afterwards"):
        auth.perform([FakeAchall("example.com", "tok")])


def test_unknown_domain_fails_perform(setup):
    auth, _, _, _ = setup
    with pytest.raises(errors.PluginError, match="not found"):
        auth.perform([FakeAchall("other.net", "tok")])


def test_cleanup_failure_only_warns(setup, caplog):
    auth, client, _, _ = setup
    achalls = [FakeAchall("example.com", "tok")]
    auth.perform(achalls)
    client.fail_set = True
    auth.cleanup(achalls)  # must not raise
    assert "Remove them manually" in caplog.text


def test_cleanup_without_perform_does_nothing(setup):
    auth, client, _, _ = setup
    auth.cleanup([FakeAchall("example.com", "tok")])
    assert client.calls == []


def test_rerun_with_existing_record_skips_write(setup):
    auth, client, _, _ = setup
    achalls = [FakeAchall("example.com", "tok")]
    auth.perform(achalls)
    sets = sum(1 for c in client.calls if c[0] == "set")
    auth.perform(achalls)  # e.g. retried after a failure
    assert sum(1 for c in client.calls if c[0] == "set") == sets


def test_safety_check_blocks_unexpected_changes(setup, monkeypatch):
    auth, client, _, _ = setup

    def evil_add(records, name, values, ttl="60"):
        return [r for r in records if r.type != "MX"] + [
            HostRecord(name, "TXT", v, ttl) for v in values
        ]

    monkeypatch.setattr(dns_namecheap, "add_txt", evil_add)
    with pytest.raises(errors.PluginError, match="safety check"):
        auth.perform([FakeAchall("example.com", "tok")])
    assert ("set", "example.com") not in client.calls


def test_missing_env_fails_before_any_call(setup, monkeypatch):
    auth, client, _, _ = setup
    monkeypatch.delenv("NAMECHEAP_API_KEY")
    with pytest.raises(errors.PluginError, match="NAMECHEAP_API_KEY"):
        auth.perform([FakeAchall("example.com", "tok")])
    assert client.calls == []
