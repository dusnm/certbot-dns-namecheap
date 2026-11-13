import pytest
import requests
from certbot import errors

from certbot_dns_namecheap._internal.client import (
    NamecheapApiError,
    NamecheapClient,
    build_set_hosts_params,
)
from certbot_dns_namecheap._internal.config import NamecheapConfig
from certbot_dns_namecheap._internal.domains import split_domain
from certbot_dns_namecheap._internal.records import HostRecord, Zone

CONFIG = NamecheapConfig.from_env(
    {
        "NAMECHEAP_API_USER": "apiuser",
        "NAMECHEAP_API_KEY": "SECRETKEY",
        "NAMECHEAP_CLIENT_IP": "203.0.113.10",
        "NAMECHEAP_SANDBOX": "true",
    }
)
PARTS = split_domain("_acme-challenge.example.co.uk")

NS = 'xmlns="http://api.namecheap.com/xml.response"'

GET_HOSTS_OK = f"""<?xml version="1.0" encoding="utf-8"?>
<ApiResponse Status="OK" {NS}>
  <Errors />
  <RequestedCommand>namecheap.domains.dns.getHosts</RequestedCommand>
  <CommandResponse Type="namecheap.domains.dns.getHosts">
    <DomainDNSGetHostsResult Domain="example.co.uk" EmailType="MX" IsUsingOurDNS="true">
      <host HostId="1" Name="@" Type="A" Address="203.0.113.1" MXPref="10" TTL="1800" IsActive="true" />
      <host HostId="2" Name="@" Type="MX" Address="mail.example.co.uk." MXPref="20" TTL="3600" IsActive="true" />
      <host HostId="3" Name="@" Type="TXT" Address="v=spf1 mx ~all" MXPref="10" TTL="1799" IsActive="true" />
      <host HostId="4" Name="@" Type="CAA" Address="0 issue &quot;letsencrypt.org&quot;" MXPref="10" TTL="1800" IsActive="true" />
      <host HostId="5" Name="old" Type="URL301" Address="https://example.co.uk/?a=1&amp;b=2" MXPref="10" TTL="1800" IsActive="true" />
    </DomainDNSGetHostsResult>
  </CommandResponse>
  <Server>X</Server>
  <ExecutionTime>0.1</ExecutionTime>
</ApiResponse>"""

SET_HOSTS_OK = f"""<?xml version="1.0" encoding="utf-8"?>
<ApiResponse Status="OK" {NS}>
  <Errors />
  <CommandResponse Type="namecheap.domains.dns.setHosts">
    <DomainDNSSetHostsResult Domain="example.co.uk" IsSuccess="true" />
  </CommandResponse>
</ApiResponse>"""


def error_xml(number, text):
    return f"""<?xml version="1.0" encoding="utf-8"?>
<ApiResponse Status="ERROR" {NS}>
  <Errors><Error Number="{number}">{text}</Error></Errors>
  <CommandResponse />
</ApiResponse>"""


class FakeResponse:
    def __init__(self, body, status=200):
        self.content = body.encode()
        self.status_code = status


class FakeSession:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def post(self, url, data=None, timeout=None, **kwargs):
        self.calls.append({"url": url, "data": data, "timeout": timeout, **kwargs})
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def client(*responses):
    session = FakeSession(*responses)
    return NamecheapClient(CONFIG, session=session), session


def test_get_hosts_parses_everything():
    c, s = client(FakeResponse(GET_HOSTS_OK))
    zone = c.get_hosts(PARTS)
    assert zone.domain == "example.co.uk"
    assert zone.email_type == "MX"
    assert zone.records == (
        HostRecord("@", "A", "203.0.113.1", "1800", "10"),
        HostRecord("@", "MX", "mail.example.co.uk.", "3600", "20"),
        HostRecord("@", "TXT", "v=spf1 mx ~all", "1799", "10"),
        HostRecord("@", "CAA", '0 issue "letsencrypt.org"', "1800", "10"),
        HostRecord("old", "URL301", "https://example.co.uk/?a=1&b=2", "1800", "10"),
    )
    data = s.calls[0]["data"]
    assert data["Command"] == "namecheap.domains.dns.getHosts"
    assert (data["SLD"], data["TLD"]) == ("example", "co.uk")
    assert data["ClientIp"] == "203.0.113.10"


def test_api_key_only_in_post_body():
    c, s = client(FakeResponse(GET_HOSTS_OK))
    c.get_hosts(PARTS)
    call = s.calls[0]
    assert "SECRETKEY" not in call["url"]
    assert "params" not in call
    assert call["data"]["ApiKey"] == "SECRETKEY"
    assert call["url"].startswith("https://api.sandbox.namecheap.com/")
    assert call["timeout"]


def test_not_using_namecheap_dns():
    body = GET_HOSTS_OK.replace('IsUsingOurDNS="true"', 'IsUsingOurDNS="false"')
    c, _ = client(FakeResponse(body))
    with pytest.raises(errors.PluginError, match="does not use Namecheap DNS"):
        c.get_hosts(PARTS)


def test_incomplete_host_is_fatal():
    body = GET_HOSTS_OK.replace('Type="A" ', "")
    c, _ = client(FakeResponse(body))
    with pytest.raises(errors.PluginError, match="incomplete host record"):
        c.get_hosts(PARTS)


def test_api_error_with_ip_hint():
    c, _ = client(FakeResponse(error_xml("1011150", "Parameter RequestIP is invalid")))
    with pytest.raises(NamecheapApiError) as exc:
        c.get_hosts(PARTS)
    assert exc.value.number == "1011150"
    assert "whitelisted" in str(exc.value)


def test_api_error_without_hint():
    c, _ = client(FakeResponse(error_xml("9999", "Something descriptive happened")))
    with pytest.raises(NamecheapApiError) as exc:
        c.get_hosts(PARTS)
    assert "whitelisted" not in str(exc.value)  # "descriptive" must not match "ip"


@pytest.mark.parametrize(
    "response",
    [
        FakeResponse("<html>bad gateway</html>", status=502),
        FakeResponse("not xml"),
        requests.ConnectionError("boom"),
    ],
)
def test_transport_failures(response):
    c, _ = client(response)
    with pytest.raises(errors.PluginError):
        c.get_hosts(PARTS)


def test_rejects_xml_entity_tricks():
    evil = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><ApiResponse Status="OK">&a;</ApiResponse>'
    c, _ = client(FakeResponse(evil))
    with pytest.raises(errors.PluginError, match="invalid XML"):
        c.get_hosts(PARTS)


def test_build_set_hosts_params_round_trip():
    c, _ = client(FakeResponse(GET_HOSTS_OK))
    zone = c.get_hosts(PARTS)
    params = build_set_hosts_params(PARTS, zone)
    assert params["SLD"] == "example" and params["TLD"] == "co.uk"
    assert params["EmailType"] == "MX"
    assert params["HostName2"] == "@" and params["RecordType2"] == "MX"
    assert params["MXPref2"] == "20" and params["TTL2"] == "3600"
    assert "MXPref1" not in params  # only sent for MX records
    assert params["Address4"] == '0 issue "letsencrypt.org"'
    assert params["Address5"] == "https://example.co.uk/?a=1&b=2"
    assert "HostName6" not in params


def test_build_set_hosts_params_without_email_type():
    zone = Zone("example.co.uk", "", (HostRecord("@", "A", "1.2.3.4", "1800"),))
    assert "EmailType" not in build_set_hosts_params(PARTS, zone)


def test_refuses_empty_zone():
    with pytest.raises(errors.PluginError, match="empty record list"):
        build_set_hosts_params(PARTS, Zone("example.co.uk", "MX", ()))


def test_set_hosts_success_and_failure():
    zone = Zone("example.co.uk", "MX", (HostRecord("@", "A", "1.2.3.4", "1800"),))
    c, s = client(
        FakeResponse(SET_HOSTS_OK),
        FakeResponse(SET_HOSTS_OK.replace('IsSuccess="true"', 'IsSuccess="false"')),
    )
    c.set_hosts(PARTS, zone)
    assert s.calls[0]["data"]["Command"] == "namecheap.domains.dns.setHosts"
    with pytest.raises(errors.PluginError, match="did not report success"):
        c.set_hosts(PARTS, zone)
