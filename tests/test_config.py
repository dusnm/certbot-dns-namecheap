import pytest
from certbot import errors

from certbot_dns_namecheap._internal.config import (
    PRODUCTION_ENDPOINT,
    SANDBOX_ENDPOINT,
    NamecheapConfig,
)

BASE = {
    "NAMECHEAP_API_USER": "apiuser",
    "NAMECHEAP_API_KEY": "secretkey",
    "NAMECHEAP_CLIENT_IP": "203.0.113.10",
}


def test_minimal_env():
    cfg = NamecheapConfig.from_env(BASE)
    assert cfg.username == "apiuser"
    assert cfg.sandbox is False
    assert cfg.endpoint == PRODUCTION_ENDPOINT


def test_username_and_sandbox():
    cfg = NamecheapConfig.from_env(
        {**BASE, "NAMECHEAP_USERNAME": "acct", "NAMECHEAP_SANDBOX": "true"}
    )
    assert cfg.username == "acct"
    assert cfg.endpoint == SANDBOX_ENDPOINT


@pytest.mark.parametrize("key", list(BASE))
def test_missing_required(key):
    env = {k: v for k, v in BASE.items() if k != key}
    with pytest.raises(errors.PluginError, match=key):
        NamecheapConfig.from_env(env)


@pytest.mark.parametrize("ip", ["not-an-ip", "2001:db8::1"])
def test_bad_client_ip(ip):
    with pytest.raises(errors.PluginError, match="IPv4"):
        NamecheapConfig.from_env({**BASE, "NAMECHEAP_CLIENT_IP": ip})


def test_bad_sandbox_value():
    with pytest.raises(errors.PluginError, match="NAMECHEAP_SANDBOX"):
        NamecheapConfig.from_env({**BASE, "NAMECHEAP_SANDBOX": "maybe"})


def test_repr_hides_key():
    assert "secretkey" not in repr(NamecheapConfig.from_env(BASE))
