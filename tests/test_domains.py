import pytest
from certbot import errors

from certbot_dns_namecheap._internal.domains import DomainParts, split_domain


@pytest.mark.parametrize(
    "name, expected",
    [
        ("example.com", DomainParts("example", "com", "@")),
        ("_acme-challenge.example.com", DomainParts("example", "com", "_acme-challenge")),
        ("_acme-challenge.sub.example.com", DomainParts("example", "com", "_acme-challenge.sub")),
        ("_acme-challenge.example.co.uk", DomainParts("example", "co.uk", "_acme-challenge")),
        ("_acme-challenge.a.b.example.com.au", DomainParts("example", "com.au", "_acme-challenge.a.b")),
        ("*.example.com", DomainParts("example", "com", "@")),
        ("_ACME-Challenge.Example.COM.", DomainParts("example", "com", "_acme-challenge")),
        # ICANN-only: private-section suffixes such as github.io are not treated as TLDs
        ("_acme-challenge.example.github.io", DomainParts("github", "io", "_acme-challenge.example")),
    ],
)
def test_split(name, expected):
    assert split_domain(name) == expected


def test_zone_property():
    assert split_domain("_acme-challenge.example.co.uk").zone == "example.co.uk"


@pytest.mark.parametrize("name", ["com", "co.uk", "", ".", "a..example.com"])
def test_invalid(name):
    with pytest.raises(errors.PluginError):
        split_domain(name)
