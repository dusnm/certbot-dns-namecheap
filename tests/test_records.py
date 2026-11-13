from certbot_dns_namecheap._internal.records import HostRecord, Zone, add_txt, remove_txt

ZONE = [
    HostRecord("@", "A", "203.0.113.1", "1800"),
    HostRecord("www", "CNAME", "example.com.", "1800"),
    HostRecord("@", "MX", "mail.example.com.", "1800", mx_pref="10"),
    HostRecord("@", "MX", "backup.example.com.", "3600", mx_pref="20"),
    HostRecord("@", "TXT", "v=spf1 include:_spf.example.net ~all", "1799"),
    HostRecord("@", "CAA", '0 issue "letsencrypt.org"', "1800"),
    HostRecord("old", "URL301", "https://example.com/", "1800"),
    HostRecord("_acme-challenge", "TXT", "stale-from-someone-else", "60"),
]


def test_add_keeps_every_existing_record():
    out = add_txt(ZONE, "_acme-challenge", ["tok1"])
    assert out[: len(ZONE)] == ZONE
    assert out[-1] == HostRecord("_acme-challenge", "TXT", "tok1", "60")


def test_add_two_values_same_name_for_wildcard_plus_apex():
    out = add_txt(ZONE, "_acme-challenge", ["apex-token", "wildcard-token"])
    added = [r.address for r in out[len(ZONE):]]
    assert added == ["apex-token", "wildcard-token"]


def test_add_is_idempotent():
    once = add_txt(ZONE, "_acme-challenge", ["tok1"])
    twice = add_txt(once, "_acme-challenge", ["tok1"])
    assert once == twice


def test_add_does_not_mutate_input():
    original = list(ZONE)
    add_txt(ZONE, "_acme-challenge", ["tok1"])
    assert ZONE == original


def test_remove_only_our_values():
    added = add_txt(ZONE, "_acme-challenge.sub", ["a", "b"])
    out = remove_txt(added, "_acme-challenge.sub", ["a", "b"])
    assert out == ZONE  # including the unrelated stale _acme-challenge record


def test_remove_partial():
    added = add_txt(ZONE, "_acme-challenge", ["a", "b"])
    out = remove_txt(added, "_acme-challenge", ["a"])
    assert out == ZONE + [HostRecord("_acme-challenge", "TXT", "b", "60")]


def test_remove_name_is_case_insensitive_value_is_not():
    zone = [HostRecord("_ACME-Challenge", "txt", "Tok", "60")]
    assert remove_txt(zone, "_acme-challenge", ["tok"]) == zone
    assert remove_txt(zone, "_acme-challenge", ["Tok"]) == []


def test_remove_ignores_other_types_with_same_value():
    zone = [HostRecord("_acme-challenge", "CNAME", "tok", "60")]
    assert remove_txt(zone, "_acme-challenge", ["tok"]) == zone


def test_remove_missing_is_noop():
    assert remove_txt(ZONE, "_acme-challenge", ["never-added"]) == ZONE


def test_zone_with_records():
    z = Zone("example.com", "MX", tuple(ZONE))
    z2 = z.with_records(add_txt(z.records, "_acme-challenge", ["t"]))
    assert z2.email_type == "MX" and z2.domain == "example.com"
    assert len(z2.records) == len(ZONE) + 1
