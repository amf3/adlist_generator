import pytest
from src.trie import ReversedDomainTrie
from src.schemas import LocalZone, LocalDNSRecord, DNSRecords

LIST_A = "https://list-a.example/domains.txt"
LIST_B = "https://list-b.example/domains.txt"


def _make_zone(zone, policy, records):
    return LocalZone(zone=zone, policy=policy, records=records)


def _make_record(domain, records, auto_ptr=False):
    return LocalDNSRecord(domain=domain, auto_ptr=auto_ptr, records=DNSRecords(**records))


# --- Adblock trie tests (unchanged behaviour) ---

def test_top_down_pruning():
    trie = ReversedDomainTrie()
    trie.insert_block_domain("example.com", LIST_A)
    trie.insert_block_domain("ads.example.com", LIST_B)

    domains = [item[0] for item in trie.serialize_pruned_tree()]
    assert "example.com" in domains
    assert "ads.example.com" not in domains


def test_child_inserted_before_parent_is_pruned():
    trie = ReversedDomainTrie()
    trie.insert_block_domain("ads.example.com", LIST_A)
    trie.insert_block_domain("example.com", LIST_A)

    domains = [item[0] for item in trie.serialize_pruned_tree()]
    assert "example.com" in domains
    assert "ads.example.com" not in domains


# --- Zone-grouped local DNS injection ---

def test_zone_registered_on_injection():
    trie = ReversedDomainTrie()
    trie.inject_local_dns([
        _make_zone("rb.af9.us.", "transparent", [
            _make_record("phanpy.rb.af9.us", {"A": "192.168.10.31"})
        ])
    ])

    assert ("rb.af9.us.", "transparent") in trie._local_zones


def test_local_record_in_serialized_output():
    trie = ReversedDomainTrie()
    trie.inject_local_dns([
        _make_zone("rb.af9.us.", "transparent", [
            _make_record("phanpy.rb.af9.us", {"A": "192.168.10.31"})
        ])
    ])

    finalized = trie.serialize_pruned_tree()
    domains = [item[0] for item in finalized]
    assert "phanpy.rb.af9.us" in domains

    entry = next(item for item in finalized if item[0] == "phanpy.rb.af9.us")
    assert entry[2] == {"A": "192.168.10.31"}
    assert entry[3] == "local"


def test_cname_field_rejected_by_schema():
    """
    CNAME is not a supported record type (see DNSRecords docstring): Unbound
    doesn't re-enter local-zone resolution when following CNAME hops, so only
    the first hop would ever be returned. Attempting to build a record with a
    CNAME field should fail schema validation before it ever reaches the trie.
    """
    with pytest.raises(Exception):
        _make_record("docker02.rb.af9.us", {"CNAME": "phanpy.rb.af9.us."})


def test_aliased_hosts_all_records_present():
    """
    Aliases (what would previously have been CNAMEs, e.g. gitea and docker02
    both pointing at phanpy) should each get their own A record repeating the
    target IP, per the documented workaround. All three hostnames should
    appear as local-data entries under a single transparent zone — no
    per-hostname local-zone declarations.
    """
    trie = ReversedDomainTrie()
    trie.inject_local_dns([
        _make_zone("rb.af9.us.", "transparent", [
            _make_record("phanpy.rb.af9.us",  {"A": "192.168.10.31"}),
            _make_record("docker02.rb.af9.us", {"A": "192.168.10.31"}),
            _make_record("gitea.rb.af9.us",    {"A": "192.168.10.31"}),
        ])
    ])

    finalized = trie.serialize_pruned_tree()
    domains = [item[0] for item in finalized]

    assert "phanpy.rb.af9.us" in domains
    assert "docker02.rb.af9.us" in domains
    assert "gitea.rb.af9.us" in domains

    # No entry should carry a policy — policy lives on the zone, not the record.
    local_entries = [item for item in finalized if item[3] == "local"]
    for domain, policy, records, source in local_entries:
        assert policy == "", f"{domain} should have no per-record policy, got '{policy}'"


def test_auto_ptr_synthesized():
    trie = ReversedDomainTrie()
    trie.inject_local_dns([
        _make_zone("rb.af9.us.", "transparent", [
            _make_record("phanpy.rb.af9.us", {"A": "192.168.10.31"}, auto_ptr=True)
        ])
    ])

    finalized = trie.serialize_pruned_tree()
    domains = [item[0] for item in finalized]
    assert "31.10.168.192.in-addr.arpa" in domains

    ptr = next(item for item in finalized if item[0] == "31.10.168.192.in-addr.arpa")
    assert ptr[2] == {"PTR": "phanpy.rb.af9.us."}


def test_multiple_zones():
    trie = ReversedDomainTrie()
    trie.inject_local_dns([
        _make_zone("rb.af9.us.", "transparent", [
            _make_record("phanpy.rb.af9.us", {"A": "192.168.10.31"})
        ]),
        _make_zone("foo.rb.af9.us.", "always_nxdomain", [
            _make_record("foo.rb.af9.us", {"A": "0.0.0.0"})
        ]),
    ])

    assert len(trie._local_zones) == 2
    assert ("rb.af9.us.", "transparent") in trie._local_zones
    assert ("foo.rb.af9.us.", "always_nxdomain") in trie._local_zones
