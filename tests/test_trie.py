# tests/test_trie.py
import pytest
from src.trie import ReversedDomainTrie
from src.schemas import LocalDNSEntry, DNSRecords

LIST_A = "https://list-a.example/domains.txt"
LIST_B = "https://list-b.example/domains.txt"


def test_top_down_pruning():
    """A parent zone block should subsume any child domain."""
    trie = ReversedDomainTrie()
    trie.insert_block_domain("example.com", LIST_A)
    trie.insert_block_domain("ads.example.com", LIST_B)

    domains = [item[0] for item in trie.serialize_pruned_tree()]
    assert "example.com" in domains
    assert "ads.example.com" not in domains


def test_child_inserted_before_parent_is_pruned():
    """Child inserted first should be dropped when the parent arrives later."""
    trie = ReversedDomainTrie()
    trie.insert_block_domain("ads.example.com", LIST_A)
    trie.insert_block_domain("example.com", LIST_A)

    domains = [item[0] for item in trie.serialize_pruned_tree()]
    assert "example.com" in domains
    assert "ads.example.com" not in domains


def test_local_dns_injection_and_auto_ptr():
    trie = ReversedDomainTrie()

    mock_local = [
        LocalDNSEntry(
            domain="router.lan",
            policy="static",
            auto_ptr=True,
            records=DNSRecords(A="10.0.0.1"),
        )
    ]
    trie.inject_local_dns(mock_local)

    finalized = trie.serialize_pruned_tree()
    domains = [item[0] for item in finalized]

    assert "router.lan" in domains
    assert "1.0.0.10.in-addr.arpa" in domains

    ptr_entry = next(item for item in finalized if item[0] == "1.0.0.10.in-addr.arpa")
    assert ptr_entry[1] == "static"
    assert ptr_entry[2]["PTR"] == "router.lan."
