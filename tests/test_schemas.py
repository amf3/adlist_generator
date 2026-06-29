import pytest
from pydantic import ValidationError
from src.schemas import (
    UnboundServerSettings,
    AccessControlEntry,
    LocalDNSEntry,
    DNSRecords,
    AdlistConfig,
    AdlistSource,
)


def test_adlist_config_valid():
    config = AdlistConfig(
        sources=[
            {"url": "https://example.com/list.txt", "format": "domains"},
            {"url": "https://example.com/hosts.txt", "format": "hosts"},
            {"url": "https://example.com/filter.txt", "format": "adblock"},
        ]
    )
    assert len(config.sources) == 3
    assert config.sources[0].format == "domains"
    assert config.sources[2].format == "adblock"


def test_adlist_config_default_format():
    config = AdlistConfig(
        sources=[
            {"url": "https://example.com/list.txt"},
        ]
    )
    assert config.sources[0].format == "domains"


def test_adlist_config_invalid_format():
    with pytest.raises(ValidationError):
        AdlistConfig(
            sources=[
                {"url": "https://example.com/list.txt", "format": "unknown_format"},
            ]
        )


def test_adlist_config_missing_url():
    with pytest.raises(ValidationError):
        AdlistConfig(
            sources=[
                {"format": "domains"},
            ]
        )


def test_adlist_config_empty_sources():
    # An empty sources list is valid — the pipeline will just skip ingestion.
    config = AdlistConfig(sources=[])
    assert config.sources == []


def test_adlist_config_model_dump_roundtrip():
    # Verify that model_dump() produces dicts compatible with DomainNormalizer's
    # existing interface (expects 'url' and 'format' keys).
    config = AdlistConfig(
        sources=[
            {"url": "https://example.com/list.txt", "format": "hosts"},
        ]
    )
    dumped = config.sources[0].model_dump()
    assert dumped == {"url": "https://example.com/list.txt", "format": "hosts"}


def test_server_settings_defaults():
    s = UnboundServerSettings()
    assert s.port == 53
    assert s.hide_identity is True
    assert s.harden_glue is True
    assert s.access_control == []


def test_server_settings_full():
    s = UnboundServerSettings(
        port=5353,
        num_threads=4,
        msg_cache_size="16m",
        verbosity=2,
        log_queries=True,
        access_control=[
            AccessControlEntry(subnet="192.168.0.0/16", action="allow"),
            AccessControlEntry(subnet="0.0.0.0/0", action="refuse"),
        ],
    )
    assert s.port == 5353
    assert len(s.access_control) == 2
    assert s.access_control[0].action == "allow"


def test_server_settings_invalid_port():
    with pytest.raises(ValidationError):
        UnboundServerSettings(port=70000)


def test_server_settings_invalid_threads():
    with pytest.raises(ValidationError):
        UnboundServerSettings(num_threads=0)


def test_server_settings_invalid_verbosity():
    with pytest.raises(ValidationError):
        UnboundServerSettings(verbosity=6)


def test_access_control_invalid_action():
    with pytest.raises(ValidationError):
        AccessControlEntry(
            subnet="0.0.0.0/0", action="permit"
        )  # not a valid Unbound action


def test_local_dns_entry_invalid_ip():
    with pytest.raises(ValidationError):
        LocalDNSEntry(
            domain="broken.lan", policy="static", records=DNSRecords(A="192.168.1.300")
        )
