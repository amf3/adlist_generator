# tests/test_adlist_schema.py
import pytest
from pydantic import ValidationError
from src.schemas import AdlistConfig, AdlistSource


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
