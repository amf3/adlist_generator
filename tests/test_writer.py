# tests/test_writer.py
import pytest
from src.schemas import UnboundServerSettings, AccessControlEntry
from src.writer import ConfigurationWriter


def _make_writer(mock_data, local_zones=None, **settings_kwargs):
    settings = UnboundServerSettings(**settings_kwargs)
    return ConfigurationWriter(
        server_settings=settings,
        finalized_data=mock_data,
        local_zones=local_zones or [],
    )


def test_local_records_emits_zone_then_data(tmp_path):
    """
    local_records.conf should have one local-zone per zone followed by
    local-data entries — not one local-zone per hostname.
    """
    local_zones = [("rb.af9.us.", "transparent")]
    mock_data = [
        ("phanpy.rb.af9.us", "", {"A": "192.168.10.31"}, "local"),
        ("docker02.rb.af9.us", "", {"CNAME": "phanpy.rb.af9.us."}, "local"),
        ("gitea.rb.af9.us", "", {"CNAME": "docker02.rb.af9.us."}, "local"),
    ]

    writer = _make_writer(mock_data, local_zones=local_zones, port=53, num_threads=1)
    writer.write_local_records_conf(str(tmp_path / "local_records.conf"))

    content = (tmp_path / "local_records.conf").read_text()

    # Exactly one local-zone declaration for the zone apex
    assert content.count('local-zone: "rb.af9.us."') == 1
    assert "transparent" in content

    # No per-hostname local-zone declarations
    assert 'local-zone: "gitea.rb.af9.us"' not in content
    assert 'local-zone: "docker02.rb.af9.us"' not in content
    assert 'local-zone: "phanpy.rb.af9.us"' not in content

    # All three records present as local-data
    assert 'local-data: "phanpy.rb.af9.us. IN A 192.168.10.31"' in content
    assert 'local-data: "docker02.rb.af9.us. IN CNAME phanpy.rb.af9.us."' in content
    assert 'local-data: "gitea.rb.af9.us. IN CNAME docker02.rb.af9.us."' in content


def test_ptr_records_emitted_without_zone_declaration(tmp_path):
    local_zones = [("rb.af9.us.", "transparent")]
    mock_data = [
        ("phanpy.rb.af9.us", "", {"A": "192.168.10.31"}, "local"),
        ("31.10.168.192.in-addr.arpa", "", {"PTR": "phanpy.rb.af9.us."}, "local"),
    ]

    writer = _make_writer(mock_data, local_zones=local_zones, port=53, num_threads=1)
    writer.write_local_records_conf(str(tmp_path / "local_records.conf"))

    content = (tmp_path / "local_records.conf").read_text()

    assert (
        'local-data: "31.10.168.192.in-addr.arpa. IN PTR phanpy.rb.af9.us."' in content
    )
    assert 'local-zone: "31.10.168.192.in-addr.arpa"' not in content


def test_multiple_zones_each_get_header(tmp_path):
    local_zones = [
        ("rb.af9.us.", "transparent"),
        ("foo.rb.af9.us.", "always_nxdomain"),
    ]
    mock_data = [
        ("phanpy.rb.af9.us", "", {"A": "192.168.10.31"}, "local"),
        ("foo.rb.af9.us", "", {"A": "0.0.0.0"}, "local"),
    ]

    writer = _make_writer(mock_data, local_zones=local_zones, port=53, num_threads=1)
    writer.write_local_records_conf(str(tmp_path / "local_records.conf"))

    content = (tmp_path / "local_records.conf").read_text()

    assert 'local-zone: "rb.af9.us." transparent' in content
    assert 'local-zone: "foo.rb.af9.us." always_nxdomain' in content


def test_adblock_conf_unchanged(tmp_path):
    mock_data = [
        ("badsite.com", "always_nxdomain", {}, "https://list-a.example/domains.txt"),
    ]
    writer = _make_writer(mock_data, port=53, num_threads=1)
    writer.write_compiled_adblock_conf(str(tmp_path / "adblock.conf"))

    content = (tmp_path / "adblock.conf").read_text()
    assert 'local-zone: "badsite.com" always_nxdomain' in content


def test_unbound_conf_includes_emitted_when_data_present(tmp_path):
    local_zones = [("rb.af9.us.", "transparent")]
    mock_data = [
        ("phanpy.rb.af9.us", "", {"A": "192.168.10.31"}, "local"),
        ("badsite.com", "always_nxdomain", {}, "https://list-a.example/domains.txt"),
    ]
    writer = _make_writer(mock_data, local_zones=local_zones, port=53, num_threads=1)
    writer.write_master_unbound_conf(str(tmp_path))

    content = (tmp_path / "unbound.conf").read_text()
    assert 'include: "/etc/unbound/local_records.conf"' in content
    assert 'include: "/etc/unbound/adblock.conf"' in content
