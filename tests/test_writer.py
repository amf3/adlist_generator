# tests/test_writer.py
import os
from src.schemas import UnboundServerSettings, AccessControlEntry
from src.writer import ConfigurationWriter


def _make_writer(mock_data, **settings_kwargs):
    settings = UnboundServerSettings(**settings_kwargs)
    return ConfigurationWriter(server_settings=settings, finalized_data=mock_data)


def test_writer_full_pipeline(tmp_path):
    mock_data = [
        ("my-nas.lan", "static", {"A": "192.168.1.10"}, "local"),
        ("10.1.168.192.in-addr.arpa", "static", {"PTR": "my-nas.lan."}, "local"),
        ("metrics-tracker.example.com", "inform", {"CNAME": "my-nas.lan"}, "local"),
        (
            "badsite.adserver.com",
            "always_nxdomain",
            {},
            "https://list-a.example/domains.txt",
        ),
    ]

    writer = _make_writer(
        mock_data,
        port=53,
        num_threads=2,
        msg_cache_size="8m",
        rrset_cache_size="16m",
        verbosity=1,
        hide_identity=True,
    )
    writer.write_master_unbound_conf(str(tmp_path))
    writer.write_compiled_adblock_conf(str(tmp_path / "adblock.conf"))
    writer.write_local_records_conf(str(tmp_path / "local_records.conf"))
    writer.write_git_manifest(str(tmp_path / "manifest.reversed"))

    unbound = (tmp_path / "unbound.conf").read_text()
    assert "port: 53" in unbound
    assert "num-threads: 2" in unbound
    assert "hide-identity: yes" in unbound
    assert 'include: "/etc/unbound/local_records.conf"' in unbound
    assert 'include: "/etc/unbound/adblock.conf"' in unbound

    adblock = (tmp_path / "adblock.conf").read_text()
    assert 'local-zone: "badsite.adserver.com" always_nxdomain' in adblock
    assert "my-nas.lan" not in adblock

    local = (tmp_path / "local_records.conf").read_text()
    assert 'local-zone: "my-nas.lan" static' in local
    assert 'local-data: "my-nas.lan. IN A 192.168.1.10"' in local

    manifest = (tmp_path / "manifest.reversed").read_text()
    assert "[local]" in manifest
    assert "[list-a.example/domains.txt]" in manifest
    assert "com.adserver.badsite" in manifest


def test_writer_omits_adblock_include_when_empty(tmp_path):
    mock_data = [("my-nas.lan", "static", {"A": "192.168.1.10"}, "local")]
    writer = _make_writer(mock_data, port=53, num_threads=1)
    writer.write_master_unbound_conf(str(tmp_path))

    content = (tmp_path / "unbound.conf").read_text()
    assert 'include: "/etc/unbound/local_records.conf"' in content
    assert 'include: "/etc/unbound/adblock.conf"' not in content


def test_writer_renders_access_control(tmp_path):
    mock_data = []
    settings = UnboundServerSettings(
        access_control=[
            AccessControlEntry(subnet="192.168.0.0/16", action="allow"),
            AccessControlEntry(subnet="0.0.0.0/0", action="refuse"),
        ]
    )
    writer = ConfigurationWriter(server_settings=settings, finalized_data=mock_data)
    writer.write_master_unbound_conf(str(tmp_path))

    content = (tmp_path / "unbound.conf").read_text()
    assert "access-control: 192.168.0.0/16 allow" in content
    assert "access-control: 0.0.0.0/0 refuse" in content
