# tests/test_zone_validation.py
import pytest
from pydantic import ValidationError
from src.schemas import LocalZone, LocalDNSRecord, DNSRecords


def _record(domain, **record_kwargs):
    return LocalDNSRecord(
        domain=domain,
        auto_ptr=False,
        records=DNSRecords(**record_kwargs)
    )


def test_valid_a_record_accepted():
    zone = LocalZone(
        zone="rb.af9.us.",
        policy="transparent",
        records=[_record("phanpy.rb.af9.us", A="192.168.10.31")]
    )
    assert len(zone.records) == 1


def test_valid_aaaa_record_accepted():
    zone = LocalZone(
        zone="rb.af9.us.",
        policy="transparent",
        records=[_record("phanpy.rb.af9.us", AAAA="fd00::1")]
    )
    assert len(zone.records) == 1


def test_zone_apex_itself_accepted():
    """A record whose domain equals the zone apex (without trailing dot) is valid."""
    zone = LocalZone(
        zone="rb.af9.us.",
        policy="always_nxdomain",
        records=[_record("rb.af9.us", A="0.0.0.0")]
    )
    assert len(zone.records) == 1


def test_bare_hostname_rejected():
    """A bare hostname with no zone suffix should fail validation."""
    with pytest.raises(ValidationError) as exc_info:
        LocalZone(
            zone="rb.af9.us.",
            policy="transparent",
            records=[_record("wifi", A="192.168.10.7")]
        )
    assert "'wifi'" in str(exc_info.value)
    assert "rb.af9.us" in str(exc_info.value)


def test_wrong_zone_domain_rejected():
    """A domain from a different zone should fail validation."""
    with pytest.raises(ValidationError) as exc_info:
        LocalZone(
            zone="rb.af9.us.",
            policy="transparent",
            records=[_record("router.lan", A="192.168.1.1")]
        )
    assert "'router.lan'" in str(exc_info.value)


def test_multiple_invalid_domains_all_reported():
    """All invalid domains should appear in the error message, not just the first."""
    with pytest.raises(ValidationError) as exc_info:
        LocalZone(
            zone="rb.af9.us.",
            policy="transparent",
            records=[
                _record("wifi", A="192.168.10.7"),
                _record("router.lan", A="192.168.1.1"),
            ]
        )
    error_text = str(exc_info.value)
    assert "'wifi'" in error_text
    assert "'router.lan'" in error_text


def test_empty_records_list_valid():
    """A zone with no records is valid — records are optional."""
    zone = LocalZone(zone="rb.af9.us.", policy="transparent", records=[])
    assert zone.records == []


def test_mixed_valid_and_invalid_reports_only_invalid():
    """Valid domains should not appear in the error message."""
    with pytest.raises(ValidationError) as exc_info:
        LocalZone(
            zone="rb.af9.us.",
            policy="transparent",
            records=[
                _record("phanpy.rb.af9.us", A="192.168.10.31"),  # valid
                _record("wifi", A="192.168.10.7"),                # invalid
            ]
        )
    error_text = str(exc_info.value)
    assert "'wifi'" in error_text
    assert "'phanpy.rb.af9.us'" not in error_text


def test_cname_field_not_accepted():
    """DNSRecords should not accept a CNAME field."""
    with pytest.raises((ValidationError, TypeError)):
        DNSRecords(CNAME="nas.lan.")


def test_srv_field_not_accepted():
    """DNSRecords should not accept an SRV field."""
    with pytest.raises((ValidationError, TypeError)):
        DNSRecords(SRV="0 100 88 kdc.lan.")
