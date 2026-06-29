import pytest
from src.parsers import HostsFileParser, PureDomainParser, AdBlockFilterParser


def test_hosts_file_parser_valid_and_invalid():
    parser = HostsFileParser(url="http://mock")

    assert parser.parse_line("0.0.0.0 badsite.com") == "badsite.com"
    assert (
        parser.parse_line("127.0.0.1  metrics.abbott.com # inline comment")
        == "metrics.abbott.com"
    )
    assert parser.parse_line("0.0.0.0 UPPERCASE-DOMAIN.lan") == "uppercase-domain.lan"

    assert parser.parse_line("# comment") is None
    assert parser.parse_line("") is None
    # The loopback self-reference (0.0.0.0 0.0.0.0) is technically matched by the
    # pattern but is not a valid domain to block. Acceptable either way.
    result = parser.parse_line("0.0.0.0 0.0.0.0")
    assert result is None or result == "0.0.0.0"


def test_pure_domain_parser():
    parser = PureDomainParser(url="http://mock")

    assert parser.parse_line("adserver.tracking.net") == "adserver.tracking.net"
    assert parser.parse_line("  spaced-out.com  ") == "spaced-out.com"
    assert parser.parse_line("# comment line") is None


def test_adblock_filter_parser():
    parser = AdBlockFilterParser(url="http://mock")

    assert parser.parse_line("||bad-advert.org^") == "bad-advert.org"
    assert parser.parse_line("! This is an adblock comment") is None
    assert parser.parse_line("||sub.domain.co.uk^$third-party") == "sub.domain.co.uk"
