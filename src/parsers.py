import re
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Generator


@dataclass
class SourceStats:
    """Ingestion statistics for a single adlist source."""

    url: str
    fetched: int = 0
    unique: int = 0
    exact_dupes: int = 0
    overlaps_with: dict[str, int] = field(default_factory=dict)

    @property
    def short_name(self) -> str:
        """Last two path components of the URL, for compact display."""
        parts = self.url.rstrip("/").split("/")
        return "/".join(parts[-2:]) if len(parts) >= 2 else self.url


class BaseParser(ABC):
    """
    Abstract base class for adlist parsers.

    Subclasses implement parse_line() to handle format-specific syntax.
    Network streaming is handled here so parsers stay stateless.
    """

    def __init__(self, url: str):
        self.url = url

    @abstractmethod
    def parse_line(self, line: str) -> str | None:
        """Return a bare domain string, or None if the line should be skipped."""
        pass

    def stream_domains(self) -> Generator[str, None, None]:
        """Stream a remote list line-by-line, yielding valid domains."""
        try:
            req = urllib.request.Request(
                self.url,
                headers={"User-Agent": "Mozilla/5.0 (Unbound-GitOps-Compiler)"},
            )
            with urllib.request.urlopen(req) as response:
                for raw_line in response:
                    line = raw_line.decode("utf-8", errors="ignore").strip()
                    domain = self.parse_line(line)
                    if domain:
                        yield domain
        except Exception as e:
            print(f"Warning: error streaming from {self.url}: {e}")


class HostsFileParser(BaseParser):
    """Parses /etc/hosts-style lists (e.g. '0.0.0.0 ads.example.com')."""

    def __init__(self, url: str):
        super().__init__(url)
        self.pattern = re.compile(r"^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9._-]+)")

    def parse_line(self, line: str) -> str | None:
        if not line or line.startswith("#"):
            return None
        line = line.split("#")[0].strip()
        match = self.pattern.match(line)
        return match.group(1).lower() if match else None


class PureDomainParser(BaseParser):
    """Parses raw domain lists (one domain per line, e.g. Firebog-style lists)."""

    def parse_line(self, line: str) -> str | None:
        if not line or line.startswith("#") or line.startswith("//"):
            return None
        domain = line.split("#")[0].strip()
        if re.match(r"^[a-zA-Z0-9._-]+$", domain):
            return domain.lower()
        return None


class AdBlockFilterParser(BaseParser):
    """Parses AdBlock filter syntax, extracting the domain from '||ads.com^' entries."""

    def __init__(self, url: str):
        super().__init__(url)
        self.pattern = re.compile(r"^\|\|([a-zA-Z0-9._-]+)\^")

    def parse_line(self, line: str) -> str | None:
        if not line or line.startswith("!") or line.startswith("["):
            return None
        match = self.pattern.match(line)
        return match.group(1).lower() if match else None


PARSER_REGISTRY = {
    "hosts": HostsFileParser,
    "domains": PureDomainParser,
    "adblock": AdBlockFilterParser,
}


class DomainNormalizer:
    """
    Orchestrates ingestion across multiple adlists with full attribution tracking.

    Tracks two levels of deduplication:
    - Exact duplicates: domain appears verbatim in more than one list. Recorded
      per-source in SourceStats.overlaps_with so the summary can show a pairwise
      overlap matrix.
    - Subsumption duplicates: a parent zone blocks a child domain. These are
      caught by the trie after ingestion, not here. Each yielded domain carries
      its source URL so the trie can attribute subsumption pruning back to the
      correct list.

    Note: the _seen_domains dict grows to one entry per unique domain before trie
    ingestion. At large list sizes (200k+ entries) this can reach 30-40MB —
    acceptable for a build pipeline, worth noting if memory is constrained.
    """

    def __init__(self, config_list: list[dict[str, str]]):
        self.config_list = config_list
        # domain -> URL of the first list that introduced it
        self._domain_source: dict[str, str] = {}
        # URL -> SourceStats for all lists
        self.source_stats: dict[str, SourceStats] = {}

    def yield_all_domains(self) -> Generator[tuple[str, str], None, None]:
        """
        Yield (domain, source_url) tuples across all configured lists.

        Exact duplicates are counted but not re-yielded. The source_url is
        passed through so the trie can attribute each domain to its origin list.
        """
        for item in self.config_list:
            url = item.get("url")
            fmt = item.get("format", "domains")

            stats = SourceStats(url=url)
            self.source_stats[url] = stats

            parser_class = PARSER_REGISTRY.get(fmt, PureDomainParser)
            parser = parser_class(url)

            print(f"  Ingesting [{fmt}] from: {url}")
            for domain in parser.stream_domains():
                stats.fetched += 1

                if domain in self._domain_source:
                    # Exact duplicate — record which list we overlapped with.
                    stats.exact_dupes += 1
                    origin_url = self._domain_source[domain]
                    stats.overlaps_with[origin_url] = (
                        stats.overlaps_with.get(origin_url, 0) + 1
                    )
                else:
                    self._domain_source[domain] = url
                    stats.unique += 1
                    yield domain, url
