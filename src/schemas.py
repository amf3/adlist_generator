from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, model_validator
from typing import Optional, Literal


class DNSRecords(BaseModel):
    """
    Resource records for a single hostname within a local zone.

    Only A and AAAA are supported. Unbound does not expand CNAME chains in
    local-data context — a client querying for an A record expects the full
    expanded answer, but Unbound's iterator only consults local zones once
    for the original query and does not re-enter local zone resolution when
    following CNAME hops. The result is that only the first hop is returned.

    For hosts that would previously have been CNAMEs (e.g. service aliases
    pointing at a server), use the target's A record directly. Since configs
    are generated rather than hand-maintained, there is no cost to repeating
    an IP address across multiple entries.

    MX, NS, SRV, and TXT are omitted as they are not needed for split-horizon
    local DNS in a home lab or small network context. Extra fields (CNAME,
    SRV, etc.) are rejected outright rather than silently dropped, so a
    misconfigured local_dns.yml fails validation instead of producing a
    local-data entry with no records.
    """
    model_config = ConfigDict(extra="forbid")

    A: Optional[IPvAnyAddress] = Field(None, description="IPv4 address")
    AAAA: Optional[IPvAnyAddress] = Field(None, description="IPv6 address")


class LocalDNSRecord(BaseModel):
    """A single hostname entry within a local zone."""
    domain: str
    auto_ptr: bool = Field(
        default=False,
        description="Synthesize a reverse PTR record for A/AAAA entries."
    )
    records: DNSRecords


ZonePolicy = Literal[
    "static",
    "transparent",
    "inform",
    "always_nxdomain",
    "redirect",
    "refuse",
    "deny",
]


class LocalZone(BaseModel):
    """
    A local authority zone with a shared policy and a list of hostname records.

    All hostnames in this zone share the zone policy. For one-off overrides
    (e.g. blocking a single hostname within an otherwise transparent zone),
    declare a second, more specific zone entry for that hostname. Unbound
    matches the most specific zone, so foo.rb.af9.us always_nxdomain takes
    precedence over rb.af9.us transparent.
    """
    zone: str = Field(description="Zone apex (e.g. 'rb.af9.us.'). Include trailing dot.")
    policy: ZonePolicy
    records: list[LocalDNSRecord] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_record_domains_within_zone(self) -> "LocalZone":
        """
        Ensure every record domain belongs to this zone.

        Each domain must either equal the zone apex (minus trailing dot) or
        be a subdomain of it. This catches bare hostnames like 'wifi' that
        would produce a broken local-data directive without the full FQDN.
        """
        zone_apex = self.zone.rstrip(".")

        invalid = [
            record.domain
            for record in self.records
            if record.domain != zone_apex
            and not record.domain.endswith(f".{zone_apex}")
        ]

        if invalid:
            raise ValueError(
                f"The following domains do not belong to zone '{self.zone}': "
                + ", ".join(f"'{d}'" for d in invalid)
                + f". Each domain must equal '{zone_apex}' or end with '.{zone_apex}'."
            )

        return self


class LocalDNSConfig(BaseModel):
    """Root model for local_dns.yml."""
    local_dns: list[LocalZone]


AccessControlAction = Literal[
    "deny", "refuse", "allow", "allow_snoop", "deny_non_local", "refuse_non_local"
]


class AccessControlEntry(BaseModel):
    """A single access-control directive, e.g. '192.168.0.0/16 allow'."""
    subnet: str
    action: AccessControlAction


class UnboundServerSettings(BaseModel):
    """
    Unbound server configuration.

    All fields use underscores and map 1:1 to unbound.conf directives.
    The writer converts underscores to hyphens when rendering the config file,
    so server_config.yml and this schema share a single consistent naming
    convention.
    """

    # --- Network ---
    port: int = Field(53, ge=1, le=65535)
    interface: list[str] = Field(
        default_factory=lambda: ["0.0.0.0", "::0"],
        description="Interfaces to listen on."
    )
    do_ip4: bool = Field(True)
    do_ip6: bool = Field(True)
    access_control: list[AccessControlEntry] = Field(default_factory=list)
    so_sndbuf: int = Field(0)
    so_rcvbuf: int = Field(0)

    # --- Process / runtime ---
    username: str = Field("")
    chroot: str = Field("")
    do_daemonize: bool = Field(False)
    pidfile: str = Field("")
    logfile: str = Field("")

    # --- Threading and cache ---
    num_threads: int = Field(1, ge=1)
    msg_cache_size: str = Field("4m")
    rrset_cache_size: str = Field("8m")

    # --- TTL and cache behaviour ---
    cache_min_ttl: int = Field(300, ge=0)
    cache_max_ttl: int = Field(86400, ge=0)
    cache_max_negative_ttl: int = Field(30, ge=0)
    serve_expired: bool = Field(True)
    serve_expired_ttl: int = Field(86400, ge=0)
    prefetch: bool = Field(True)
    prefetch_key: bool = Field(True)

    # --- Privacy and hardening ---
    hide_identity: bool = Field(True)
    hide_version: bool = Field(True)
    harden_glue: bool = Field(True)
    harden_dnssec_stripped: bool = Field(True)

    # --- DNSSEC ---
    trust_anchor_file: str = Field("")
    root_hints: str = Field("")
    domain_insecure: list[str] = Field(
        default_factory=list,
        description="Domains exempt from DNSSEC validation."
    )

    # --- Logging ---
    verbosity: int = Field(0, ge=0, le=5)
    use_syslog: bool = Field(False)
    log_queries: bool = Field(False)
    log_replies: bool = Field(False)
    log_time_ascii: bool = Field(True)


ListFormat = Literal["domains", "hosts", "adblock"]


class AdlistSource(BaseModel):
    """A single blocklist source."""
    url: str = Field(description="URL of the blocklist to fetch.")
    format: ListFormat = Field(
        default="domains",
        description=(
            "Parsing format for this list. "
            "'domains': one bare domain per line. "
            "'hosts': /etc/hosts style (0.0.0.0 or 127.0.0.1 prefix). "
            "'adblock': AdBlock filter syntax (||domain.com^)."
        )
    )


class AdlistConfig(BaseModel):
    """Root model for adlists_sources.yml."""
    sources: list[AdlistSource]
