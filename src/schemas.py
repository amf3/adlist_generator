# src/schemas.py
from pydantic import BaseModel, Field, IPvAnyAddress, ConfigDict
from typing import Optional, Literal


class DNSRecords(BaseModel):
    """Resource records for a local DNS entry."""

    A: Optional[IPvAnyAddress] = Field(None, description="IPv4 address")
    AAAA: Optional[IPvAnyAddress] = Field(None, description="IPv6 address")
    CNAME: Optional[str] = Field(None, description="Canonical hostname")
    SRV: Optional[str] = Field(
        None, description="SRV record string (e.g. '0 100 88 kdc.lan.')"
    )


class LocalDNSEntry(BaseModel):
    domain: str
    policy: Literal[
        "static",
        "transparent",
        "inform",
        "always_nxdomain",
        "redirect",
        "refuse",
        "deny",
    ]
    auto_ptr: bool = Field(default=False)
    records: DNSRecords


class LocalDNSConfig(BaseModel):
    """Root model for local_dns.yml."""

    local_dns: list[LocalDNSEntry]


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
    convention without aliases or passthrough escapes.

    Fields are a curated subset of commonly used Unbound directives. If you
    need a directive that isn't here, add it as a typed field rather than
    reaching for a passthrough dict — that's how we keep the schema honest.
    """

    # --- Network ---
    port: int = Field(53, ge=1, le=65535)
    interface: list[str] = Field(
        default_factory=lambda: ["0.0.0.0", "::0"],
        description="Interfaces to listen on. Accepts IPs or interface names.",
    )
    do_ip4: bool = Field(True)
    do_ip6: bool = Field(True)
    access_control: list[AccessControlEntry] = Field(
        default_factory=list,
        description="ACL entries controlling which clients may query the resolver.",
    )

    # --- Threading and cache ---
    num_threads: int = Field(1, ge=1)
    msg_cache_size: str = Field("4m")
    rrset_cache_size: str = Field("8m")

    # --- Privacy and hardening ---
    hide_identity: bool = Field(True)
    hide_version: bool = Field(True)
    harden_glue: bool = Field(True)
    harden_dnssec_stripped: bool = Field(True)

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
        ),
    )


class AdlistConfig(BaseModel):
    """Root model for adlists_sources.yml."""

    sources: list[AdlistSource]
