"""
der_sep2.models
~~~~~~~~~~~~~~~~~~
Shared data structures used across all modules.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, Flag, auto
from typing import Optional


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class Severity(Enum):
    INFO     = "INFO"
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


class ProbeType(Enum):
    NO_CERT       = "no_cert"         # Probe A — no client cert at all
    SELF_SIGNED   = "self_signed"     # Probe B — self-signed, not in ACL
    VALID_UNREG   = "valid_unregistered"  # Probe C — valid cert, not registered
    VALID_REG     = "valid_registered"    # Probe D — valid cert, registered


class ACLAccess(Flag):
    """
    Bitmask matching aclDefaultAccess in IEEE 2030.5 Table 12.
    Bit 3=GET, Bit 2=POST, Bit 1=PUT, Bit 0=DELETE
    """
    NONE   = 0
    DELETE = auto()   # 0x1
    PUT    = auto()   # 0x2
    POST   = auto()   # 0x4
    GET    = auto()   # 0x8
    FULL   = DELETE | PUT | POST | GET  # 0xf

    @classmethod
    def from_int(cls, value: int) -> "ACLAccess":
        result = cls.NONE
        if value & 0x8: result |= cls.GET
        if value & 0x4: result |= cls.POST
        if value & 0x2: result |= cls.PUT
        if value & 0x1: result |= cls.DELETE
        return result


# ---------------------------------------------------------------------------
# Discovery targets
# ---------------------------------------------------------------------------

@dataclass
class ServiceTarget:
    """
    A discovered 2030.5 service endpoint, as resolved from DNS-SD or
    a port scan.  This is the normalized unit that all later phases
    consume.
    """
    ip:          str
    port:        int
    base_path:   str = "/dcap"
    hostname:    Optional[str] = None   # as advertised in SRV record
    tls:         bool = True

    # DNS-SD metadata
    instance_name:  Optional[str] = None
    service_type:   Optional[str] = None   # e.g. "_2030-5._tcp"
    txt_properties: dict[str, str] = field(default_factory=dict)

    # How was this target found?
    source: str = "unknown"   # "dns_sd", "mdns", "port_scan"

    @property
    def base_url(self) -> str:
        scheme = "https" if self.tls else "http"
        host   = self.hostname or self.ip
        return f"{scheme}://{host}:{self.port}{self.base_path}"

    def __hash__(self):
        return hash((self.ip, self.port))

    def __eq__(self, other):
        return isinstance(other, ServiceTarget) and \
               self.ip == other.ip and self.port == other.port


# ---------------------------------------------------------------------------
# TLS / certificate findings
# ---------------------------------------------------------------------------

@dataclass
class CertInfo:
    """Parsed metadata from a server-side TLS certificate."""
    subject:        dict[str, str]
    issuer:         dict[str, str]
    san:            list[str]
    not_before:     datetime
    not_after:      datetime
    serial:         int
    fingerprint_sha256: str
    sig_algorithm:  str


    @property
    def is_expired(self) -> bool:
        from datetime import timezone
        return datetime.now(tz=timezone.utc) > self.not_after

    @property
    def days_until_expiry(self) -> int:
        from datetime import timezone
        delta = self.not_after - datetime.now(tz=timezone.utc)
        return delta.days

    @property
    def is_self_signed(self) -> bool:
        return self.subject == self.issuer


@dataclass
class WeakCipherResult:
    """A confirmed weak cipher finding from probing."""
    requested:   str    # the cipher string / selector we sent
    negotiated:  str    # what the server actually chose
    category:    str    # human-readable weakness label


@dataclass
class TLSProfile:
    """Full TLS handshake result for a target."""
    target:           ServiceTarget
    negotiated_version:  Optional[str]           = None
    negotiated_cipher:   Optional[str]           = None
    supported_versions:  list[str]               = field(default_factory=list)
    weak_ciphers:        list[WeakCipherResult]  = field(default_factory=list)
    # kept for backwards compat — mirrors weak_ciphers[*].requested
    supported_ciphers:   list[str]               = field(default_factory=list)
    cert_chain:          list[CertInfo]          = field(default_factory=list)
    requires_client_cert: bool                   = False
    accepted_self_signed: bool                   = False
    error:               Optional[str]           = None

    @property
    def leaf_cert(self) -> Optional[CertInfo]:
        return self.cert_chain[0] if self.cert_chain else None


# ---------------------------------------------------------------------------
# HTTP probe results
# ---------------------------------------------------------------------------

@dataclass
class ProbeResult:
    """Result of a single HTTP request against one resource."""
    target:       ServiceTarget
    probe_type:   ProbeType
    method:       str
    path:         str
    status_code:  Optional[int]    = None
    headers:      dict             = field(default_factory=dict)
    body:         Optional[bytes]  = None
    elapsed_ms:   Optional[float]  = None
    error:        Optional[str]    = None

    @property
    def success(self) -> bool:
        return self.status_code is not None and self.status_code < 500

    @property
    def body_text(self) -> Optional[str]:
        if self.body:
            try:
                return self.body.decode("utf-8", errors="replace")
            except Exception:
                return None
        return None


@dataclass
class ResourceNode:
    """
    A discovered resource in the 2030.5 tree.
    Tracks what was accessible under each probe type.
    """
    path:           str
    probe_results:  dict[ProbeType, ProbeResult] = field(default_factory=dict)
    children:       list["ResourceNode"]         = field(default_factory=list)
    hrefs:          list[str]                    = field(default_factory=list)

    @property
    def policy_gap(self) -> bool:
        """
        True if this resource is accessible without a cert (Probe A)
        when Probe D (full auth) also succeeds — potential policy violation
        depending on which resource this is.
        """
        a = self.probe_results.get(ProbeType.NO_CERT)
        d = self.probe_results.get(ProbeType.VALID_REG)
        if a and d:
            return a.status_code == d.status_code == 200
        return False


# ---------------------------------------------------------------------------
# Security findings
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """A single security finding produced by any phase of the tool."""
    severity:    Severity
    title:       str
    description: str
    target:      ServiceTarget
    evidence:    dict              = field(default_factory=dict)
    path:        Optional[str]    = None
    probe_type:  Optional[ProbeType] = None
    timestamp:   datetime         = field(default_factory=datetime.utcnow)

    def __str__(self) -> str:
        loc = f" @ {self.path}" if self.path else ""
        return f"[{self.severity.value}] {self.title}{loc} ({self.target.ip}:{self.target.port})"
