"""Shared result schema for all DER protocol tools.

Every mapper and fuzzer normalizes its output to :class:`AttackSurface`. This is
the linchpin of the toolkit: one comparable structure across DNP3, SunSpec, and
IEEE 2030.5 so a report -- or the MCP-driven AI -- can rank *reachable, writable,
high-severity* control points uniformly, regardless of protocol.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

Protocol = Literal["dnp3", "sunspec", "sep2"]
Severity = Literal["info", "low", "medium", "high", "critical"]


class Target(BaseModel):
    ip: str
    port: int
    protocol: Protocol
    base_path: str | None = None  # e.g. sep2 "/dcap"
    unit_id: int | None = None    # modbus/sunspec unit id
    hostname: str | None = None


class AuthProfile(BaseModel):
    """How (or whether) the target authenticates a client.

    This is where the project's core thesis lives: `requires_auth=False` means the
    self-describing surface is reachable by anyone; for sep2, a leaked client
    cert flips `client_cert_present` to True and collapses to the same state.
    """

    scheme: Literal["none", "modbus", "tls_client_cert"] = "none"
    requires_auth: bool = False
    tls: bool = False
    tls_version: str | None = None
    weak_ciphers: list[str] = Field(default_factory=list)
    client_cert_present: bool = False
    accepted_self_signed: bool | None = None
    notes: str | None = None


class ControlPoint(BaseModel):
    """A single reachable read/write point on the target.

    `semantic_label` is the whole story for self-describing protocols: on legacy
    Modbus it is often unknown ("register 40072"); on SunSpec/2030.5 the device
    hands it to you ("AC Power Setpoint").
    """

    address: str                       # "40072" | "/edev/1/derc" | "group12:idx3"
    semantic_label: str | None = None
    model: str | None = None        # sunspec model / dnp3 group / sep2 resource type
    readable: bool = False
    writable: bool = False
    value: Any = None
    units: str | None = None
    severity: Severity = "info"
    reachable_unauthenticated: bool = False


class FuzzFinding(BaseModel):
    """An anomaly observed while fuzzing. Large evidence stays on disk.

    `artifact_ref` points into the run directory (pcap, boofuzz db, raw bytes) --
    it is NEVER an inline blob, so the MCP layer never streams a 500 MB db into
    the model's context.
    """

    title: str
    input_summary: str
    response_summary: str | None = None
    crashed: bool = False
    severity: Severity = "info"
    reproducible: bool | None = None
    artifact_ref: str | None = None


class Finding(BaseModel):
    """A cross-cutting security observation not tied to one control point.

    Covers things like TLS/auth misconfiguration, ACL policy gaps, or dangerous
    HTTP methods -- issues that describe the *posture* of the target rather than
    a single reachable point or a fuzzing crash.
    """

    severity: Severity = "info"
    title: str
    description: str = ""
    category: str = "general"     # "tls" | "policy" | "method" | "discovery" | ...
    path: str | None = None
    evidence: dict = Field(default_factory=dict)


class AttackSurface(BaseModel):
    protocol: Protocol
    target: Target
    auth_profile: AuthProfile
    control_points: list[ControlPoint] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    fuzz_findings: list[FuzzFinding] = Field(default_factory=list)
    generated_at: str                  # ISO-8601, stamped by the caller
    tool_version: str = "0.1.0"

    def writable_reachable(self) -> list[ControlPoint]:
        """The headline number for an operator: writable points an
        unauthenticated attacker can reach."""
        return [
            cp for cp in self.control_points
            if cp.writable and cp.reachable_unauthenticated
        ]
