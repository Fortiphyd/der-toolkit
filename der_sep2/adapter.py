"""Adapter: native sep2_mapper results -> der_common.AttackSurface.

Keeps the original mapper/fuzzer engine untouched and normalizes its output to
the shared schema so IEEE 2030.5 results are directly comparable with DNP3 and
SunSpec. This is where the project's thesis is made structural: a supplied
client cert flips ``client_cert_present`` and every reachable resource carries a
self-describing ``semantic_label`` pulled from the 2030.5 function-set policy.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from der_common.schema import (
    AttackSurface,
    AuthProfile,
    ControlPoint,
    Finding,
    FuzzFinding,
    Target,
)

from der_sep2.models import (
    ACLAccess,
    ProbeType,
    ResourceNode,
    ServiceTarget,
    Severity,
    TLSProfile,
)
from der_sep2.models import Finding as Sep2Finding
from der_sep2.mapping.resource_tree import lookup_policy

_SEV_ORDER = ["info", "low", "medium", "high", "critical"]
_WRITE_MASK = ACLAccess.POST | ACLAccess.PUT | ACLAccess.DELETE


# ---------------------------------------------------------------------------
# small predicates
# ---------------------------------------------------------------------------

def _http_ok(pr) -> bool:
    return bool(pr and pr.status_code and 200 <= pr.status_code < 300)


def _mtls_enforced(pr) -> bool:
    return bool(pr and pr.error and ("mTLS_REQUIRED" in pr.error or "CERT_REJECTED" in pr.error))


def _sev(s: Severity) -> str:
    return s.value.lower()


def _max_sev(a: str, b: str) -> str:
    return a if _SEV_ORDER.index(a) >= _SEV_ORDER.index(b) else b


# ---------------------------------------------------------------------------
# component conversions
# ---------------------------------------------------------------------------

def target_to_common(t: ServiceTarget) -> Target:
    return Target(
        ip=t.ip,
        port=t.port,
        protocol="sep2",
        base_path=t.base_path,
        hostname=t.hostname,
    )


def auth_profile(map_result, tls_profile: Optional[TLSProfile], used_cert: bool) -> AuthProfile:
    """Derive the AuthProfile from a TLS handshake (if available) and the
    observed reachability of the no-cert probe across the resource tree."""
    nodes = map_result.nodes.values()
    no_cert_ok = any(_http_ok(n.probe_results.get(ProbeType.NO_CERT)) for n in nodes)
    no_cert_blocked = any(_mtls_enforced(n.probe_results.get(ProbeType.NO_CERT)) for n in nodes)
    self_signed_ok = any(_http_ok(n.probe_results.get(ProbeType.SELF_SIGNED)) for n in nodes)

    # requires_auth: the server refuses the unauthenticated client everywhere.
    requires_auth = no_cert_blocked and not no_cert_ok

    prof = AuthProfile(
        scheme="tls_client_cert" if requires_auth else "none",
        requires_auth=requires_auth,
        tls=map_result.target.tls,
        client_cert_present=used_cert,
        accepted_self_signed=self_signed_ok or None,
    )
    if tls_profile is not None:
        prof.tls_version = tls_profile.negotiated_version
        prof.weak_ciphers = [w.requested for w in tls_profile.weak_ciphers]
        if tls_profile.accepted_self_signed:
            prof.accepted_self_signed = True
        # a server that requires a client cert but still serves the full
        # self-describing tree once one is presented is the "cert leak" case
        if tls_profile.requires_client_cert and used_cert:
            prof.notes = (
                "Full resource tree is served once a client certificate is "
                "presented; a leaked/misvalidated cert collapses to the "
                "unauthenticated-equivalent exposure."
            )
    return prof


def _control_point(path: str, node: ResourceNode, path_sev: dict[str, str]) -> ControlPoint:
    policy = lookup_policy(path)
    probe_a = node.probe_results.get(ProbeType.NO_CERT)
    method_probe: dict = (probe_a.headers.get("_method_probe", {}) if probe_a else {}) or {}

    get_ok_any = any(_http_ok(r) for r in node.probe_results.values())
    write_ok_unauth = any(
        m in ("POST", "PUT", "DELETE") and s and 200 <= s < 300
        for m, s in method_probe.items()
    )
    policy_writable = bool(policy.acl_default_access & _WRITE_MASK) if policy else False
    writable = write_ok_unauth or policy_writable
    reachable_unauth = _http_ok(probe_a) or write_ok_unauth

    label = policy.function_set if policy else path.rstrip("/").split("/")[-1] or None
    # Severity is driven by the mapper's graded findings. Without a finding,
    # only an *observed* unauthenticated write self-elevates; a merely
    # spec-permitted-writable point that is reachable is low, everything else info.
    sev = path_sev.get(path)
    if sev is None:
        if write_ok_unauth:
            sev = "high"
        elif reachable_unauth and writable:
            sev = "low"
        else:
            sev = "info"

    return ControlPoint(
        address=path,
        semantic_label=label,
        model=policy.function_set if policy else None,
        readable=get_ok_any,
        writable=writable,
        severity=sev,
        reachable_unauthenticated=reachable_unauth,
    )


def _finding(f: Sep2Finding, category: str) -> Finding:
    return Finding(
        severity=_sev(f.severity),
        title=f.title,
        description=f.description,
        category=category,
        path=f.path,
        evidence=f.evidence or {},
    )


def _fuzz_finding(f: Sep2Finding) -> FuzzFinding:
    payload = f.evidence.get("payload") or f.evidence.get("input") if f.evidence else None
    return FuzzFinding(
        title=f.title,
        input_summary=str(payload) if payload else f.description[:200],
        response_summary=str(f.evidence.get("response")) if f.evidence.get("response") else None,
        crashed="crash" in f.title.lower() or "500" in f.title,
        severity=_sev(f.severity),
    )


# ---------------------------------------------------------------------------
# top-level assembly
# ---------------------------------------------------------------------------

def build_attack_surface(
    map_result,
    tls_profile: Optional[TLSProfile] = None,
    used_cert: bool = False,
    security_findings: Optional[list[Sep2Finding]] = None,
    fuzz_findings: Optional[list[Sep2Finding]] = None,
    generated_at: Optional[str] = None,
) -> AttackSurface:
    """Assemble a normalized AttackSurface from one target's mapping run."""
    # per-path severity taken from the mapper's own graded findings
    path_sev: dict[str, str] = {}
    for f in map_result.findings:
        if f.path:
            path_sev[f.path] = _max_sev(path_sev.get(f.path, "info"), _sev(f.severity))

    control_points = [
        _control_point(path, node, path_sev)
        for path, node in sorted(map_result.nodes.items())
    ]

    # cross-cutting findings: mapper findings + any extra TLS/security findings
    sec = list(map_result.findings)
    if security_findings:
        sec.extend(security_findings)
    findings = [_finding(f, _categorize(f)) for f in sec]

    return AttackSurface(
        protocol="sep2",
        target=target_to_common(map_result.target),
        auth_profile=auth_profile(map_result, tls_profile, used_cert),
        control_points=control_points,
        findings=findings,
        fuzz_findings=[_fuzz_finding(f) for f in (fuzz_findings or [])],
        generated_at=generated_at or datetime.now(tz=timezone.utc).isoformat(),
    )


def _categorize(f: Sep2Finding) -> str:
    t = f.title.lower()
    if "cipher" in t or "tls" in t or "cert" in t:
        return "tls"
    if "method" in t or "trace" in t or "options" in t:
        return "method"
    if "not linked" in t or "hidden" in t:
        return "discovery"
    return "policy"
