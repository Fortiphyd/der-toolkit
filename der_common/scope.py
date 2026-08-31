"""Authorization / scope gate shared by all active operations.

These tools can crash live grid equipment. Mapping is read-only and safe;
fuzzing is disruptive. Every entry point that emits traffic to a target should
route through here so the safety policy lives in exactly one place -- and so the
MCP server can surface a clear, auditable consent boundary in the demo.
"""

from __future__ import annotations

import ipaddress


class ScopeError(PermissionError):
    """Raised when a target is outside the caller's authorized scope, or a
    disruptive action was requested without explicit consent."""


def assert_in_scope(target_ip: str, authorized_scope: list[str]) -> None:
    """Refuse targets the operator did not explicitly declare in scope.

    `authorized_scope` is a list of IPs or CIDRs the operator affirms they are
    authorized to test. Empty scope means nothing is authorized -- fail closed.
    """
    if not authorized_scope:
        raise ScopeError(
            "No authorized_scope declared. Refusing to touch any target. "
            "Pass the IPs/CIDRs you are authorized to assess."
        )
    ip = ipaddress.ip_address(target_ip)
    for entry in authorized_scope:
        net = ipaddress.ip_network(entry, strict=False)
        if ip in net:
            return
    raise ScopeError(
        f"Target {target_ip} is not within authorized_scope {authorized_scope}. "
        "Refusing to proceed."
    )


def require_disruptive_consent(allow_disruptive: bool) -> None:
    """Gate for actions that can hang, crash, or corrupt a live device.

    Fuzzing must pass `allow_disruptive=True`. This is deliberately explicit so
    an AI agent cannot start a disruptive run by default."""
    if not allow_disruptive:
        raise ScopeError(
            "This operation can disrupt or crash live equipment. "
            "Re-invoke with allow_disruptive=True to confirm you are authorized "
            "and the target can tolerate disruption."
        )
