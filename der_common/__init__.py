"""Shared models and safety primitives for the DER toolkit."""

from der_common.schema import (
    AttackSurface,
    AuthProfile,
    ControlPoint,
    Finding,
    FuzzFinding,
    Target,
)
from der_common.scope import ScopeError, assert_in_scope, require_disruptive_consent

__all__ = [
    "AttackSurface",
    "AuthProfile",
    "ControlPoint",
    "Finding",
    "FuzzFinding",
    "Target",
    "ScopeError",
    "assert_in_scope",
    "require_disruptive_consent",
]
