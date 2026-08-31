"""der_common.scope is the single chokepoint between read-only mapping and
disruptive fuzzing that can hang or crash live grid equipment. Every CLI and
the MCP server route through assert_in_scope/require_disruptive_consent, so a
regression here silently reopens every one of them at once.
"""

import pytest

from der_common.scope import ScopeError, assert_in_scope, require_disruptive_consent


def test_empty_scope_rejects_everything():
    with pytest.raises(ScopeError):
        assert_in_scope("127.0.0.1", [])


def test_ip_inside_declared_cidr_passes():
    assert_in_scope("192.168.1.50", ["192.168.1.0/24"])


def test_ip_outside_declared_cidr_rejected():
    with pytest.raises(ScopeError):
        assert_in_scope("10.0.0.1", ["192.168.1.0/24"])


def test_single_host_entry_matches_only_itself():
    assert_in_scope("127.0.0.1", ["127.0.0.1/32"])
    with pytest.raises(ScopeError):
        assert_in_scope("127.0.0.2", ["127.0.0.1/32"])


def test_checks_every_entry_in_a_multi_entry_scope():
    scope = ["10.0.0.0/24", "192.168.1.0/24"]
    assert_in_scope("10.0.0.5", scope)
    assert_in_scope("192.168.1.5", scope)
    with pytest.raises(ScopeError):
        assert_in_scope("172.16.0.1", scope)


def test_disruptive_consent_required():
    with pytest.raises(ScopeError):
        require_disruptive_consent(False)
    require_disruptive_consent(True)  # must not raise
