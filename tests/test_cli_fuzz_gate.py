"""Regression coverage for the exact class of bug found in der_sep2 this
session: a fuzz/run CLI command that never calls der_common.scope at all, so
it happily sends disruptive traffic to any host with no authorized-scope or
consent check. Each of the three CLIs must fail closed -- and must do so
*before* touching the module that actually talks to the network -- when
--authorized-scope or --allow-disruptive is missing.
"""

import sys
from argparse import Namespace

import pytest

from der_common.scope import ScopeError


def test_dnp3_fuzz_refuses_without_scope_or_consent():
    sys.modules.pop("der_dnp3.fuzzer", None)
    from der_dnp3.cli import _cmd_fuzz

    args = Namespace(host="127.0.0.1", authorized_scope=None, allow_disruptive=False)
    with pytest.raises(ScopeError):
        _cmd_fuzz(args)
    assert "der_dnp3.fuzzer" not in sys.modules, (
        "the boofuzz-based fuzzer must never be imported before the scope gate passes"
    )


def test_dnp3_fuzz_refuses_with_scope_but_no_consent():
    sys.modules.pop("der_dnp3.fuzzer", None)
    from der_dnp3.cli import _cmd_fuzz

    args = Namespace(host="127.0.0.1", authorized_scope=["127.0.0.1/32"], allow_disruptive=False)
    with pytest.raises(ScopeError):
        _cmd_fuzz(args)
    assert "der_dnp3.fuzzer" not in sys.modules


def test_sunspec_fuzz_refuses_without_scope_or_consent():
    sys.modules.pop("der_sunspec.fuzzer", None)
    from der_sunspec.cli import _cmd_fuzz

    args = Namespace(host="127.0.0.1", authorized_scope=None, allow_disruptive=False)
    with pytest.raises(ScopeError):
        _cmd_fuzz(args)
    assert "der_sunspec.fuzzer" not in sys.modules


def test_sunspec_fuzz_refuses_with_scope_but_no_consent():
    sys.modules.pop("der_sunspec.fuzzer", None)
    from der_sunspec.cli import _cmd_fuzz

    args = Namespace(host="127.0.0.1", authorized_scope=["127.0.0.1/32"], allow_disruptive=False)
    with pytest.raises(ScopeError):
        _cmd_fuzz(args)
    assert "der_sunspec.fuzzer" not in sys.modules


def test_sep2_fuzz_refuses_without_scope_or_consent(monkeypatch):
    from der_sep2 import cli as sep2_cli

    def _boom(*a, **kw):
        raise AssertionError("TLSContextFactory must never be constructed before the scope gate passes")

    monkeypatch.setattr(sep2_cli, "TLSContextFactory", _boom)
    args = Namespace(host="127.0.0.1", port=8443, allow_disruptive=False, authorized_scope=None)
    with pytest.raises(ScopeError):
        sep2_cli.cmd_fuzz(args)


def test_sep2_fuzz_refuses_with_scope_but_no_consent(monkeypatch):
    from der_sep2 import cli as sep2_cli

    def _boom(*a, **kw):
        raise AssertionError("TLSContextFactory must never be constructed before the scope gate passes")

    monkeypatch.setattr(sep2_cli, "TLSContextFactory", _boom)
    args = Namespace(host="127.0.0.1", port=8443, allow_disruptive=False,
                      authorized_scope=["127.0.0.1/32"])
    with pytest.raises(ScopeError):
        sep2_cli.cmd_fuzz(args)
