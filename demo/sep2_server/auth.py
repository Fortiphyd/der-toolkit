"""
auth.py
───────
LFDI computation, client-cert extraction, and per-resource policy enforcement.

Policy table mirrors IEEE 2030.5 Table 12 (Function Set Access Requirements):
  ┌──────────────────────┬──────────────┬───────────────┐
  │ Resource             │ Cert needed? │ Reg needed?   │
  ├──────────────────────┼──────────────┼───────────────┤
  │ /dcap /tm /msg /ps   │ No           │ No            │
  │ /edev  GET           │ No           │ No            │
  │ /edev  POST          │ Yes          │ No            │
  │ /edev/{id}           │ Yes          │ No            │
  │ /edev/{id}/reg       │ Yes          │ No            │
  │ /edev/{id}/fsa       │ Yes          │ No            │
  │ /edev/{id}/der       │ Yes          │ Yes           │
  │ /edev/{id}/derc      │ Yes          │ Yes           │
  │ /edev/{id}/dercr     │ Yes          │ Yes           │
  │ /edev/{id}/log       │ Yes          │ Yes           │
  │ /upt  /upt/{id}/*    │ Yes          │ Yes           │
  │ /bill                │ Yes          │ Yes           │
  │ /sdev                │ Yes          │ No            │
  └──────────────────────┴──────────────┴───────────────┘
"""

import hashlib
import logging
import re
from functools import wraps
from typing import Optional

from flask import request, current_app, g
from xml_responses import error_response

log = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# LFDI helpers
# ──────────────────────────────────────────────────────────────────────────────

def compute_lfdi(der_bytes: bytes) -> str:
    """Return the LFDI: first 40 hex chars (upper-case) of SHA-256(DER cert)."""
    return hashlib.sha256(der_bytes).hexdigest()[:40].upper()


def extract_lfdi_from_request() -> Optional[str]:
    """
    Pull the DER bytes injected by ssl_server.py and return the LFDI string,
    or None if no client cert was presented.
    """
    der = request.environ.get("SSL_CLIENT_CERT_DER")
    if not der:
        return None
    return compute_lfdi(der)


# ──────────────────────────────────────────────────────────────────────────────
# Policy table
# Each entry: (url_regex, methods_needing_cert, registration_required)
# Patterns are tested in order; first match wins.
# ──────────────────────────────────────────────────────────────────────────────

_POLICY: list[tuple[re.Pattern, set, bool]] = [
    # Open resources – no cert, no registration
    (re.compile(r"^/dcap$"),           set(),            False),
    (re.compile(r"^/tm$"),             set(),            False),
    (re.compile(r"^/msg(/.*)?$"),      set(),            False),
    (re.compile(r"^/ps(/.*)?$"),       set(),            False),

    # /edev list – GET open, POST needs cert
    (re.compile(r"^/edev$"),           {"POST"},         False),

    # Device sub-resources that need cert + registration
    (re.compile(r"^/edev/[^/]+/der(/.*)?$"),  {"GET","POST","PUT","DELETE"}, True),
    (re.compile(r"^/edev/[^/]+/derc(/.*)?$"), {"GET","POST","PUT","DELETE"}, True),
    (re.compile(r"^/edev/[^/]+/dercr(/.*)?$"),{"GET","POST","PUT","DELETE"}, True),
    (re.compile(r"^/edev/[^/]+/log(/.*)?$"),  {"GET"},                       True),

    # Device sub-resources that need cert but NOT registration
    (re.compile(r"^/edev/[^/]+(/.*)?$"), {"GET","POST","PUT","DELETE"}, False),

    # Usage points – cert + registration
    (re.compile(r"^/upt(/.*)?$"),      {"GET","POST","PUT","DELETE"}, True),

    # Billing – cert + registration
    (re.compile(r"^/bill(/.*)?$"),     {"GET"},          True),

    # Self device – cert, no registration required
    (re.compile(r"^/sdev(/.*)?$"),     {"GET"},          False),
]

# "ALL methods" sentinel – if every method needs a cert
_ALL_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}


def _policy_for_path(path: str):
    """
    Returns (cert_required: bool, registration_required: bool) for a path+method.
    Falls back to (True, True) for unknown paths.
    """
    method = request.method.upper()
    for pattern, cert_methods, reg_required in _POLICY:
        if pattern.match(path):
            cert_required = (method in cert_methods) or (cert_methods == _ALL_METHODS)
            return cert_required, reg_required
    # Unknown path – default deny
    return True, True


def _is_open_override(path: str) -> bool:
    """Return True if this path has been forced open via the vulnerability config."""
    open_resources = current_app.config["SEP2_CFG"].get("vulnerability", {}).get("open_resources", [])
    for pattern_str in open_resources:
        # Convert {id} wildcards to a simple regex fragment
        regex = re.compile("^" + re.sub(r"\{[^}]+\}", r"[^/]+", pattern_str) + r"(/.*)?$")
        if regex.match(path):
            return True
    return False


# ──────────────────────────────────────────────────────────────────────────────
# Main enforcement decorator
# ──────────────────────────────────────────────────────────────────────────────

def enforce_policy(f):
    """
    Decorator that applies the SEP 2.0 Table-12 access policy to a route.

    Populates flask.g with:
      g.lfdi          – LFDI string or None
      g.cert_present  – bool
      g.registered    – bool
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        cfg = current_app.config["SEP2_CFG"]
        path = request.path

        # ── 1. Extract client cert / LFDI ────────────────────────────────────
        g.lfdi = extract_lfdi_from_request()
        g.cert_present = g.lfdi is not None

        if g.cert_present:
            log.debug("Request from LFDI %s  %s %s", g.lfdi, request.method, path)
        else:
            log.debug("Request (no cert)  %s %s", request.method, path)

        # ── 2. Check vulnerability overrides ─────────────────────────────────
        if _is_open_override(path):
            log.warning("OPEN OVERRIDE active for %s – skipping policy", path)
            g.registered = _check_registration(cfg, g.lfdi)
            return f(*args, **kwargs)

        # ── 3. Determine policy for this path/method ─────────────────────────
        cert_required, reg_required = _policy_for_path(path)

        # ── 4. Cert check ─────────────────────────────────────────────────────
        # enforce_mtls lives here (application layer), NOT in the TLS context.
        # The TLS layer always uses CERT_OPTIONAL so that open resources
        # (/dcap, /tm, /msg, /ps) remain reachable without a client cert.
        # Setting enforce_mtls=false simulates a misconfigured server that
        # lets Probe A through to cert-required routes.
        enforce_mtls = cfg.get("tls", {}).get("enforce_mtls", True)
        if cert_required and not g.cert_present:
            if enforce_mtls:
                log.info("POLICY DENY (no cert) %s %s", request.method, path)
                return error_response(
                    "Unauthorized",
                    "Client certificate required for this resource.",
                    status=401,
                )
            else:
                log.warning(
                    "POLICY BYPASS enforce_mtls=false — no cert on cert-required route %s %s",
                    request.method, path,
                )

        # ── 5. Registration check ─────────────────────────────────────────────
        g.registered = _check_registration(cfg, g.lfdi)

        enforce_reg = cfg.get("acl", {}).get("enforce_registration", True)
        if reg_required and enforce_reg and g.cert_present and not g.registered:
            log.info("POLICY DENY (not registered) LFDI=%s %s %s", g.lfdi, request.method, path)
            return error_response(
                "NotFound",
                f"No device found for LFDI {g.lfdi}",
                status=404,
            )

        return f(*args, **kwargs)

    return wrapper


def _check_registration(cfg: dict, lfdi: Optional[str]) -> bool:
    if not lfdi:
        return False
    registered = cfg.get("acl", {}).get("registered_lfdis", [])
    return lfdi.upper() in [x.upper() for x in registered]
