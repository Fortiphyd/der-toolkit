"""
der_sep2.mapping.resource_tree
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Two things live here:

1. POLICY_TABLE  — IEEE 2030.5 Table 12 encoded as structured data.
   Maps each function set / resource pattern to its default security
   policy: aclDefaultAccess bitmask, cert requirement, registration
   requirement.  Used by the finding generator to decide whether
   unauthenticated access to a resource is a bug or expected behaviour.

2. RESOURCE_WORDLIST — the spec-defined resource path templates, used
   as a brute-force list alongside the recursive href-follower.
   Templates use {id} as a placeholder for discovered numeric/string IDs.

Reference: IEEE 2030.5-2018, Table 12 and Section 6 (Resource Model)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from der_sep2.models import ACLAccess


# ---------------------------------------------------------------------------
# Policy table entry
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ResourcePolicy:
    """
    Default security policy for one function set / resource, per Table 12.

    acl_default_access: bitmask — which HTTP methods are open by default
    cert_required:      whether a client certificate is required
    reg_required:       whether the device must be registered in the server ACL
    auth_type:          "No" | "Optional" | "Required"
    function_set:       human-readable label
    notes:              any spec clarifications worth surfacing in findings
    """
    function_set:        str
    acl_default_access:  ACLAccess
    cert_required:       bool
    reg_required:        bool
    auth_type:           str   = "No"
    notes:               str   = ""


# ---------------------------------------------------------------------------
# Table 12 — Default security policy per function set
#
# Key  = the "canonical" path prefix that identifies this function set.
#        For parameterised paths (e.g. /edev/{id}) we store the prefix
#        (/edev) so matching works on startswith().
#
# The table is ordered from least-privileged (open) to most-privileged
# so that prefix matching picks the most-specific rule when two prefixes
# overlap (handled by the lookup function below).
# ---------------------------------------------------------------------------

POLICY_TABLE: dict[str, ResourcePolicy] = {

    # ── Universally open (no cert, no registration) ──────────────────────

    "/dcap": ResourcePolicy(
        function_set       = "Device Capability",
        acl_default_access = ACLAccess.FULL,   # 0xf — intentionally open
        cert_required      = False,
        reg_required       = False,
        auth_type          = "No",
        notes              = (
            "Bootstrap resource. Full access is intentional so new devices "
            "can discover server capabilities before registering."
        ),
    ),

    "/tm": ResourcePolicy(
        function_set       = "Time",
        acl_default_access = ACLAccess.GET,    # 0x8 — read-only
        cert_required      = False,
        reg_required       = False,
        auth_type          = "No",
        notes              = "Read-only time sync. Writes without auth = finding.",
    ),

    "/edev": ResourcePolicy(
        function_set       = "End Device (list)",
        acl_default_access = ACLAccess.GET,
        cert_required      = False,
        reg_required       = False,
        auth_type          = "No",
        notes              = (
            "The list itself is open so new devices can POST to register. "
            "Individual /edev/{id} resources require a cert."
        ),
    ),

    "/sdev": ResourcePolicy(
        function_set       = "Self Device",
        acl_default_access = ACLAccess.FULL,
        cert_required      = True,
        reg_required       = False,
        auth_type          = "No",
        notes              = "Own device record. Cert required, registration not.",
    ),

    "/msg": ResourcePolicy(
        function_set       = "Messaging",
        acl_default_access = ACLAccess.GET,
        cert_required      = False,
        reg_required       = False,
        auth_type          = "No",
        notes              = "Public broadcast messages. Writes without auth = finding.",
    ),

    "/ps": ResourcePolicy(
        function_set       = "Pricing",
        acl_default_access = ACLAccess.GET,
        cert_required      = False,
        reg_required       = False,
        auth_type          = "No",
        notes              = "Retail pricing — intentionally public.",
    ),

    # ── Cert required, registration not ──────────────────────────────────

    "/rsps": ResourcePolicy(
        function_set       = "Response Set",
        acl_default_access = ACLAccess.FULL,
        cert_required      = True,
        reg_required       = False,
        auth_type          = "No",
    ),

    # ── Cert + registration required ─────────────────────────────────────

    "/upt": ResourcePolicy(
        function_set       = "Usage Point / Metering",
        acl_default_access = ACLAccess.GET,
        cert_required      = True,
        reg_required       = True,
        auth_type          = "No",
        notes              = "Meter readings — sensitive consumption data.",
    ),

    "/bill": ResourcePolicy(
        function_set       = "Billing",
        acl_default_access = ACLAccess.GET,
        cert_required      = True,
        reg_required       = True,
        auth_type          = "No",
        notes              = "Billing data — sensitive financial data.",
    ),

    "/dr": ResourcePolicy(
        function_set       = "Demand Response",
        acl_default_access = ACLAccess.GET,
        cert_required      = True,
        reg_required       = True,
        auth_type          = "No",
        notes              = "DR programs. Control resources under /dr/{id}/drc are FULL.",
    ),

    "/ppy": ResourcePolicy(
        function_set       = "Prepayment",
        acl_default_access = ACLAccess.FULL,
        cert_required      = True,
        reg_required       = True,
        auth_type          = "No",
    ),

    "/csf": ResourcePolicy(
        function_set       = "Customer Account",
        acl_default_access = ACLAccess.GET,
        cert_required      = True,
        reg_required       = True,
        auth_type          = "No",
        notes              = "Account info — PII risk.",
    ),

    # ── DER — highest sensitivity (physical control) ──────────────────────

    "/edev/{id}/der": ResourcePolicy(
        function_set       = "DER (Distributed Energy Resource)",
        acl_default_access = ACLAccess.FULL,
        cert_required      = True,
        reg_required       = True,
        auth_type          = "No",
        notes              = (
            "DER controls affect physical grid assets (solar inverters, batteries). "
            "Unauthenticated write access here is a critical safety finding."
        ),
    ),

    "/edev/{id}/derp": ResourcePolicy(
        function_set       = "DER Program",
        acl_default_access = ACLAccess.FULL,
        cert_required      = True,
        reg_required       = True,
        auth_type          = "No",
    ),

    "/edev/{id}/derc": ResourcePolicy(
        function_set       = "DER Control",
        acl_default_access = ACLAccess.FULL,
        cert_required      = True,
        reg_required       = True,
        auth_type          = "No",
        notes              = "Active DER control — safety-critical.",
    ),

    "/edev/{id}/dera": ResourcePolicy(
        function_set       = "DER Availability",
        acl_default_access = ACLAccess.FULL,
        cert_required      = True,
        reg_required       = True,
        auth_type          = "No",
    ),

    "/edev/{id}/derg": ResourcePolicy(
        function_set       = "DER Settings",
        acl_default_access = ACLAccess.FULL,
        cert_required      = True,
        reg_required       = True,
        auth_type          = "No",
        notes              = "Persistent DER configuration — changes survive reboots.",
    ),

    "/edev/{id}/dercap": ResourcePolicy(
        function_set       = "DER Capability",
        acl_default_access = ACLAccess.GET,
        cert_required      = True,
        reg_required       = True,
        auth_type          = "No",
    ),

    # ── End device sub-resources ──────────────────────────────────────────

    "/edev/{id}": ResourcePolicy(
        function_set       = "End Device (individual)",
        acl_default_access = ACLAccess.FULL,
        cert_required      = True,
        reg_required       = False,
        auth_type          = "No",
        notes              = "Own device record is accessible with cert but before registration.",
    ),

    "/edev/{id}/reg": ResourcePolicy(
        function_set       = "Registration",
        acl_default_access = ACLAccess.FULL,
        cert_required      = True,
        reg_required       = False,
        auth_type          = "No",
        notes              = "Registration endpoint — cert required so server can record LFDI.",
    ),

    "/edev/{id}/fsa": ResourcePolicy(
        function_set       = "Function Set Assignments",
        acl_default_access = ACLAccess.GET,
        cert_required      = True,
        reg_required       = True,
        auth_type          = "No",
    ),

    "/edev/{id}/log": ResourcePolicy(
        function_set       = "Log Event List",
        acl_default_access = ACLAccess.FULL,
        cert_required      = True,
        reg_required       = True,
        auth_type          = "No",
    ),

    "/edev/{id}/sub": ResourcePolicy(
        function_set       = "Subscription",
        acl_default_access = ACLAccess.FULL,
        cert_required      = True,
        reg_required       = True,
        auth_type          = "No",
    ),
}


def lookup_policy(path: str) -> Optional[ResourcePolicy]:
    """
    Find the most-specific policy for a given path.

    Matching strategy:
      1. Normalise the path by replacing numeric/short segments with {id}
         so /edev/3/der matches the /edev/{id}/der policy.
      2. Walk from most-specific (longest key) to least-specific.
      3. Return the first policy whose (normalised) key is a prefix of
         the normalised path.
    """
    normalised = _normalise_path(path)

    # Sort by key length descending — most specific first
    for key in sorted(POLICY_TABLE.keys(), key=len, reverse=True):
        norm_key = _normalise_path(key)
        if normalised == norm_key or normalised.startswith(norm_key + "/"):
            return POLICY_TABLE[key]
    return None


def _normalise_path(path: str) -> str:
    """
    Replace path segments that look like IDs (short alphanumeric strings,
    integers) with the literal token {id}.

    Examples:
      /edev/3/der     → /edev/{id}/der
      /edev/3         → /edev/{id}
      /upt/abc123/mr  → /upt/{id}/mr
      /dcap           → /dcap   (no change — known name, not an ID)
    """
    # Known non-ID segment names — never replace these
    KNOWN_SEGMENTS = {
        "dcap", "tm", "edev", "sdev", "upt", "mr", "rs", "rg", "rp",
        "msg", "ps", "dr", "ppy", "csf", "bill", "rsps", "ntfy",
        "der", "derp", "derc", "dera", "derg", "dercap",
        "reg", "fsa", "log", "sub", "cfg", "di",
    }

    parts = path.strip("/").split("/")
    result = []
    for part in parts:
        if part in KNOWN_SEGMENTS:
            result.append(part)
        elif part == "{id}":
            result.append("{id}")
        elif _looks_like_id(part):
            result.append("{id}")
        else:
            result.append(part)

    return "/" + "/".join(result) if result else "/"


def _looks_like_id(segment: str) -> bool:
    """
    Heuristic: is this path segment an ID rather than a resource name?
    IDs are typically:
      - Pure integers:            "3", "42", "10001"
      - Short alphanumeric:       "abc", "a3f2"  (not in KNOWN_SEGMENTS)
      - Long hex / UUID strings:  "deadbeef", "550e8400-e29b-41d4-a716..."
    The caller already checked KNOWN_SEGMENTS before calling us, so any
    short alphanumeric segment that reaches here is not a known resource
    name and is therefore treated as an ID.
    """
    if not segment:
        return False
    if segment.isdigit():
        return True
    # UUID / long hex
    if len(segment) >= 8 and all(c in "0123456789abcdefABCDEF-" for c in segment):
        return True
    # Any remaining short alphanumeric (not caught by KNOWN_SEGMENTS above)
    if segment.isalnum():
        return True
    return False


# ---------------------------------------------------------------------------
# Spec-defined resource wordlist
#
# These are path TEMPLATES — {id} is substituted with IDs discovered
# during href-following before brute-forcing.
#
# Grouped by function set for readability.
# ---------------------------------------------------------------------------

RESOURCE_WORDLIST: list[str] = [

    # ── Always try first ──────────────────────────────────────────────────
    "/dcap",
    "/tm",

    # ── End device ────────────────────────────────────────────────────────
    "/edev",
    "/edev/{id}",
    "/edev/{id}/reg",
    "/edev/{id}/fsa",
    "/edev/{id}/fsa/{id}",
    "/edev/{id}/log",
    "/edev/{id}/sub",
    "/edev/{id}/sub/{id}",

    # ── Self device ───────────────────────────────────────────────────────
    "/sdev",
    "/sdev/reg",
    "/sdev/fsa",
    "/sdev/fsa/{id}",
    "/sdev/log",

    # ── Device information ─────────────────────────────────────────────────
    "/di",
    "/sdev/di",

    # ── DER ───────────────────────────────────────────────────────────────
    "/edev/{id}/der",
    "/edev/{id}/der/{id}",
    "/edev/{id}/der/{id}/dercap",
    "/edev/{id}/der/{id}/dera",
    "/edev/{id}/der/{id}/derg",
    "/edev/{id}/derp",
    "/edev/{id}/derp/{id}",
    "/edev/{id}/derp/{id}/derc",
    "/edev/{id}/derp/{id}/derc/{id}",
    "/edev/{id}/derc",
    "/edev/{id}/derc/{id}",
    "/edev/{id}/dera",
    "/edev/{id}/derg",
    "/edev/{id}/dercap",

    # ── Demand Response ───────────────────────────────────────────────────
    "/dr",
    "/dr/{id}",
    "/dr/{id}/drlc",
    "/dr/{id}/drlc/{id}",

    # ── Messaging ─────────────────────────────────────────────────────────
    "/msg",
    "/msg/{id}",

    # ── Pricing ───────────────────────────────────────────────────────────
    "/ps",
    "/ps/{id}",
    "/ps/{id}/rtp",
    "/ps/{id}/rtp/{id}",
    "/ps/{id}/cpp",
    "/ps/{id}/cpp/{id}",

    # ── Metering / Usage Points ───────────────────────────────────────────
    "/upt",
    "/upt/{id}",
    "/upt/{id}/mr",
    "/upt/{id}/mr/{id}",
    "/upt/{id}/mr/{id}/rs",
    "/upt/{id}/mr/{id}/rs/{id}",
    "/upt/{id}/mr/{id}/rs/{id}/r",
    "/upt/{id}/mr/{id}/rg",
    "/upt/{id}/mr/{id}/rg/{id}",
    "/upt/{id}/mr/{id}/rp",

    # ── Billing ───────────────────────────────────────────────────────────
    "/bill",
    "/bill/{id}",
    "/bill/{id}/bs",
    "/bill/{id}/bs/{id}",

    # ── Customer account ─────────────────────────────────────────────────
    "/csf",
    "/csf/{id}",
    "/csf/{id}/ca",
    "/csf/{id}/ca/{id}",

    # ── Prepayment ────────────────────────────────────────────────────────
    "/ppy",
    "/ppy/{id}",
    "/ppy/{id}/csl",
    "/ppy/{id}/csl/{id}",

    # ── Response sets ─────────────────────────────────────────────────────
    "/rsps",
    "/rsps/{id}",
    "/rsps/{id}/rsp",
    "/rsps/{id}/rsp/{id}",

    # ── Subscriptions / notifications ─────────────────────────────────────
    "/ntfy",
    "/ntfy/{id}",

    # ── Configuration (vendor-common extras) ──────────────────────────────
    "/cfg",
    "/log",
]


def expand_wordlist(discovered_ids: dict[str, list[str]]) -> list[str]:
    """
    Expand the wordlist templates by substituting discovered IDs.

    discovered_ids: maps a path prefix to a list of IDs found under it.
      e.g. {"/edev": ["3", "7", "12"], "/upt": ["1"]}

    Returns a flat list of concrete paths ready to probe, deduplicated.

    For paths with multiple {id} placeholders we substitute all combinations
    of IDs found at each level.  A path like /edev/{id}/der/{id} becomes
    /edev/3/der/1, /edev/3/der/2, /edev/7/der/1, etc.
    """
    import itertools

    concrete: set[str] = set()

    for template in RESOURCE_WORDLIST:
        placeholders = template.count("{id}")

        if placeholders == 0:
            concrete.add(template)
            continue

        # Find which prefixes are relevant for each placeholder level
        # by walking the template left-to-right
        segments   = template.split("{id}")
        id_options = _ids_for_template(template, discovered_ids)

        if not id_options:
            # No IDs discovered yet — still include the template with a
            # synthetic "0" so the wordlist brute-forcer has something to try
            synthetic = template.replace("{id}", "0", 1)
            concrete.add(synthetic)
            continue

        for combo in itertools.product(*id_options):
            path = template
            for id_val in combo:
                path = path.replace("{id}", id_val, 1)
            concrete.add(path)

    return sorted(concrete)


def _ids_for_template(
    template: str, discovered_ids: dict[str, list[str]]
) -> list[list[str]]:
    """
    For each {id} placeholder in template, find the relevant discovered IDs.

    Strategy: the prefix before each {id} is the parent resource path.
    We look up that prefix in discovered_ids.  If nothing is found,
    we use ["0"] as a synthetic fallback.
    """
    result: list[list[str]] = []
    remaining = template

    while "{id}" in remaining:
        prefix = remaining.split("{id}")[0].rstrip("/")
        # Find the best matching prefix in discovered_ids
        ids = discovered_ids.get(prefix) or ["0"]
        result.append(ids)
        # Advance past this placeholder
        remaining = remaining[remaining.index("{id}") + 4:]

    return result
