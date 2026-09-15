"""
der_sep2.fuzzing.http_fuzzer
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Targeted HTTP fuzzing for IEEE 2030.5 — focused on the two
highest-yield attack classes for this protocol:

  1. IDOR (Insecure Direct Object Reference)
     The spec requires servers to check that a client can only access
     resources belonging to their own registered device. Many
     implementations only check "does this client have a valid cert"
     rather than "does this cert belong to the device at this path".

     We enumerate adjacent IDs around each discovered resource ID and
     compare the responses to what we get for our own resource. A 200
     on someone else's /edev/{id}/der is a critical finding.

  2. Pagination parameter abuse
     2030.5 uses s= (start index) and l= (limit) on all list resources.
     This logic is always hand-rolled and rarely tested. We try:
       - Negative values          s=-1, l=-1
       - Zero limit               l=0
       - Enormous values          s=2147483647, l=999999
       - Type confusion           s=abc, l=1.5
       - Both at once             s=-1&l=-1

  3. HTTP method confusion on individual resources
     Separate from the mapper's method probing — here we specifically
     test whether a registered device can DELETE or PUT to another
     device's resources (method + IDOR combined).
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field

from der_sep2.mapping.resource_mapper import MappingResult, Sep2HTTPClient
from der_sep2.mapping.resource_tree import _normalise_path, lookup_policy
from der_sep2.models import Finding, ProbeType, ServiceTarget, Severity
from der_sep2.tls.client import TLSContextFactory

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# IDOR probe configuration
# ---------------------------------------------------------------------------

# How many adjacent IDs to probe around each discovered ID
# e.g. discovered /edev/7  →  probe /edev/1 through /edev/14 (skip 7)
IDOR_PROBE_RANGE = 10

# Resource path patterns that are IDOR-sensitive — we only probe these
# because /dcap, /tm etc. are shared resources with no per-device ownership
IDOR_SENSITIVE_PATTERNS = {
    "/edev/{id}",
    "/edev/{id}/reg",
    "/edev/{id}/fsa",
    "/edev/{id}/der",
    "/edev/{id}/der/{id}",
    "/edev/{id}/derc",
    "/edev/{id}/derp",
    "/edev/{id}/dera",
    "/edev/{id}/derg",
    "/edev/{id}/dercap",
    "/edev/{id}/log",
    "/edev/{id}/sub",
    "/upt/{id}",
    "/upt/{id}/mr",
    "/upt/{id}/mr/{id}",
    "/bill/{id}",
    "/csf/{id}",
    "/ppy/{id}",
}

# Pagination test cases: (s_value, l_value, description)
# None means "omit that parameter"
PAGINATION_CASES: list[tuple[str | None, str | None, str]] = [
    ("-1",          None,          "negative start index"),
    (None,          "-1",          "negative limit"),
    ("0",           "0",           "zero start and limit"),
    (None,          "0",           "zero limit"),
    ("2147483647",  None,          "max int32 start index"),
    ("-2147483648", None,          "min int32 start index"),
    (None,          "999999",      "enormous limit"),
    ("abc",         None,          "non-numeric start index"),
    (None,          "1.5",         "float limit"),
    ("1",           "abc",         "non-numeric limit"),
    ("-1",          "-1",          "both negative"),
    ("0",           "2147483647",  "zero start, max limit"),
    ("' OR 1=1--",  None,          "SQL injection in start param"),
    (None,          "' OR 1=1--",  "SQL injection in limit param"),
    ("1",           "1",           "baseline — valid pagination (control)"),
]

# HTTP methods to test for IDOR cross-device writes
IDOR_WRITE_METHODS = ["PUT", "DELETE", "POST"]


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class IDORResult:
    """Result of probing one resource ID we don't own."""
    target:       ServiceTarget
    our_path:     str           # the path we legitimately own
    probe_path:   str           # the path we're probing (different device)
    method:       str
    status_code:  int | None  = None
    our_status:   int | None  = None   # what we get for our own resource
    response_body: bytes | None = None
    elapsed_ms:   float          = 0.0
    error:        str | None  = None

    @property
    def is_idor(self) -> bool:
        """
        True if we got a successful response to someone else's resource.
        We compare to our own resource response to avoid flagging paths
        that return 200 to everyone (public resources).
        """
        return (
            self.status_code is not None
            and 200 <= self.status_code < 300
            and self.our_status is not None
            and 200 <= self.our_status < 300
            and self.probe_path != self.our_path
        )


@dataclass
class PaginationResult:
    """Result of one pagination parameter fuzz case."""
    target:       ServiceTarget
    path:         str
    s_value:      str | None
    l_value:      str | None
    description:  str
    status_code:  int | None  = None
    response_body: bytes | None = None
    elapsed_ms:   float           = 0.0
    baseline_ms:  float           = 0.0
    error:        str | None   = None

    @property
    def query_string(self) -> str:
        parts = []
        if self.s_value is not None:
            parts.append(f"s={self.s_value}")
        if self.l_value is not None:
            parts.append(f"l={self.l_value}")
        return "&".join(parts)

    @property
    def server_error(self) -> bool:
        return self.status_code is not None and self.status_code >= 500

    @property
    def slow_response(self) -> bool:
        if self.baseline_ms <= 0:
            return False
        return self.elapsed_ms > max(self.baseline_ms * 5, 3000)

    @property
    def body_text(self) -> str:
        if self.response_body:
            return self.response_body.decode("utf-8", errors="replace")
        return ""


@dataclass
class HTTPFuzzingResult:
    target:             ServiceTarget
    idor_results:       list[IDORResult]       = field(default_factory=list)
    pagination_results: list[PaginationResult] = field(default_factory=list)
    findings:           list[Finding]          = field(default_factory=list)


# ---------------------------------------------------------------------------
# Core HTTP fuzzer
# ---------------------------------------------------------------------------

class HTTPFuzzer:
    """
    Targeted HTTP fuzzer for IEEE 2030.5.
    Focuses on IDOR and pagination parameter abuse.
    """

    def __init__(
        self,
        target:          ServiceTarget,
        context_factory: TLSContextFactory,
        mapping_result:  MappingResult | None = None,
        rate_limit_rps:  float = 3.0,
        timeout:         float = 10.0,
        idor_range:      int   = IDOR_PROBE_RANGE,
    ):
        self.target          = target
        self.factory         = context_factory
        self.mapping_result  = mapping_result
        self.rate_limit_rps  = rate_limit_rps
        self.timeout         = timeout
        self.idor_range      = idor_range

        self._min_interval = 1.0 / rate_limit_rps
        self._last_request = 0.0
        self._result       = HTTPFuzzingResult(target=target)

        # Registered cert context for IDOR — we need to be authenticated
        # to reach the resources we're testing
        try:
            self._ctx = context_factory.valid_cert_context()
        except ValueError:
            log.warning(
                "[HTTPFuzzer] No registered client cert — "
                "IDOR probes will use no-cert context and may not reach resources."
            )
            self._ctx = context_factory.no_cert_context()

    def run(self) -> HTTPFuzzingResult:
        log.info(
            f"[HTTPFuzzer] Starting HTTP fuzzing of "
            f"{self.target.ip}:{self.target.port}"
        )

        self._run_idor_probes()
        self._run_pagination_probes()

        log.info(
            f"[HTTPFuzzer] Complete — "
            f"{len(self._result.idor_results)} IDOR probes, "
            f"{len(self._result.pagination_results)} pagination probes, "
            f"{len(self._result.findings)} findings."
        )
        return self._result

    # ------------------------------------------------------------------
    # IDOR
    # ------------------------------------------------------------------

    def _run_idor_probes(self) -> None:
        """
        For each discovered resource ID, probe adjacent IDs and
        compare the responses. A 200 on an adjacent ID is an IDOR.
        """
        if not self.mapping_result:
            log.info("[HTTPFuzzer] No mapping result — running IDOR against static paths")
            self._idor_static_fallback()
            return

        # Find all paths that:
        #   a) We got a 200 on with Probe D (registered cert)
        #   b) Match an IDOR-sensitive pattern
        #   c) Contain at least one numeric ID segment we can enumerate
        probed_patterns: set[str] = set()

        for path, node in self.mapping_result.nodes.items():
            reg_result = node.probe_results.get(ProbeType.VALID_REG)
            if not reg_result or reg_result.status_code != 200:
                continue

            norm = _normalise_path(path)
            if norm not in IDOR_SENSITIVE_PATTERNS:
                continue

            # Extract the numeric ID from this path
            our_id, id_pos = _extract_first_numeric_id(path)
            if our_id is None:
                continue

            # Only probe each (pattern, id_position) once to avoid
            # redundant probes on the same resource family
            probe_key = (norm, id_pos)
            if probe_key in probed_patterns:
                continue
            probed_patterns.add(probe_key)

            log.info(
                f"[HTTPFuzzer] IDOR probing around {path} "
                f"(our_id={our_id}, range=±{self.idor_range})"
            )
            self._probe_idor_range(path, our_id, id_pos, reg_result.status_code)

    def _probe_idor_range(
        self,
        our_path:   str,
        our_id:     int,
        id_pos:     int,      # which slash-separated segment is the ID
        our_status: int,
    ) -> None:
        """Probe IDs adjacent to our_id in the same resource path."""
        segments = our_path.strip("/").split("/")

        for delta in range(1, self.idor_range + 1):
            for candidate_id in [our_id - delta, our_id + delta]:
                if candidate_id < 0:
                    continue

                # Build the probe path by substituting the candidate ID
                probe_segments = segments.copy()
                probe_segments[id_pos] = str(candidate_id)
                probe_path = "/" + "/".join(probe_segments)

                self._rate_limit()
                result = self._single_get(probe_path)

                idor_result = IDORResult(
                    target        = self.target,
                    our_path      = our_path,
                    probe_path    = probe_path,
                    method        = "GET",
                    status_code   = result.get("status"),
                    our_status    = our_status,
                    response_body = result.get("body"),
                    elapsed_ms    = result.get("elapsed_ms", 0),
                    error         = result.get("error"),
                )
                self._result.idor_results.append(idor_result)

                if idor_result.is_idor:
                    policy = lookup_policy(probe_path)
                    fs     = policy.function_set if policy else "unknown"
                    sev    = _idor_severity(probe_path)
                    self._finding(
                        sev   = sev,
                        title = f"IDOR: accessed another device's resource: {probe_path}",
                        desc  = (
                            f"GET {probe_path} returned HTTP {idor_result.status_code} "
                            f"using credentials registered for {our_path}. "
                            f"The server is not checking that the requesting device "
                            f"owns the resource at this path. "
                            f"Function set: {fs}."
                        ),
                        path     = probe_path,
                        evidence = {
                            "our_path":    our_path,
                            "probe_path":  probe_path,
                            "our_id":      our_id,
                            "probed_id":   candidate_id,
                            "status_code": idor_result.status_code,
                            "our_status":  our_status,
                        },
                    )
                    log.warning(
                        f"[HTTPFuzzer] *** IDOR *** "
                        f"{probe_path} → {idor_result.status_code} "
                        f"(our resource: {our_path})"
                    )

                # Also try write methods on accessible foreign resources
                if idor_result.status_code == 200:
                    self._probe_idor_writes(probe_path, our_path)

    def _probe_idor_writes(self, probe_path: str, our_path: str) -> None:
        """
        If we can GET another device's resource, try writing to it too.
        A writable IDOR is more severe than a read-only one.
        """
        for method in IDOR_WRITE_METHODS:
            self._rate_limit()
            result = self._single_request(
                method  = method,
                path    = probe_path,
                body    = b"<EndDevice/>",   # minimal body
                headers = {"Content-Type": "application/sep+xml"},
            )
            status = result.get("status")
            if status and 200 <= status < 300:
                sev = Severity.CRITICAL
                self._finding(
                    sev   = sev,
                    title = f"IDOR write: {method} to another device's resource: {probe_path}",
                    desc  = (
                        f"{method} {probe_path} returned HTTP {status} "
                        f"using credentials for {our_path}. "
                        f"Cross-device write access — can modify or delete "
                        f"another device's configuration."
                    ),
                    path     = probe_path,
                    evidence = {
                        "method":      method,
                        "probe_path":  probe_path,
                        "our_path":    our_path,
                        "status_code": status,
                    },
                )

    def _idor_static_fallback(self) -> None:
        """
        When no mapping result is available, probe a few well-known
        paths with a range of small integer IDs.
        """
        static_paths = ["/edev", "/upt", "/bill"]
        for base in static_paths:
            for id_ in range(1, self.idor_range + 1):
                path = f"{base}/{id_}"
                self._rate_limit()
                result = self._single_get(path)
                idor_result = IDORResult(
                    target        = self.target,
                    our_path      = base,
                    probe_path    = path,
                    method        = "GET",
                    status_code   = result.get("status"),
                    our_status    = 200,   # assume we have access to the base
                    response_body = result.get("body"),
                    elapsed_ms    = result.get("elapsed_ms", 0),
                    error         = result.get("error"),
                )
                self._result.idor_results.append(idor_result)
                if idor_result.status_code == 200:
                    log.info(
                        f"[HTTPFuzzer] {path} → 200 "
                        f"(static fallback — verify manually)"
                    )

    # ------------------------------------------------------------------
    # Pagination fuzzing
    # ------------------------------------------------------------------

    def _run_pagination_probes(self) -> None:
        """
        Find list resources and fuzz their s= / l= parameters.
        List resources are those whose path has no trailing numeric ID
        and whose GET returned a 200.
        """
        list_paths = self._find_list_resources()
        if not list_paths:
            # Fallback to well-known list resources
            list_paths = ["/edev", "/upt", "/msg", "/ps", "/dr", "/bill"]

        log.info(
            f"[HTTPFuzzer] Pagination fuzzing {len(list_paths)} "
            f"list resource(s) × {len(PAGINATION_CASES)} cases"
        )

        for path in list_paths:
            baseline_ms = self._get_baseline(path)
            log.info(
                f"[HTTPFuzzer] Pagination: {path} "
                f"(baseline {baseline_ms:.0f}ms)"
            )
            for s_val, l_val, description in PAGINATION_CASES:
                self._rate_limit()
                self._probe_pagination(path, s_val, l_val,
                                       description, baseline_ms)

    def _find_list_resources(self) -> list[str]:
        """
        From the mapping result, find paths that:
          - Returned 200 on GET with registered cert
          - Look like list resources (no trailing numeric ID)
          - Have the all= attribute in their response (confirms it's a list)
        """
        if not self.mapping_result:
            return []

        list_paths = []
        for path, node in self.mapping_result.nodes.items():
            reg = node.probe_results.get(ProbeType.VALID_REG)
            if not reg or reg.status_code != 200 or not reg.body:
                continue

            # Check for all= or results= attribute — list resource indicator
            body_text = reg.body.decode("utf-8", errors="replace")
            if 'all="' in body_text or "results=" in body_text:
                list_paths.append(path)
                continue

            # Also include if path normalises to a known list pattern
            norm = _normalise_path(path)
            if norm in {"/edev", "/upt", "/msg", "/ps", "/dr",
                        "/bill", "/csf", "/ppy", "/rsps", "/upt/{id}/mr"}:
                list_paths.append(path)

        return list_paths

    def _probe_pagination(
        self,
        path:        str,
        s_val:       str | None,
        l_val:       str | None,
        description: str,
        baseline_ms: float,
    ) -> None:
        qs_parts = []
        if s_val is not None:
            qs_parts.append(f"s={s_val}")
        if l_val is not None:
            qs_parts.append(f"l={l_val}")
        full_path = f"{path}?{'&'.join(qs_parts)}" if qs_parts else path

        result = self._single_get(full_path)

        pag_result = PaginationResult(
            target        = self.target,
            path          = path,
            s_value       = s_val,
            l_value       = l_val,
            description   = description,
            status_code   = result.get("status"),
            response_body = result.get("body"),
            elapsed_ms    = result.get("elapsed_ms", 0),
            baseline_ms   = baseline_ms,
            error         = result.get("error"),
        )
        self._result.pagination_results.append(pag_result)

        self._analyse_pagination(pag_result)

    def _analyse_pagination(self, result: PaginationResult) -> None:
        path = result.path
        qs   = result.query_string

        # Server error = logic crash in pagination handling
        if result.server_error:
            self._finding(
                sev   = Severity.MEDIUM,
                title = f"Server error on pagination params: {path}?{qs}",
                desc  = (
                    f"GET {path}?{qs} returned HTTP {result.status_code} "
                    f"({result.description}). "
                    f"Server error rather than a clean 400 suggests the "
                    f"pagination logic is not validating inputs before use."
                ),
                path     = path,
                evidence = {
                    "query_string": qs,
                    "description":  result.description,
                    "status_code":  result.status_code,
                },
            )

        # Timeout / very slow response — possible DoS via huge limit
        elif result.slow_response:
            self._finding(
                sev   = Severity.HIGH,
                title = f"Slow response to pagination params: {path}?{qs}",
                desc  = (
                    f"GET {path}?{qs} took {result.elapsed_ms:.0f}ms "
                    f"(baseline {result.baseline_ms:.0f}ms). "
                    f"The server may be attempting to fulfil a huge or "
                    f"invalid page request rather than rejecting it. "
                    f"({result.description})"
                ),
                path     = path,
                evidence = {
                    "query_string": qs,
                    "elapsed_ms":   result.elapsed_ms,
                    "baseline_ms":  result.baseline_ms,
                    "description":  result.description,
                },
            )

        # SQL injection markers in response
        elif result.status_code and _looks_like_sqli_response(result.body_text):
            self._finding(
                sev   = Severity.CRITICAL,
                title = f"Possible SQL injection via pagination param: {path}?{qs}",
                desc  = (
                    f"GET {path}?{qs} response contains SQL error markers. "
                    f"The s= or l= parameter may be interpolated directly "
                    f"into a SQL query without sanitisation."
                ),
                path     = path,
                evidence = {
                    "query_string": qs,
                    "status_code":  result.status_code,
                    "description":  result.description,
                },
            )

        # Huge response body on enormous limit — server returned everything
        elif (result.l_value and result.l_value.lstrip("-").isdigit()
              and int(result.l_value) > 10000
              and result.response_body
              and len(result.response_body) > 100_000):
            self._finding(
                sev   = Severity.MEDIUM,
                title = f"Server returned unbounded response for large limit: {path}?{qs}",
                desc  = (
                    f"GET {path}?{qs} returned {len(result.response_body):,} bytes. "
                    f"The server honoured an extremely large l= value rather than "
                    f"capping it. This could expose all records and cause DoS."
                ),
                path     = path,
                evidence = {
                    "query_string":   qs,
                    "response_bytes": len(result.response_body),
                    "description":    result.description,
                },
            )

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------

    def _single_get(self, path: str) -> dict:
        return self._single_request("GET", path)

    def _single_request(
        self,
        method:  str,
        path:    str,
        body:    bytes | None = None,
        headers: dict | None  = None,
    ) -> dict:
        start = time.monotonic()
        try:
            client = Sep2HTTPClient(self.target, self._ctx, self.timeout)
            status, resp_hdrs, resp_body = client.request(
                method=method, path=path, body=body, headers=headers
            )
            elapsed = (time.monotonic() - start) * 1000
            log.debug(f"[HTTPFuzzer] {method} {path} → {status} ({elapsed:.0f}ms)")
            return {"status": status, "headers": resp_hdrs,
                    "body": resp_body, "elapsed_ms": elapsed}
        except Exception as e:
            elapsed = (time.monotonic() - start) * 1000
            err = f"{type(e).__name__}: {e}"
            log.debug(f"[HTTPFuzzer] {method} {path} → ERR {err}")
            return {"error": err, "elapsed_ms": elapsed}

    def _get_baseline(self, path: str) -> float:
        result = self._single_get(path)
        return result.get("elapsed_ms", 100.0)

    def _rate_limit(self) -> None:
        elapsed = time.monotonic() - self._last_request
        if elapsed < self._min_interval:
            time.sleep(self._min_interval - elapsed)
        self._last_request = time.monotonic()

    def _finding(
        self,
        sev:      Severity,
        title:    str,
        desc:     str,
        path:     str,
        evidence: dict,
    ) -> None:
        f = Finding(
            severity    = sev,
            title       = title,
            description = desc,
            target      = self.target,
            path        = path,
            evidence    = evidence,
        )
        self._result.findings.append(f)
        log.warning(f"[HTTPFuzzer] [{sev.value}] {title}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_first_numeric_id(path: str) -> tuple[int | None, int]:
    """
    Find the first numeric segment in a path and return (value, position).
    Position is the 0-based index into path.strip("/").split("/").

    Example: /edev/7/der  →  (7, 1)
             /upt/3/mr/2  →  (3, 1)
             /dcap        →  (None, -1)
    """
    segments = path.strip("/").split("/")
    for i, seg in enumerate(segments):
        if seg.isdigit():
            return int(seg), i
    return None, -1


def _idor_severity(path: str) -> Severity:
    """Grade IDOR severity by the function set of the accessed resource."""
    norm = _normalise_path(path)
    critical_patterns = {
        "/edev/{id}/derc", "/edev/{id}/der", "/edev/{id}/derg",
        "/edev/{id}/derp",
    }
    high_patterns = {
        "/upt/{id}", "/upt/{id}/mr", "/bill/{id}",
        "/edev/{id}/dera", "/edev/{id}/dercap",
    }
    if any(norm.startswith(p.rstrip("{id}")) for p in critical_patterns):
        return Severity.CRITICAL
    if any(norm.startswith(p.rstrip("{id}")) for p in high_patterns):
        return Severity.HIGH
    return Severity.MEDIUM


# SQL error markers that suggest the pagination param hit a query
_SQLI_PATTERNS = [
    re.compile(r"syntax\s+error", re.IGNORECASE),
    re.compile(r"sql.*error|error.*sql", re.IGNORECASE),
    re.compile(r"ORA-\d{5}"),           # Oracle
    re.compile(r"mysql_fetch", re.IGNORECASE),
    re.compile(r"pg_query", re.IGNORECASE),       # PostgreSQL
    re.compile(r"sqlite.*error", re.IGNORECASE),
    re.compile(r"unclosed quotation", re.IGNORECASE),
    re.compile(r"unterminated.*string", re.IGNORECASE),
    re.compile(r"error in your sql", re.IGNORECASE),
]

def _looks_like_sqli_response(text: str) -> bool:
    return any(p.search(text) for p in _SQLI_PATTERNS)


# ---------------------------------------------------------------------------
# Pretty printer
# ---------------------------------------------------------------------------

def print_http_fuzzing_result(result: HTTPFuzzingResult) -> None:
    SEV_COLORS = {
        Severity.CRITICAL: "\033[1;31m",
        Severity.HIGH:     "\033[31m",
        Severity.MEDIUM:   "\033[33m",
        Severity.LOW:      "\033[34m",
        Severity.INFO:     "\033[90m",
    }
    RESET = "\033[0m"

    idor_hits = [r for r in result.idor_results if r.is_idor]

    print(f"\n{'─'*60}")
    print(f"  HTTP FUZZING RESULTS — {result.target.ip}:{result.target.port}")
    print(f"{'─'*60}")
    print(f"  IDOR probes     : {len(result.idor_results)} "
          f"({len(idor_hits)} hits)")
    print(f"  Pagination probes: {len(result.pagination_results)}")
    print(f"  Findings         : {len(result.findings)}")

    if result.findings:
        print()
        for f in sorted(result.findings,
                        key=lambda x: list(Severity).index(x.severity)):
            color = SEV_COLORS.get(f.severity, "")
            print(f"  {color}[{f.severity.value}]{RESET} {f.title}")
            print(f"         {f.description[:120]}"
                  f"{'...' if len(f.description) > 120 else ''}")
    else:
        print("\n  No findings.")

    # IDOR summary table — show every probed path and its status
    if result.idor_results:
        print("\n  IDOR probe summary:")
        print(f"  {'Path':<45} {'Status':>6}  {'IDOR?':>5}")
        print(f"  {'':─<45} {'─'*6}  {'─'*5}")
        for r in sorted(result.idor_results, key=lambda x: x.probe_path):
            status = str(r.status_code) if r.status_code else (r.error or "ERR")[:6]
            flag   = "\033[1;31mYES\033[0m" if r.is_idor else "   "
            print(f"  {r.probe_path:<45} {status:>6}  {flag}")

    print()
