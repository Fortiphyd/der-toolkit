"""
der_sep2.fuzzing.xml_fuzzer
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Sends XML fuzzing payloads to writable 2030.5 endpoints and analyses
the responses for evidence of vulnerability.

Detection strategy per vulnerability class:

  Billion laughs / Quadratic blowup
    → Response time >> baseline.  A vulnerable parser will hang or
      time out while expanding entities.  We measure the baseline
      GET response time first and flag if the fuzz response takes
      more than 3× longer (or hits the timeout).

  XXE file disclosure
    → Response body contains content that looks like /etc/passwd
      (colon-separated fields), /etc/hosts (IP + hostname lines),
      or other file signatures.  Also flag if Content-Length of
      the error response is surprisingly large — the file may be
      reflected even in error messages.

  XXE SSRF
    → Primarily detected out-of-band (listener receives a request).
      In-band: response time spike (server made an outbound HTTP
      request and waited), or error message revealing internal host.

  Oversized / Deep nesting
    → Server crashes (connection reset), hangs (timeout), or returns
      5xx.  A well-hardened server returns 400 quickly.

  Malformed XML
    → 5xx or connection reset = parser not handling errors gracefully.
      400 = correct rejection.

  Namespace confusion
    → 200 on a wrong-namespace payload = namespace not validated.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field

from der_sep2.fuzzing.xml_payloads import (
    FuzzPayload,
    VulnClass,
    all_payloads,
)
from der_sep2.mapping.resource_mapper import MappingResult, Sep2HTTPClient
from der_sep2.models import Finding, ProbeType, ServiceTarget, Severity
from der_sep2.tls.client import TLSContextFactory

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Endpoints that accept XML bodies (POST/PUT)
# The fuzzer targets these paths from the mapping result.
# ---------------------------------------------------------------------------

# Paths that commonly accept POST (create new resource)
POST_ENDPOINTS = {
    "/edev",
    "/edev/{id}/log",
    "/edev/{id}/sub",
    "/rsps",
    "/rsps/{id}/rsp",
    "/ntfy",
}

# Paths that commonly accept PUT (update existing resource)
PUT_ENDPOINTS = {
    "/edev/{id}",
    "/edev/{id}/reg",
    "/edev/{id}/der/{id}",
    "/edev/{id}/der/{id}/derg",
    "/edev/{id}/der/{id}/dera",
    "/edev/{id}/derp/{id}",
    "/edev/{id}/derp/{id}/derc/{id}",
}

# Signatures indicating file content was reflected in the response
FILE_DISCLOSURE_PATTERNS = [
    re.compile(r"root:.*:0:0"),                  # /etc/passwd root entry
    re.compile(r"\d+\.\d+\.\d+\.\d+\s+\w+"),    # /etc/hosts IP line
    re.compile(r"PATH=|HOME=|USER=|SHELL="),      # /proc/environ
    re.compile(r"-----BEGIN.*PRIVATE KEY-----"),  # TLS key
    re.compile(r"\[fonts\]|\[extensions\]"),       # Windows ini
]


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class FuzzResult:
    """Result of sending one payload to one endpoint."""
    target:        ServiceTarget
    path:          str
    method:        str
    payload:       FuzzPayload
    status_code:   int | None    = None
    response_body: bytes | None  = None
    elapsed_ms:    float            = 0.0
    error:         str | None    = None
    baseline_ms:   float            = 0.0   # GET response time for comparison

    @property
    def timed_out(self) -> bool:
        return self.error is not None and "timeout" in self.error.lower()

    @property
    def server_error(self) -> bool:
        return self.status_code is not None and self.status_code >= 500

    @property
    def slow_response(self) -> bool:
        if self.baseline_ms <= 0:
            return False
        threshold = max(self.payload.timeout_flag_secs * 1000,
                        self.baseline_ms * 3)
        return self.elapsed_ms > threshold

    @property
    def body_text(self) -> str:
        if self.response_body:
            return self.response_body.decode("utf-8", errors="replace")
        return ""


@dataclass
class FuzzingResult:
    target:   ServiceTarget
    results:  list[FuzzResult]  = field(default_factory=list)
    findings: list[Finding]     = field(default_factory=list)


# ---------------------------------------------------------------------------
# Core fuzzer
# ---------------------------------------------------------------------------

class XMLFuzzer:
    """
    Sends XML payloads to writable endpoints discovered by the resource
    mapper and analyses responses for vulnerability indicators.
    """

    def __init__(
        self,
        target:          ServiceTarget,
        context_factory: TLSContextFactory,
        mapping_result:  MappingResult | None = None,
        rate_limit_rps:  float = 2.0,   # lower default than mapper — fuzzing is noisier
        timeout:         float = 10.0,
        callback_host:   str   = "127.0.0.1",
        callback_port:   int   = 9999,
        vuln_classes:    list[VulnClass] | None = None,
    ):
        self.target          = target
        self.factory         = context_factory
        self.mapping_result  = mapping_result
        self.rate_limit_rps  = rate_limit_rps
        self.timeout         = timeout
        self.callback_host   = callback_host
        self.callback_port   = callback_port
        self.vuln_classes    = vuln_classes  # None = all classes

        self._min_interval = 1.0 / rate_limit_rps
        self._last_request = 0.0

        # Use the registered cert context for fuzzing — we want to get past
        # auth checks so we're actually hitting the XML parser
        try:
            self._ctx = context_factory.valid_cert_context()
        except ValueError:
            log.warning(
                "[Fuzzer] No registered client cert provided. "
                "Fuzzing will use no-cert context — many endpoints may reject requests "
                "before reaching the XML parser."
            )
            self._ctx = context_factory.no_cert_context()

        self._result = FuzzingResult(target=target)

    def run(self) -> FuzzingResult:
        payloads = all_payloads(self.callback_host, self.callback_port)
        if self.vuln_classes:
            payloads = [p for p in payloads if p.vuln_class in self.vuln_classes]

        endpoints = self._select_endpoints()
        log.info(
            f"[Fuzzer] Starting XML fuzzing of {self.target.ip}:{self.target.port} — "
            f"{len(endpoints)} endpoints × {len(payloads)} payloads"
        )

        for path, method in endpoints:
            baseline_ms = self._get_baseline(path)
            log.info(f"[Fuzzer] Fuzzing {method} {path} (baseline {baseline_ms:.0f}ms)")

            for payload in payloads:
                if self.vuln_classes and payload.vuln_class not in self.vuln_classes:
                    continue
                self._rate_limit()
                result = self._send(path, method, payload, baseline_ms)
                self._result.results.append(result)
                self._analyse(result)

        log.info(
            f"[Fuzzer] Complete. "
            f"{len(self._result.results)} probes, "
            f"{len(self._result.findings)} findings."
        )
        return self._result

    # ------------------------------------------------------------------
    # Endpoint selection
    # ------------------------------------------------------------------

    def _select_endpoints(self) -> list[tuple[str, str]]:
        """
        Build the list of (path, method) pairs to fuzz.

        Priority:
          1. Paths from the mapping result that returned 2xx on POST or PUT
             under Probe D — these are confirmed writable endpoints.
          2. Common writable paths from the static list, substituting
             discovered IDs from the mapping result.
        """
        endpoints: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()

        def _add(path: str, method: str) -> None:
            key = (path, method)
            if key not in seen:
                seen.add(key)
                endpoints.append(key)

        # From mapping result — confirmed writable endpoints
        if self.mapping_result:
            for path, node in self.mapping_result.nodes.items():
                method_probe = node.probe_results.get(ProbeType.VALID_REG)
                if not method_probe:
                    continue
                extra = method_probe.headers.get("_method_probe", {})
                for method, status in extra.items():
                    if method in ("POST", "PUT") and status and 200 <= status < 300:
                        _add(path, method)

            # Also try POST on list endpoints that returned 200 on GET
            for path, node in self.mapping_result.nodes.items():
                get_result = node.probe_results.get(ProbeType.VALID_REG)
                if get_result and get_result.status_code == 200:
                    # If it's a list resource (no trailing ID), try POST
                    from der_sep2.mapping.resource_tree import _normalise_path
                    norm = _normalise_path(path)
                    if not norm.endswith("/{id}") and path.count("/") <= 2:
                        _add(path, "POST")

        # Static fallback — common writable paths
        discovered_ids = {}
        if self.mapping_result:
            discovered_ids = dict(self.mapping_result.discovered_ids)

        from der_sep2.mapping.resource_tree import _normalise_path, expand_wordlist
        all_paths = expand_wordlist(discovered_ids)

        for path in all_paths:
            norm = _normalise_path(path)
            if any(_normalise_path(ep) == norm for ep in POST_ENDPOINTS):
                _add(path, "POST")
            if any(_normalise_path(ep) == norm for ep in PUT_ENDPOINTS):
                _add(path, "PUT")

        # Always include /edev as a POST target — it's the registration endpoint
        _add("/edev", "POST")

        log.info(f"[Fuzzer] Selected {len(endpoints)} (path, method) pairs to fuzz")
        return endpoints

    # ------------------------------------------------------------------
    # Baseline measurement
    # ------------------------------------------------------------------

    def _get_baseline(self, path: str) -> float:
        """
        GET the path with the registered cert and record response time.
        Used as a reference to detect anomalously slow fuzz responses.
        """
        try:
            client = Sep2HTTPClient(self.target, self._ctx, self.timeout)
            start = time.monotonic()
            client.request("GET", path)
            return (time.monotonic() - start) * 1000
        except Exception:
            return 100.0   # default 100ms if baseline fails

    # ------------------------------------------------------------------
    # Send one payload
    # ------------------------------------------------------------------

    def _send(
        self,
        path:        str,
        method:      str,
        payload:     FuzzPayload,
        baseline_ms: float,
    ) -> FuzzResult:
        result = FuzzResult(
            target      = self.target,
            path        = path,
            method      = method,
            payload     = payload,
            baseline_ms = baseline_ms,
        )

        try:
            client = Sep2HTTPClient(self.target, self._ctx, self.timeout)
            start  = time.monotonic()
            status, hdrs, body = client.request(
                method  = method,
                path    = path,
                body    = payload.body,
                headers = {"Content-Type": "application/sep+xml"},
            )
            result.elapsed_ms    = (time.monotonic() - start) * 1000
            result.status_code   = status
            result.response_body = body

            log.debug(
                f"[Fuzzer] {method} {path} [{payload.name}] "
                f"→ {status} ({result.elapsed_ms:.0f}ms)"
            )

        except Exception as e:
            result.elapsed_ms = (time.monotonic() - start) * 1000 \
                if 'start' in dir() else 0.0
            result.error = f"{type(e).__name__}: {e}"
            log.debug(
                f"[Fuzzer] {method} {path} [{payload.name}] → ERR {result.error}"
            )

        return result

    # ------------------------------------------------------------------
    # Response analysis
    # ------------------------------------------------------------------

    def _analyse(self, result: FuzzResult) -> None:
        """Generate findings from a single FuzzResult."""

        vc = result.payload.vuln_class

        # ── DoS indicators (billion laughs, quadratic, oversized, deep nesting)
        if vc in (VulnClass.BILLION_LAUGHS, VulnClass.QUADRATIC_BLOWUP,
                  VulnClass.OVERSIZED, VulnClass.DEEP_NESTING):
            if result.timed_out:
                self._finding(
                    sev      = Severity.CRITICAL,
                    title    = f"Server hung on {vc.value} payload: {result.path}",
                    desc     = (
                        f"{result.method} {result.path} timed out after "
                        f"{self.timeout}s when sent [{result.payload.name}]. "
                        f"The XML parser appears to be expanding entities / processing "
                        f"large input without limits — potential denial of service. "
                        f"{result.payload.description}"
                    ),
                    result   = result,
                )
            elif result.slow_response:
                self._finding(
                    sev      = Severity.HIGH,
                    title    = f"Slow response to {vc.value} payload: {result.path}",
                    desc     = (
                        f"{result.method} {result.path} took {result.elapsed_ms:.0f}ms "
                        f"(baseline {result.baseline_ms:.0f}ms) for [{result.payload.name}]. "
                        f"Response significantly slower than baseline — may indicate "
                        f"partial entity expansion before limit was hit. "
                        f"{result.payload.description}"
                    ),
                    result   = result,
                )
            elif result.server_error:
                self._finding(
                    sev      = Severity.MEDIUM,
                    title    = f"Server error on {vc.value} payload: {result.path}",
                    desc     = (
                        f"{result.method} {result.path} returned HTTP "
                        f"{result.status_code} for [{result.payload.name}]. "
                        f"Server error rather than clean 400 — parser may not be "
                        f"handling this input gracefully. {result.payload.description}"
                    ),
                    result   = result,
                )

        # ── XXE file disclosure
        elif vc == VulnClass.XXE_FILE:
            if result.status_code and result.response_body:
                for pattern in FILE_DISCLOSURE_PATTERNS:
                    if pattern.search(result.body_text):
                        self._finding(
                            sev    = Severity.CRITICAL,
                            title  = f"XXE file disclosure confirmed: {result.path}",
                            desc   = (
                                f"Response to [{result.payload.name}] on "
                                f"{result.method} {result.path} contains content "
                                f"matching pattern {pattern.pattern!r}. "
                                f"The XML parser is resolving external file:// entities "
                                f"and reflecting file contents in responses. "
                                f"{result.payload.description}"
                            ),
                            result = result,
                        )
                        break

            # Large error response may indicate file was partially read
            if (result.status_code and result.status_code >= 400
                    and result.response_body
                    and len(result.response_body) > 500):
                self._finding(
                    sev    = Severity.MEDIUM,
                    title  = f"Unexpectedly large error response to XXE payload: {result.path}",
                    desc   = (
                        f"HTTP {result.status_code} response to [{result.payload.name}] "
                        f"on {result.method} {result.path} is {len(result.response_body)} bytes — "
                        f"larger than expected for a simple rejection. "
                        f"Inspect manually — file contents may be embedded in error message."
                    ),
                    result = result,
                )

        # ── XXE SSRF
        elif vc == VulnClass.XXE_SSRF:
            if result.slow_response or result.timed_out:
                self._finding(
                    sev    = Severity.HIGH,
                    title  = f"Possible XXE SSRF — slow response: {result.path}",
                    desc   = (
                        f"{result.method} {result.path} took {result.elapsed_ms:.0f}ms "
                        f"for [{result.payload.name}] (baseline {result.baseline_ms:.0f}ms). "
                        f"Slow response may indicate the server made an outbound connection "
                        f"attempt. Check your callback listener at "
                        f"{self.callback_host}:{self.callback_port}. "
                        f"{result.payload.description}"
                    ),
                    result = result,
                )

        # ── Namespace confusion — server accepted wrong namespace
        elif vc == VulnClass.NAMESPACE:
            if result.status_code and 200 <= result.status_code < 300:
                self._finding(
                    sev    = Severity.MEDIUM,
                    title  = f"Wrong XML namespace accepted: {result.path}",
                    desc   = (
                        f"{result.method} {result.path} returned HTTP "
                        f"{result.status_code} for [{result.payload.name}] which uses "
                        f"a non-2030.5 namespace. The server is not validating the XML "
                        f"namespace — it may process arbitrary XML structures."
                    ),
                    result = result,
                )

        # ── Malformed XML — server crashed or hung rather than returning 400
        elif vc == VulnClass.MALFORMED:
            if result.timed_out or result.error:
                self._finding(
                    sev    = Severity.MEDIUM,
                    title  = f"Server hung/crashed on malformed XML: {result.path}",
                    desc   = (
                        f"{result.method} {result.path} produced error "
                        f"{result.error!r} for [{result.payload.name}]. "
                        f"A robust server should return 400 immediately. "
                        f"{result.payload.description}"
                    ),
                    result = result,
                )
            elif result.server_error:
                self._finding(
                    sev    = Severity.LOW,
                    title  = f"Server error on malformed XML: {result.path}",
                    desc   = (
                        f"{result.method} {result.path} returned "
                        f"HTTP {result.status_code} for [{result.payload.name}]. "
                        f"Should return 400. {result.payload.description}"
                    ),
                    result = result,
                )

    def _finding(
        self,
        sev:    Severity,
        title:  str,
        desc:   str,
        result: FuzzResult,
    ) -> None:
        f = Finding(
            severity    = sev,
            title       = title,
            description = desc,
            target      = self.target,
            path        = result.path,
            evidence    = {
                "payload_name":  result.payload.name,
                "vuln_class":    result.payload.vuln_class.value,
                "method":        result.method,
                "status_code":   result.status_code,
                "elapsed_ms":    result.elapsed_ms,
                "baseline_ms":   result.baseline_ms,
                "error":         result.error,
                "response_size": len(result.response_body) if result.response_body else 0,
            },
        )
        self._result.findings.append(f)
        log.warning(f"[Fuzzer] [{sev.value}] {title}")

    def _rate_limit(self) -> None:
        elapsed = time.monotonic() - self._last_request
        if elapsed < self._min_interval:
            time.sleep(self._min_interval - elapsed)
        self._last_request = time.monotonic()


# ---------------------------------------------------------------------------
# Pretty printer
# ---------------------------------------------------------------------------

def print_fuzzing_result(result: FuzzingResult) -> None:
    SEV_COLORS = {
        Severity.CRITICAL: "\033[1;31m",
        Severity.HIGH:     "\033[31m",
        Severity.MEDIUM:   "\033[33m",
        Severity.LOW:      "\033[34m",
        Severity.INFO:     "\033[90m",
    }
    RESET = "\033[0m"

    print(f"\n{'─'*60}")
    print(f"  XML FUZZING RESULTS — {result.target.ip}:{result.target.port}")
    print(f"{'─'*60}")
    print(f"  Payloads sent : {len(result.results)}")
    print(f"  Findings      : {len(result.findings)}")

    if not result.findings:
        print("\n  No findings — server handled all payloads correctly.")
        return

    # Group findings by vuln class
    by_class: dict[str, list[Finding]] = {}
    for f in result.findings:
        vc = f.evidence.get("vuln_class", "unknown")
        by_class.setdefault(vc, []).append(f)

    for vc, findings in sorted(by_class.items()):
        print(f"\n  ── {vc.replace('_', ' ').title()} ({len(findings)}) ──")
        for f in sorted(findings, key=lambda x: list(Severity).index(x.severity)):
            color = SEV_COLORS.get(f.severity, "")
            print(f"  {color}[{f.severity.value}]{RESET} {f.title}")
            print(f"         {f.description[:120]}"
                  f"{'...' if len(f.description) > 120 else ''}")
            ev = f.evidence
            print(
                f"         payload={ev.get('payload_name')} "
                f"status={ev.get('status_code')} "
                f"elapsed={ev.get('elapsed_ms', 0):.0f}ms "
                f"baseline={ev.get('baseline_ms', 0):.0f}ms"
            )
    print()
