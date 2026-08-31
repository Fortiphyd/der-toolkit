"""
der_sep2.mapping.resource_mapper
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The resource mapper walks the IEEE 2030.5 resource tree using two
complementary strategies:

  Strategy A — href-following (RFC-compliant)
    Start at /dcap, parse XML responses for href attributes, follow
    each one recursively.  This finds everything the server intends
    to expose.  Handles pagination via s= / l= query params.

  Strategy B — wordlist brute-force
    Probe every path in the spec-defined wordlist, substituting IDs
    discovered by Strategy A.  This catches resources that exist but
    aren't linked from the root.

Both strategies run under all four probe types (A=no cert, B=self-signed,
C=valid unregistered, D=valid registered).  The diff between probe types
is what generates the policy gap findings.

Output:  a MappingResult containing:
  - A tree of ResourceNode objects (all paths → all probe results)
  - A flat list of Finding objects graded against Table 12 policy
"""

from __future__ import annotations

import logging
import re
import ssl
import socket
import time
import urllib.parse
from collections import defaultdict
from dataclasses import dataclass, field
from http.client import HTTPSConnection, HTTPResponse
from typing import Iterator, Optional

from der_sep2.models import (
    ACLAccess, Finding, ProbeResult, ProbeType,
    ResourceNode, ServiceTarget, Severity,
)
from der_sep2.mapping.resource_tree import (
    RESOURCE_WORDLIST, ResourcePolicy, expand_wordlist,
    lookup_policy, _normalise_path,
)
from der_sep2.tls.client import TLSContextFactory

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# HTTP methods to probe on each discovered resource
# ---------------------------------------------------------------------------

PROBE_METHODS = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"]

# We only auto-follow hrefs from GET responses —
# other methods are probed for method-level findings
HREF_METHODS = ["GET"]

# Pagination defaults
DEFAULT_PAGE_LIMIT = 255   # max items per page (spec allows up to 255)
MAX_PAGES          = 20    # safety cap — avoid infinite loops on buggy servers

# Request timeout
HTTP_TIMEOUT = 10.0


# ---------------------------------------------------------------------------
# Result container
# ---------------------------------------------------------------------------

@dataclass
class MappingResult:
    target:      ServiceTarget
    nodes:       dict[str, ResourceNode]  = field(default_factory=dict)
    findings:    list[Finding]            = field(default_factory=list)
    errors:      list[str]                = field(default_factory=list)

    # discovered_ids[prefix] = list of IDs found under that prefix
    # e.g. {"/edev": ["3", "7"], "/upt": ["1"]}
    discovered_ids: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))

    @property
    def all_paths(self) -> list[str]:
        return sorted(self.nodes.keys())

    @property
    def accessible_paths(self) -> list[str]:
        """Paths that returned 2xx for at least one probe type."""
        return [
            p for p, node in self.nodes.items()
            if any(
                r.status_code and 200 <= r.status_code < 300
                for r in node.probe_results.values()
            )
        ]


# ---------------------------------------------------------------------------
# HTTP client (wraps http.client with custom TLS contexts)
# ---------------------------------------------------------------------------

class Sep2HTTPClient:
    """
    Minimal HTTP/HTTPS client that accepts a custom ssl.SSLContext.

    Key design decisions vs the naive HTTPSConnection approach:
      - We open the TCP socket ourselves so we can bind to the IP directly
        while still passing the hostname (or IP) as the TLS SNI value.
        This avoids DNS re-resolution and lets us control exactly what
        goes into the TLS ClientHello.
      - We do NOT call connect() before request() — http.client handles
        the connection lifecycle internally.
      - Plain HTTP is supported for test servers that don't use TLS.
    """

    def __init__(
        self,
        target:  ServiceTarget,
        ctx:     Optional[ssl.SSLContext],   # None = plain HTTP
        timeout: float = HTTP_TIMEOUT,
    ):
        self.target  = target
        self.ctx     = ctx
        self.timeout = timeout

    def request(
        self,
        method:  str,
        path:    str,
        body:    Optional[bytes] = None,
        headers: Optional[dict]  = None,
    ) -> tuple[int, dict, bytes]:
        """
        Make a single HTTP(S) request.
        Returns (status_code, response_headers, body_bytes).
        Raises on connection / TLS failure — callers catch and store as error.
        """
        from http.client import HTTPConnection, HTTPSConnection

        hdrs = {
            "Accept":     "application/sep+xml",
            "User-Agent": "sep2-mapper/0.1",
            "Connection": "close",
            # Some 2030.5 servers require the Host header to match exactly
            "Host":       f"{self.target.hostname or self.target.ip}:{self.target.port}",
        }
        if headers:
            hdrs.update(headers)
        if body:
            hdrs["Content-Type"] = "application/sep+xml"

        # SNI server_hostname: prefer the DNS hostname, fall back to IP.
        # Using an IP for SNI is technically invalid (RFC 6066) but many
        # embedded servers handle it — we try hostname first.
        sni_host = self.target.hostname or self.target.ip

        if self.ctx is not None:
            # HTTPS path
            conn = HTTPSConnection(
                host         = self.target.ip,   # TCP destination = IP
                port         = self.target.port,
                context      = self.ctx,
                timeout      = self.timeout,
            )
            # Override the hostname used for SNI and Host header matching.
            # This is the key fix: http.client uses conn.host for SNI by
            # default, but we want to connect to the IP while sending the
            # correct hostname in the TLS handshake.
            conn._tunnel_host = None
            # Monkey-patch the SNI hostname if it differs from the IP
            if sni_host != self.target.ip:
                conn._check_hostname = sni_host
        else:
            # Plain HTTP path — used when target.tls is False
            conn = HTTPConnection(
                host    = self.target.ip,
                port    = self.target.port,
                timeout = self.timeout,
            )

        try:
            # Let http.client manage connect() internally — do NOT call
            # conn.connect() before conn.request(), it causes state issues.
            conn.request(method, path, body=body, headers=hdrs)
            resp = conn.getresponse()
            status    = resp.status
            resp_hdrs = dict(resp.getheaders())
            data      = resp.read(1024 * 1024)   # cap at 1 MB
            return status, resp_hdrs, data
        finally:
            try:
                conn.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# XML href extractor
# ---------------------------------------------------------------------------

# Matches href="..." or href='...' in XML/HTML, capturing the value.
# Using regex rather than a full XML parser so we handle malformed XML
# gracefully — important for a fuzzer/security tool.
_HREF_RE  = re.compile(r'\bhref=["\']([^"\']+)["\']', re.IGNORECASE)
_ALL_RE   = re.compile(r'\bhref=["\']([^"\']+)["\']|all=["\'](\d+)["\']', re.IGNORECASE)

# Matches the `all` attribute on list resources — tells us total item count
_ALL_ATTR = re.compile(r'\ball=["\'](\d+)["\']', re.IGNORECASE)
_RESULTS  = re.compile(r'\bresults=["\'](\d+)["\']', re.IGNORECASE)


def extract_hrefs(body: bytes) -> list[str]:
    """Pull every href value out of an XML response body."""
    if not body:
        return []
    try:
        text = body.decode("utf-8", errors="replace")
    except Exception:
        return []
    hrefs = _HREF_RE.findall(text)
    # Filter out hrefs that look like XSD type references or URNs
    return [
        h for h in hrefs
        if h.startswith("/") or h.startswith("http")
    ]


def extract_total_count(body: bytes) -> Optional[int]:
    """
    Extract the total item count from a list resource response.
    The spec uses `all="N"` on the list element, e.g.:
      <EndDeviceList all="42" results="10" ...>
    """
    if not body:
        return None
    text = body.decode("utf-8", errors="replace")
    m = _ALL_ATTR.search(text)
    if m:
        return int(m.group(1))
    return None


def extract_ids_from_hrefs(hrefs: list[str], parent_path: str) -> list[str]:
    """
    Given a list of hrefs like ["/edev/3", "/edev/7", "/edev/12"]
    and a parent path "/edev", extract the ID segments: ["3", "7", "12"].
    """
    ids = []
    prefix = parent_path.rstrip("/") + "/"
    for href in hrefs:
        path = href.split("?")[0]   # strip query string
        if path.startswith(prefix):
            remainder = path[len(prefix):]
            segment   = remainder.split("/")[0]
            if segment and not segment.startswith("{"):
                ids.append(segment)
    return list(dict.fromkeys(ids))   # deduplicate, preserve order


# ---------------------------------------------------------------------------
# Single resource prober
# ---------------------------------------------------------------------------

class ResourceProber:
    """
    Probes a single path under all configured probe types and HTTP methods.
    Returns a ResourceNode.
    """

    def __init__(
        self,
        target:          ServiceTarget,
        context_factory: TLSContextFactory,
        probe_types:     list[ProbeType],
        methods:         list[str] = PROBE_METHODS,
        timeout:         float     = HTTP_TIMEOUT,
    ):
        self.target          = target
        self.factory         = context_factory
        self.probe_types     = probe_types
        self.methods         = methods
        self.timeout         = timeout

        # Pre-build one SSLContext per probe type to avoid regenerating
        # self-signed certs on every request
        self._contexts: dict[ProbeType, ssl.SSLContext] = {}
        self._self_signed_paths: dict[ProbeType, tuple[str, str]] = {}
        self._build_contexts()

    def _build_contexts(self) -> None:
        for pt in self.probe_types:
            try:
                if not self.target.tls:
                    self._contexts[pt] = None
                elif pt == ProbeType.SELF_SIGNED:
                    ctx, cert_p, key_p = self.factory.self_signed_context()
                    self._contexts[pt]          = ctx
                    self._self_signed_paths[pt] = (cert_p, key_p)
                elif pt == ProbeType.VALID_UNREG:
                    ctx, is_distinct = self.factory.unreg_cert_context()
                    self._contexts[pt] = ctx
                    if not is_distinct:
                        log.warning(
                            "[Prober] No --client-cert-unreg provided. "
                            "Probe C (unregistered) is using a self-signed cert as "
                            "fallback — it cannot distinguish between 'CA not trusted' "
                            "and 'LFDI not registered'. "
                            "For accurate Probe C results, generate a CA-signed cert "
                            "whose LFDI you have NOT registered with the server, and "
                            "pass it via --client-cert-unreg / --client-key-unreg."
                        )
                elif pt == ProbeType.VALID_REG:
                    self._contexts[pt] = self.factory.valid_cert_context()
                else:
                    self._contexts[pt] = self.factory.no_cert_context()
            except Exception as e:
                log.warning(f"[Prober] Could not build context for {pt}: {e}")

    def cleanup(self) -> None:
        import os
        for cert_p, key_p in self._self_signed_paths.values():
            for p in (cert_p, key_p):
                try:
                    os.unlink(p)
                except Exception:
                    pass

    def probe(self, path: str) -> ResourceNode:
        node = ResourceNode(path=path)

        for probe_type in self.probe_types:
            if probe_type not in self._contexts:
                # Context build failed for this probe type — skip
                continue

            ctx = self._contexts[probe_type]   # may be None for plain HTTP

            result = self._single_request(
                probe_type = probe_type,
                ctx        = ctx,
                method     = "GET",
                path       = path,
            )
            node.probe_results[probe_type] = result

            # Extract hrefs from successful GET responses
            if result.status_code and 200 <= result.status_code < 300 and result.body:
                node.hrefs = list(dict.fromkeys(
                    node.hrefs + extract_hrefs(result.body)
                ))

        return node

    def probe_methods(self, path: str, probe_type: ProbeType) -> dict[str, ProbeResult]:
        """
        Probe all HTTP methods on a path under one probe type.
        Used after the main GET probe to check for method-level findings.
        """
        if probe_type not in self._contexts:
            return {}

        ctx = self._contexts[probe_type]

        results = {}
        for method in self.methods:
            if method == "GET":
                continue
            result = self._single_request(
                probe_type = probe_type,
                ctx        = ctx,
                method     = method,
                path       = path,
            )
            results[method] = result
        return results

    def _single_request(
        self,
        probe_type: ProbeType,
        ctx:        ssl.SSLContext,
        method:     str,
        path:       str,
    ) -> ProbeResult:
        start = time.monotonic()
        try:
            client = Sep2HTTPClient(self.target, ctx, self.timeout)
            status, hdrs, body = client.request(method, path)
            elapsed = (time.monotonic() - start) * 1000
            log.debug(
                f"[{probe_type.value:16s}] {method:6s} {path:40s} "
                f"→ {status} ({elapsed:.0f}ms)"
            )
            return ProbeResult(
                target      = self.target,
                probe_type  = probe_type,
                method      = method,
                path        = path,
                status_code = status,
                headers     = hdrs,
                body        = body,
                elapsed_ms  = elapsed,
            )
        except Exception as e:
            elapsed = (time.monotonic() - start) * 1000
            err_str = str(e)
            exc_name = type(e).__name__

            # Classify the error so the display and findings are meaningful
            if "RemoteDisconnected" in exc_name or "RemoteDisconnected" in err_str:
                # Server closed the connection before sending a response.
                # On a 2030.5 server this almost always means the TLS layer
                # rejected the client (or lack thereof) before HTTP was reached.
                err = "mTLS_REQUIRED: server closed connection (no client cert accepted)"
                log.debug(
                    f"[{probe_type.value}] {method} {path} → "
                    f"server rejected connection (mTLS enforced)"
                )
            elif "UNKNOWN_CA" in err_str or "unknown ca" in err_str.lower():
                # Server validated our client cert chain and rejected it.
                # This is CORRECT server behaviour — the self-signed cert
                # was rejected as expected.
                err = "CERT_REJECTED: server rejected client cert (unknown CA)"
                log.debug(
                    f"[{probe_type.value}] {method} {path} → "
                    f"client cert rejected by server (CA not trusted)"
                )
            elif "CERTIFICATE_REQUIRED" in err_str or "certificate required" in err_str.lower():
                err = "mTLS_REQUIRED: server explicitly requested a client cert"
                log.debug(f"[{probe_type.value}] {method} {path} → cert required")
            else:
                err = f"{exc_name}: {e}"
                log.warning(
                    f"[{probe_type.value}] {method} {path} → ERR {err}"
                )

            return ProbeResult(
                target     = self.target,
                probe_type = probe_type,
                method     = method,
                path       = path,
                error      = err,
                elapsed_ms = elapsed,
            )


# ---------------------------------------------------------------------------
# Main mapper
# ---------------------------------------------------------------------------

class ResourceMapper:
    """
    Orchestrates href-following and wordlist brute-forcing,
    then generates findings by comparing results against Table 12.
    """

    def __init__(
        self,
        target:          ServiceTarget,
        context_factory: TLSContextFactory,
        probe_types:     Optional[list[ProbeType]]  = None,
        rate_limit_rps:  float                      = 5.0,
        max_depth:       int                        = 8,
        timeout:         float                      = HTTP_TIMEOUT,
        skip_methods:    bool                       = False,
    ):
        """
        Args:
            target:          The 2030.5 server to map.
            context_factory: Pre-built TLS context factory.
            probe_types:     Which probes to run. Defaults to all four.
            rate_limit_rps:  Max requests per second (across all probes).
                             Keep low for embedded hardware targets.
            max_depth:       Max href-follow recursion depth.
            timeout:         Per-request timeout in seconds.
            skip_methods:    Skip the HTTP method probe (faster, less noisy).
        """
        self.target          = target
        self.factory         = context_factory
        self.probe_types     = probe_types or list(ProbeType)
        self.rate_limit_rps  = rate_limit_rps
        self.max_depth       = max_depth
        self.timeout         = timeout
        self.skip_methods    = skip_methods

        self._min_interval   = 1.0 / rate_limit_rps
        self._last_request   = 0.0
        self._visited:  set[str]  = set()
        self._result         = MappingResult(target=target)
        self._prober         = ResourceProber(
            target          = target,
            context_factory = context_factory,
            probe_types     = self.probe_types,
            timeout         = timeout,
        )

    def run(self) -> MappingResult:
        log.info(
            f"[Mapper] Starting resource map of {self.target.ip}:{self.target.port} "
            f"probe_types={[p.value for p in self.probe_types]}"
        )

        # ── Strategy A: href-following from /dcap ─────────────────────
        log.info("[Mapper] Phase A: href-following from base path")
        self._follow_hrefs(self.target.base_path, depth=0)

        # ── Strategy B: wordlist brute-force with discovered IDs ──────
        log.info("[Mapper] Phase B: wordlist brute-force")
        wordlist = expand_wordlist(dict(self._result.discovered_ids))
        log.info(f"[Mapper] Wordlist expanded to {len(wordlist)} paths")

        for path in wordlist:
            if path not in self._visited:
                self._probe_path(path)

        # ── Strategy C: method probing on accessible paths ────────────
        if not self.skip_methods:
            log.info("[Mapper] Phase C: HTTP method probing")
            self._probe_all_methods()

        # ── Generate findings ─────────────────────────────────────────
        log.info("[Mapper] Generating findings")
        self._generate_findings()

        self._prober.cleanup()

        log.info(
            f"[Mapper] Complete. "
            f"Paths visited: {len(self._visited)}, "
            f"Accessible: {len(self._result.accessible_paths)}, "
            f"Findings: {len(self._result.findings)}"
        )
        return self._result

    # ------------------------------------------------------------------
    # Strategy A: Recursive href-following with pagination
    # ------------------------------------------------------------------

    def _follow_hrefs(self, path: str, depth: int) -> None:
        if depth > self.max_depth:
            log.debug(f"[Mapper] Max depth {self.max_depth} reached at {path}")
            return
        if path in self._visited:
            return

        node = self._probe_path(path)

        # Paginate if needed — use the Probe D (full auth) GET response
        # as the reference for pagination, since it's most likely to succeed
        full_body = self._best_body(node)
        total     = extract_total_count(full_body) if full_body else None

        if total and total > len(node.hrefs):
            log.debug(
                f"[Mapper] Paginating {path}: server reports {total} items, "
                f"got {len(node.hrefs)} hrefs so far"
            )
            extra_hrefs = self._paginate(path, already_fetched=len(node.hrefs))
            node.hrefs  = list(dict.fromkeys(node.hrefs + extra_hrefs))

        # Record IDs discovered from child hrefs
        child_ids = extract_ids_from_hrefs(node.hrefs, path)
        if child_ids:
            existing = self._result.discovered_ids[path]
            for id_ in child_ids:
                if id_ not in existing:
                    existing.append(id_)
            log.debug(f"[Mapper] Discovered IDs under {path}: {child_ids}")

        # Recurse into children
        for href in node.hrefs:
            child_path = self._normalise_href(href)
            if child_path and child_path not in self._visited:
                self._follow_hrefs(child_path, depth + 1)

    def _paginate(self, path: str, already_fetched: int) -> list[str]:
        """
        Fetch subsequent pages of a list resource.
        Uses the no-cert context (Probe A) for pagination.
        """
        hrefs = []
        if ProbeType.NO_CERT not in self._contexts:
            return hrefs
        ctx = self._contexts[ProbeType.NO_CERT]   # may be None for plain HTTP

        offset = already_fetched
        for _ in range(MAX_PAGES):
            self._rate_limit()
            try:
                client = Sep2HTTPClient(self.target, ctx, self.timeout)
                paginated_path = f"{path}?s={offset}&l={DEFAULT_PAGE_LIMIT}"
                status, _, body = client.request("GET", paginated_path)
                if status != 200 or not body:
                    break
                page_hrefs = extract_hrefs(body)
                if not page_hrefs:
                    break
                hrefs.extend(page_hrefs)
                offset += len(page_hrefs)
                # If we got fewer than the limit, we've reached the end
                if len(page_hrefs) < DEFAULT_PAGE_LIMIT:
                    break
            except Exception as e:
                log.debug(f"[Mapper] Pagination error at {path}?s={offset}: {e}")
                break

        return hrefs

    # ------------------------------------------------------------------
    # Strategy C: Method probing on discovered accessible paths
    # ------------------------------------------------------------------

    def _probe_all_methods(self) -> None:
        """
        For each accessible path, probe non-GET HTTP methods under
        Probe A (no cert) only — we're looking for methods that should
        require auth but don't.
        """
        accessible = [
            p for p, node in self._result.nodes.items()
            if any(
                r.status_code and 200 <= r.status_code < 300
                for r in node.probe_results.values()
                if r.method == "GET"
            )
        ]

        log.info(f"[Mapper] Method probing {len(accessible)} accessible paths")

        for path in accessible:
            self._rate_limit()
            method_results = self._prober.probe_methods(path, ProbeType.NO_CERT)
            node = self._result.nodes[path]
            # Store method results in evidence dict on the node's Probe A result
            if ProbeType.NO_CERT in node.probe_results:
                node.probe_results[ProbeType.NO_CERT].headers["_method_probe"] = {
                    m: r.status_code for m, r in method_results.items()
                }

    # ------------------------------------------------------------------
    # Core probe helper
    # ------------------------------------------------------------------

    def _probe_path(self, path: str) -> ResourceNode:
        """Probe a path under all probe types, register in result."""
        self._rate_limit()
        self._visited.add(path)

        node = self._prober.probe(path)
        self._result.nodes[path] = node

        # Quick summary log for anything that responded
        for pt, result in node.probe_results.items():
            if result.status_code:
                log.info(
                    f"[{pt.value:18s}] GET {path:45s} → {result.status_code}"
                )

        return node

    # ------------------------------------------------------------------
    # Finding generator
    # ------------------------------------------------------------------

    def _generate_findings(self) -> None:
        for path, node in self._result.nodes.items():
            policy = lookup_policy(path)
            self._check_policy_gap(path, node, policy)
            self._check_write_without_auth(path, node, policy)
            self._check_unlisted_resource(path, node, policy)
            self._check_method_findings(path, node, policy)

    def _check_policy_gap(
        self,
        path:   str,
        node:   ResourceNode,
        policy: Optional[ResourcePolicy],
    ) -> None:
        """
        Core finding: resource accessible without a cert when policy
        says one is required.

        mTLS enforcement signals (RemoteDisconnected / UNKNOWN_CA) on
        Probe A are treated as CORRECT behaviour — the server is enforcing
        the policy at the TLS layer rather than the HTTP layer.
        """
        if policy is None:
            return

        probe_a = node.probe_results.get(ProbeType.NO_CERT)
        probe_b = node.probe_results.get(ProbeType.SELF_SIGNED)
        probe_d = node.probe_results.get(ProbeType.VALID_REG)

        def _mtls_enforced(r) -> bool:
            """True if this probe result shows the server enforced mTLS."""
            return r is not None and r.error is not None and (
                "mTLS_REQUIRED" in r.error or "CERT_REJECTED" in r.error
            )

        def _http_ok(r) -> bool:
            return r is not None and r.status_code is not None and \
                   200 <= r.status_code < 300

        a_ok           = _http_ok(probe_a)
        a_mtls_enforced = _mtls_enforced(probe_a)
        d_ok           = _http_ok(probe_d)

        if policy.cert_required:
            if a_ok:
                # HTTP 2xx without cert — policy violation
                sev = _policy_severity(policy, is_write=False)
                self._result.findings.append(Finding(
                    severity    = sev,
                    title       = f"Resource accessible without client certificate: {path}",
                    description = (
                        f"The {policy.function_set} resource at {path!r} returned "
                        f"HTTP {probe_a.status_code} without a client certificate. "
                        f"IEEE 2030.5 Table 12 specifies cert_required=True. "
                        f"{policy.notes}"
                    ),
                    target     = self.target,
                    path       = path,
                    probe_type = ProbeType.NO_CERT,
                    evidence   = {
                        "probe_a_status": probe_a.status_code,
                        "probe_d_status": probe_d.status_code if probe_d else None,
                        "function_set":   policy.function_set,
                    },
                ))
            elif a_mtls_enforced:
                # Server correctly enforced mTLS — log at DEBUG, no finding
                log.debug(
                    f"[Findings] {path}: mTLS correctly enforced for "
                    f"{policy.function_set}"
                )
            # else: connection error unrelated to cert policy — skip

        if policy.reg_required and _http_ok(probe_b):
            # Self-signed cert accepted on a resource that requires registration
            self._result.findings.append(Finding(
                severity    = Severity.CRITICAL,
                title       = f"Self-signed cert accepted on protected resource: {path}",
                description = (
                    f"{policy.function_set} resource {path!r} accepted a "
                    f"self-signed client certificate not from any recognised CA. "
                    f"This means ACL / registration checks are not backed by real "
                    f"certificate chain validation."
                ),
                target     = self.target,
                path       = path,
                probe_type = ProbeType.SELF_SIGNED,
                evidence   = {
                    "probe_b_status": probe_b.status_code,
                    "function_set":   policy.function_set,
                },
            ))

    def _check_write_without_auth(
        self,
        path:   str,
        node:   ResourceNode,
        policy: Optional[ResourcePolicy],
    ) -> None:
        """
        Flag writable methods (POST/PUT/DELETE) on resources whose
        aclDefaultAccess is read-only (GET only = 0x8).
        """
        if policy is None:
            return

        probe_a = node.probe_results.get(ProbeType.NO_CERT)
        if not probe_a or not probe_a.status_code:
            return

        # Extract method probe results stored in headers by _probe_all_methods
        method_results: dict = probe_a.headers.get("_method_probe", {})
        if not method_results:
            return

        read_only_policy = (
            policy.acl_default_access == ACLAccess.GET
            and not policy.cert_required
        )

        if not read_only_policy:
            return

        for method, status in method_results.items():
            if method in ("POST", "PUT", "DELETE") and status and 200 <= status < 300:
                self._result.findings.append(Finding(
                    severity    = _policy_severity(policy, is_write=True),
                    title       = f"Unauthenticated write accepted: {method} {path}",
                    description = (
                        f"{method} {path!r} returned HTTP {status} without any "
                        f"client certificate. "
                        f"Table 12 aclDefaultAccess for {policy.function_set} is "
                        f"0x8 (GET only). Write access without auth violates the "
                        f"default policy."
                    ),
                    target     = self.target,
                    path       = path,
                    probe_type = ProbeType.NO_CERT,
                    evidence   = {
                        "method":       method,
                        "status":       status,
                        "function_set": policy.function_set,
                        "acl_default":  str(policy.acl_default_access),
                    },
                ))

    def _check_unlisted_resource(
        self,
        path:   str,
        node:   ResourceNode,
        policy: Optional[ResourcePolicy],
    ) -> None:
        """
        A resource is accessible but wasn't reachable from the href tree —
        it only appeared in the wordlist brute-force.  Flag as informational.
        """
        probe_d = node.probe_results.get(ProbeType.VALID_REG)
        d_ok    = probe_d and probe_d.status_code and 200 <= probe_d.status_code < 300

        if not d_ok:
            return

        # Was this path reachable via href-following?
        # Proxy: check if any parent path's hrefs include this path
        parent_linked = any(
            path in parent_node.hrefs
            for parent_path, parent_node in self._result.nodes.items()
            if parent_path != path
        )

        if not parent_linked:
            self._result.findings.append(Finding(
                severity    = Severity.INFO,
                title       = f"Accessible resource not linked from resource tree: {path}",
                description = (
                    f"{path!r} responded successfully but is not reachable by "
                    f"following hrefs from /dcap. It was only found via wordlist "
                    f"brute-force. This may indicate an intentionally hidden endpoint "
                    f"or a misconfigured resource tree."
                ),
                target     = self.target,
                path       = path,
                probe_type = ProbeType.VALID_REG,
                evidence   = {"discovered_via": "wordlist"},
            ))

    def _check_method_findings(
        self,
        path:   str,
        node:   ResourceNode,
        policy: Optional[ResourcePolicy],
    ) -> None:
        """
        Check for unexpected methods:
          - OPTIONS revealing sensitive info
          - TRACE enabled (potential XST)
          - DELETE on list resources without auth
        """
        probe_a = node.probe_results.get(ProbeType.NO_CERT)
        if not probe_a:
            return

        method_results: dict = probe_a.headers.get("_method_probe", {})

        trace_status = method_results.get("TRACE")
        if trace_status and 200 <= trace_status < 300:
            self._result.findings.append(Finding(
                severity    = Severity.MEDIUM,
                title       = f"TRACE method enabled: {path}",
                description = (
                    f"TRACE {path!r} returned {trace_status}. "
                    f"TRACE can be used in Cross-Site Tracing (XST) attacks to steal "
                    f"credentials from headers. It should be disabled on all endpoints."
                ),
                target     = self.target,
                path       = path,
                probe_type = ProbeType.NO_CERT,
                evidence   = {"trace_status": trace_status},
            ))

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _rate_limit(self) -> None:
        elapsed = time.monotonic() - self._last_request
        if elapsed < self._min_interval:
            time.sleep(self._min_interval - elapsed)
        self._last_request = time.monotonic()

    def _best_body(self, node: ResourceNode) -> Optional[bytes]:
        """Return the response body from the most-privileged successful probe."""
        for pt in [ProbeType.VALID_REG, ProbeType.VALID_UNREG,
                   ProbeType.SELF_SIGNED, ProbeType.NO_CERT]:
            r = node.probe_results.get(pt)
            if r and r.status_code and 200 <= r.status_code < 300 and r.body:
                return r.body
        return None

    def _normalise_href(self, href: str) -> Optional[str]:
        """
        Convert an href to a bare path we can probe.
        Handles absolute URLs (same host), relative paths, and strips
        query strings (we handle pagination separately).
        """
        if not href:
            return None
        parsed = urllib.parse.urlparse(href)
        if parsed.scheme and parsed.netloc:
            # Absolute URL — only follow if it's the same host
            target_host = self.target.hostname or self.target.ip
            if parsed.hostname not in (target_host, self.target.ip):
                log.debug(f"[Mapper] Skipping external href: {href}")
                return None
        path = parsed.path
        if not path or not path.startswith("/"):
            return None
        return path


# ---------------------------------------------------------------------------
# Severity grading helper
# ---------------------------------------------------------------------------

_HIGH_RISK_FUNCTION_SETS = {
    "DER (Distributed Energy Resource)",
    "DER Program",
    "DER Control",
    "DER Settings",
    "DER Availability",
    "Billing",
    "Prepayment",
    "Customer Account",
}

_MEDIUM_RISK_FUNCTION_SETS = {
    "Demand Response",
    "Usage Point / Metering",
    "Response Set",
    "Subscription",
    "Log Event List",
}


def _policy_severity(policy: ResourcePolicy, is_write: bool) -> Severity:
    fs = policy.function_set
    if fs in _HIGH_RISK_FUNCTION_SETS:
        return Severity.CRITICAL if is_write else Severity.HIGH
    if fs in _MEDIUM_RISK_FUNCTION_SETS:
        return Severity.HIGH if is_write else Severity.MEDIUM
    return Severity.MEDIUM if is_write else Severity.LOW


# ---------------------------------------------------------------------------
# Pretty-print helper
# ---------------------------------------------------------------------------

def print_mapping_result(result: MappingResult) -> None:
    """Print a human-readable summary of a MappingResult to stdout."""
    SEV_COLORS = {
        Severity.CRITICAL: "\033[1;31m",
        Severity.HIGH:     "\033[31m",
        Severity.MEDIUM:   "\033[33m",
        Severity.LOW:      "\033[34m",
        Severity.INFO:     "\033[90m",
    }
    RESET = "\033[0m"

    print(f"\n{'─'*60}")
    print(f"  RESOURCE MAP — {result.target.ip}:{result.target.port}")
    print(f"{'─'*60}")
    print(f"  Paths visited:    {len(result.nodes)}")
    print(f"  Paths accessible: {len(result.accessible_paths)}")

    # Probe access matrix
    # Column codes:
    #   200-599  = HTTP status code
    #   mTLS     = server closed connection (requires client cert)
    #   CAREJ    = server rejected client cert (unknown CA)
    #   ERR      = unexpected connection error
    #   ---      = probe not run
    def _cell(r) -> str:
        if r is None:
            return f"{'---':>6}"
        if r.status_code:
            return f"{r.status_code:>6}"
        if r.error:
            if "mTLS_REQUIRED" in r.error:
                return f"{'mTLS':>6}"
            if "CERT_REJECTED" in r.error:
                return f"{'CAREJ':>6}"
            return f"{'ERR':>6}"
        return f"{'---':>6}"

    print(f"\n  {'Path':<45} {'  A':>6} {'  B':>6} {'  C':>6} {'  D':>6}")
    print(f"  {'':─<45} {'─'*6} {'─'*6} {'─'*6} {'─'*6}")
    print(f"  {'':─<45} {'no cert':>6} {'selfsig':>6} {'unreg':>6} {'reg':>6}")
    print(f"  {'':─<45} {'─'*6} {'─'*6} {'─'*6} {'─'*6}")
    for path in sorted(result.nodes.keys()):
        node = result.nodes[path]
        cols = [_cell(node.probe_results.get(pt)) for pt in ProbeType]
        print(f"  {path:<45} {cols[0]} {cols[1]} {cols[2]} {cols[3]}")

    # Findings
    print(f"\n  Findings ({len(result.findings)}):")
    if not result.findings:
        print("  (none)")
    else:
        for f in sorted(result.findings,
                        key=lambda x: list(Severity).index(x.severity)):
            color = SEV_COLORS.get(f.severity, "")
            print(f"  {color}[{f.severity.value}]{RESET} {f.title}")
            print(f"         {f.description[:120]}"
                  f"{'...' if len(f.description) > 120 else ''}")
    print()
