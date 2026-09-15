"""
der_sep2.cli
~~~~~~~~~~~~~~~
Command-line interface for the IEEE 2030.5 mapper/fuzzer.

Usage examples:

  # Full discovery on local network
  python -m der_sep2 discover --scan 192.168.1.0/24

  # TLS profile a known target
  python -m der_sep2 tls 192.168.1.100 --port 15388 \
      --client-cert ./my.crt --client-key ./my.key

  # Map resources on a known target (no discovery needed)
  python -m der_sep2 map 192.168.1.100 --port 15388 \
      --client-cert ./my.crt --client-key ./my.key

  # Fuzz a known target (DISRUPTIVE)
  python -m der_sep2 fuzz 192.168.1.100 --port 15388 \
      --client-cert ./my.crt --client-key ./my.key \
      --authorized-scope 192.168.1.100/32 --allow-disruptive

  # Full pipeline: discover → TLS → map → fuzz (DISRUPTIVE unless --skip-fuzz)
  python -m der_sep2 run --scan 192.168.1.0/24 \
      --client-cert ./my.crt --client-key ./my.key \
      --authorized-scope 192.168.1.0/24 --allow-disruptive \
      --output results.json
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

from der_sep2.discovery.dns_sd import DiscoveryOrchestrator
from der_sep2.models import (
    Finding,
    ProbeType,
    ServiceTarget,
    Severity,
    TLSProfile,
)
from der_sep2.tls.cert_analyzer import TLSFindingGenerator
from der_sep2.tls.client import TLSContextFactory, TLSProfiler

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

def _setup_logging(verbose: bool = False) -> None:
    level   = logging.DEBUG if verbose else logging.INFO
    fmt     = "%(asctime)s %(levelname)-8s %(name)s — %(message)s"
    datefmt = "%H:%M:%S"
    logging.basicConfig(level=level, format=fmt, datefmt=datefmt)
    for lib in ("zeroconf", "urllib3", "asyncio"):
        logging.getLogger(lib).setLevel(logging.WARNING)


# ---------------------------------------------------------------------------
# Result serialization
# ---------------------------------------------------------------------------

def _target_dict(t: ServiceTarget) -> dict:
    return {
        "ip":           t.ip,
        "port":         t.port,
        "base_path":    t.base_path,
        "hostname":     t.hostname,
        "tls":          t.tls,
        "source":       t.source,
        "service_type": t.service_type,
        "txt":          t.txt_properties,
        "base_url":     t.base_url,
    }


def _tls_profile_dict(p: TLSProfile) -> dict:
    return {
        "negotiated_version":    p.negotiated_version,
        "negotiated_cipher":     p.negotiated_cipher,
        "supported_versions":    p.supported_versions,
        "weak_ciphers": [
            {"requested": w.requested, "negotiated": w.negotiated, "category": w.category}
            for w in p.weak_ciphers
        ],
        "requires_client_cert":  p.requires_client_cert,
        "accepted_self_signed":  p.accepted_self_signed,
        "error":                 p.error,
        "certificates": [
            {
                "subject":        c.subject,
                "issuer":         c.issuer,
                "san":            c.san,
                "not_before":     str(c.not_before),
                "not_after":      str(c.not_after),
                "is_expired":     c.is_expired,
                "is_self_signed": c.is_self_signed,
                "sig_algorithm":  c.sig_algorithm,
                "fingerprint":    c.fingerprint_sha256,
            }
            for c in p.cert_chain
        ],
    }


def _finding_dict(f: Finding) -> dict:
    return {
        "severity":    f.severity.value,
        "title":       f.title,
        "description": f.description,
        "target":      f"{f.target.ip}:{f.target.port}",
        "path":        f.path,
        "evidence":    f.evidence,
        "timestamp":   f.timestamp.isoformat(),
    }


def _map_result_dict(result) -> dict:
    nodes = {}
    for path, node in result.nodes.items():
        probe_summary = {}
        for pt, pr in node.probe_results.items():
            probe_summary[pt.value] = {
                "status":     pr.status_code,
                "error":      pr.error,
                "elapsed_ms": pr.elapsed_ms,
            }
        nodes[path] = {
            "probe_results": probe_summary,
            "hrefs":         node.hrefs,
            "policy_gap":    node.policy_gap,
        }
    return {
        "target":        f"{result.target.ip}:{result.target.port}",
        "paths_visited": len(result.nodes),
        "accessible":    result.accessible_paths,
        "discovered_ids": dict(result.discovered_ids),
        "nodes":          nodes,
    }


# ---------------------------------------------------------------------------
# Pretty console output
# ---------------------------------------------------------------------------

SEV_COLORS = {
    Severity.CRITICAL: "\033[1;31m",
    Severity.HIGH:     "\033[31m",
    Severity.MEDIUM:   "\033[33m",
    Severity.LOW:      "\033[34m",
    Severity.INFO:     "\033[90m",
}
RESET = "\033[0m"


def _print_findings(findings: list[Finding]) -> None:
    if not findings:
        print("  (none)")
        return
    for f in sorted(findings, key=lambda x: list(Severity).index(x.severity)):
        color = SEV_COLORS.get(f.severity, "")
        loc   = f" [{f.path}]" if f.path else ""
        print(f"  {color}[{f.severity.value}]{RESET} {f.title}{loc}")
        print(f"         {f.description[:120]}{'...' if len(f.description) > 120 else ''}")


def _print_banner() -> None:
    print("""
╔══════════════════════════════════════════╗
║   IEEE 2030.5 (SEP 2.0) Mapper/Fuzzer   ║
║                                          ║
║  Phases: discover → tls → map → fuzz    ║
╚══════════════════════════════════════════╝
""")


# ---------------------------------------------------------------------------
# Sub-command: discover
# ---------------------------------------------------------------------------

def cmd_discover(args: argparse.Namespace) -> list[ServiceTarget]:
    log = logging.getLogger("cli.discover")
    log.info("Starting discovery phase")

    orchestrator = DiscoveryOrchestrator(
        nameserver   = args.nameserver,
        domains      = args.domains,
        scan_targets = args.scan or [],
        scan_ports   = [int(p) for p in args.ports.split(",")] if args.ports else None,
        mdns_timeout = args.mdns_timeout,
        skip_mdns    = args.no_mdns,
        skip_dns_sd  = args.no_dns_sd,
        skip_scan    = not args.scan,
    )

    targets = orchestrator.run()

    print(f"\n{'─'*50}")
    print(f"  DISCOVERY RESULTS — {len(targets)} target(s) found")
    print(f"{'─'*50}")
    for t in targets:
        print(f"  [{t.source:10s}] {t.base_url}")
        if t.txt_properties:
            for k, v in t.txt_properties.items():
                print(f"             TXT  {k}={v}")
    print()

    return targets


# ---------------------------------------------------------------------------
# Sub-command: tls
# ---------------------------------------------------------------------------

def cmd_tls(
    args:    argparse.Namespace,
    targets: list[ServiceTarget] | None = None,
) -> tuple[list[TLSProfile], list[Finding]]:
    log = logging.getLogger("cli.tls")

    if targets is None:
        targets = [ServiceTarget(
            ip       = args.host,
            port     = args.port,
            hostname = args.hostname or args.host,
        )]

    factory = TLSContextFactory(
        ca_bundle   = getattr(args, "ca_bundle",   None),
        client_cert = getattr(args, "client_cert", None),
        client_key  = getattr(args, "client_key",  None),
        unreg_cert  = getattr(args, "client_cert_unreg", None),
        unreg_key   = getattr(args, "client_key_unreg",  None),
    )

    all_profiles: list[TLSProfile] = []
    all_findings: list[Finding]    = []

    for target in targets:
        log.info(f"TLS profiling {target.ip}:{target.port}")
        profiler = TLSProfiler(target, factory, connect_timeout=args.timeout)
        profile  = profiler.profile()
        all_profiles.append(profile)

        gen      = TLSFindingGenerator(target, profile)
        findings = gen.findings()
        all_findings.extend(findings)

        print(f"\n{'─'*50}")
        print(f"  TLS PROFILE — {target.ip}:{target.port}")
        print(f"{'─'*50}")
        if profile.error:
            print(f"  ERROR: {profile.error}")
        else:
            print(f"  Negotiated : {profile.negotiated_version} / {profile.negotiated_cipher}")
            print(f"  Versions   : {', '.join(profile.supported_versions) or 'none found'}")
            if profile.weak_ciphers:
                for w in profile.weak_ciphers:
                    print(f"  Weak cipher: {w.requested} → negotiated {w.negotiated} ({w.category})")
            else:
                print("  Weak ciphers: none confirmed")
            print(f"  Client cert required : {profile.requires_client_cert}")
            print(f"  Accepts self-signed  : {profile.accepted_self_signed}")
            if profile.leaf_cert:
                c = profile.leaf_cert
                expiry_str = "EXPIRED" if c.is_expired else f"{c.days_until_expiry}d remaining"
                print(f"  Cert subject : {c.subject}")
                print(f"  Cert expiry  : {c.not_after} ({expiry_str})")
                print(f"  Self-signed  : {c.is_self_signed}")
                print(f"  SAN          : {', '.join(c.san) or '(none)'}")
                print(f"  Sig alg      : {c.sig_algorithm}")
        print(f"\n  Findings ({len(findings)}):")
        _print_findings(findings)

    return all_profiles, all_findings


# ---------------------------------------------------------------------------
# Sub-command: map
# ---------------------------------------------------------------------------

def cmd_map(
    args:    argparse.Namespace,
    targets: list[ServiceTarget] | None = None,
) -> tuple[list[dict], list[Finding], list]:
    """Returns (map_dicts, findings, mapping_results) — the raw MappingResult
    objects are passed to cmd_fuzz so it can use discovered endpoints/IDs."""
    from der_sep2.mapping.resource_mapper import ResourceMapper, print_mapping_result

    log = logging.getLogger("cli.map")

    if targets is None:
        targets = [ServiceTarget(
            ip        = args.host,
            port      = args.port,
            hostname  = getattr(args, "hostname", None) or args.host,
            base_path = getattr(args, "base_path", "/dcap"),
        )]

    factory = TLSContextFactory(
        ca_bundle   = getattr(args, "ca_bundle",   None),
        client_cert = getattr(args, "client_cert", None),
        client_key  = getattr(args, "client_key",  None),
        unreg_cert  = getattr(args, "client_cert_unreg", None),
        unreg_key   = getattr(args, "client_key_unreg",  None),
    )
    probe_types = [ProbeType.NO_CERT, ProbeType.SELF_SIGNED]
    if getattr(args, "client_cert", None):
        probe_types.append(ProbeType.VALID_UNREG)
        probe_types.append(ProbeType.VALID_REG)

    all_map_dicts:    list[dict]    = []
    all_findings:     list[Finding] = []
    all_map_results:  list          = []

    for target in targets:
        log.info(
            f"Resource mapping {target.ip}:{target.port} "
            f"probes={[p.value for p in probe_types]}"
        )
        mapper = ResourceMapper(
            target          = target,
            context_factory = factory,
            probe_types     = probe_types,
            rate_limit_rps  = getattr(args, "rate_limit", 5.0),
            max_depth       = getattr(args, "max_depth",  8),
            timeout         = getattr(args, "timeout",    10.0),
            skip_methods    = getattr(args, "skip_methods", False),
        )
        result = mapper.run()
        print_mapping_result(result)
        all_map_dicts.append(_map_result_dict(result))
        all_findings.extend(result.findings)
        all_map_results.append(result)

    return all_map_dicts, all_findings, all_map_results


# ---------------------------------------------------------------------------
# Sub-command: run (full pipeline)
# ---------------------------------------------------------------------------

def cmd_run(args: argparse.Namespace) -> None:
    results = {
        "generated_at":  datetime.now(tz=timezone.utc).isoformat(),
        "targets":       [],
        "tls_profiles":  [],
        "resource_maps": [],
        "findings":      [],
    }

    # Phase 1: Discovery
    targets = cmd_discover(args)
    results["targets"] = [_target_dict(t) for t in targets]

    if not targets:
        print("No targets found. Exiting.")
        sys.exit(0)

    # Phase 2: TLS profiling
    profiles, findings = cmd_tls(args, targets=targets)
    results["tls_profiles"] = [_tls_profile_dict(p) for p in profiles]

    # Phase 3: Resource mapping
    map_dicts, map_findings, map_results = cmd_map(args, targets=targets)
    findings.extend(map_findings)
    results["resource_maps"] = map_dicts
    results["findings"]      = [_finding_dict(f) for f in findings]

    # Phase 4: XML fuzzing
    fuzz_per_target = None
    if not getattr(args, "skip_fuzz", False):
        fuzz_dicts, fuzz_findings, fuzz_per_target = cmd_fuzz(
            args, targets=targets, map_results=map_results)
        findings.extend(fuzz_findings)
        results["fuzz_results"] = fuzz_dicts
        results["findings"]     = [_finding_dict(f) for f in findings]

    # Normalized cross-protocol schema (der_common.AttackSurface per target)
    from der_sep2.adapter import build_attack_surface
    used_cert = bool(getattr(args, "client_cert", None))
    surfaces = []
    for i, mr in enumerate(map_results):
        prof = profiles[i] if i < len(profiles) else None
        ff   = fuzz_per_target[i] if (fuzz_per_target and i < len(fuzz_per_target)) else None
        surfaces.append(build_attack_surface(
            mr, tls_profile=prof, used_cert=used_cert,
            fuzz_findings=ff, generated_at=results["generated_at"],
        ).model_dump())
    results["attack_surfaces"] = surfaces

    # Summary
    print(f"\n{'═'*50}")
    print("  SUMMARY")
    print(f"{'═'*50}")
    print(f"  Targets found   : {len(targets)}")
    print(f"  TLS profiles    : {len(profiles)}")
    print(f"  Total findings  : {len(findings)}")
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
        count = sum(1 for f in findings if f.severity == sev)
        if count:
            color = SEV_COLORS[sev]
            print(f"    {color}{sev.value:8s}{RESET}: {count}")
    print()

    if hasattr(args, "output") and args.output:
        out_path = Path(args.output)
        out_path.write_text(json.dumps(results, indent=2, default=str))
        print(f"  Results saved to: {out_path}")


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog        = "der_sep2",
        description = "IEEE 2030.5 (SEP 2.0) security mapper and fuzzer",
    )
    parser.add_argument("-v", "--verbose", action="store_true")

    sub = parser.add_subparsers(dest="command", required=True)

    # ── discover ──────────────────────────────────────────────────────
    disc = sub.add_parser("discover", help="Run discovery phase only")
    disc.add_argument("--scan", nargs="+", metavar="CIDR",
                      help="IP ranges to port scan (e.g. 192.168.1.0/24)")
    disc.add_argument("--ports",        default=None,
                      help="Comma-separated ports (default: 15388,443,8443)")
    disc.add_argument("--nameserver",   default=None)
    disc.add_argument("--domains",      nargs="+", default=["local"])
    disc.add_argument("--no-mdns",      action="store_true")
    disc.add_argument("--no-dns-sd",    action="store_true")
    disc.add_argument("--mdns-timeout", type=float, default=5.0)

    # ── tls ───────────────────────────────────────────────────────────
    tls_p = sub.add_parser("tls", help="TLS profile a single target")
    tls_p.add_argument("host")
    tls_p.add_argument("--port",        type=int,   default=15388)
    tls_p.add_argument("--hostname",    default=None)
    tls_p.add_argument("--client-cert", default=None, metavar="PEM")
    tls_p.add_argument("--client-key",  default=None, metavar="PEM")
    tls_p.add_argument("--ca-bundle",   default=None, metavar="PEM")
    tls_p.add_argument("--timeout",     type=float, default=5.0)

    # ── map ───────────────────────────────────────────────────────────
    map_p = sub.add_parser("map", help="Map resources on a single target")
    map_p.add_argument("host")
    map_p.add_argument("--port",              type=int,   default=15388)
    map_p.add_argument("--hostname",          default=None)
    map_p.add_argument("--base-path",         default="/dcap")
    map_p.add_argument("--client-cert",       default=None, metavar="PEM",
                       help="Registered client cert (Probe D)")
    map_p.add_argument("--client-key",        default=None, metavar="PEM")
    map_p.add_argument("--client-cert-unreg", default=None, metavar="PEM",
                       help="Unregistered client cert (Probe C) — CA-signed but "
                            "LFDI not in server ACL. If omitted, Probe C falls back "
                            "to a self-signed cert (same as Probe B).")
    map_p.add_argument("--client-key-unreg",  default=None, metavar="PEM")
    map_p.add_argument("--ca-bundle",         default=None, metavar="PEM")
    map_p.add_argument("--timeout",           type=float, default=10.0)
    map_p.add_argument("--rate-limit",        type=float, default=5.0,
                       help="Max requests/sec (default 5 — lower for embedded targets)")
    map_p.add_argument("--max-depth",         type=int,   default=8,
                       help="Max href-follow recursion depth")
    map_p.add_argument("--skip-methods",      action="store_true",
                       help="Skip HTTP method probing (faster)")
    map_p.add_argument("--output",            default=None, metavar="FILE")

    # ── run (full pipeline) ───────────────────────────────────────────
    run_p = sub.add_parser("run", help="Full discovery → TLS → map pipeline")
    run_p.add_argument("--scan",              nargs="+", metavar="CIDR")
    run_p.add_argument("--ports",             default=None)
    run_p.add_argument("--nameserver",        default=None)
    run_p.add_argument("--domains",           nargs="+", default=["local"])
    run_p.add_argument("--no-mdns",           action="store_true")
    run_p.add_argument("--no-dns-sd",         action="store_true")
    run_p.add_argument("--mdns-timeout",      type=float, default=5.0)
    run_p.add_argument("--client-cert",       default=None, metavar="PEM",
                       help="Registered client cert (Probe D)")
    run_p.add_argument("--client-key",        default=None, metavar="PEM")
    run_p.add_argument("--client-cert-unreg", default=None, metavar="PEM",
                       help="Unregistered client cert (Probe C)")
    run_p.add_argument("--client-key-unreg",  default=None, metavar="PEM")
    run_p.add_argument("--ca-bundle",         default=None, metavar="PEM")
    run_p.add_argument("--timeout",           type=float, default=10.0)
    run_p.add_argument("--rate-limit",        type=float, default=5.0)
    run_p.add_argument("--max-depth",         type=int,   default=8)
    run_p.add_argument("--skip-methods",      action="store_true")
    run_p.add_argument("--skip-fuzz",         action="store_true",
                       help="Skip the XML fuzzing phase")
    run_p.add_argument("--fuzz-rate-limit",   type=float, default=2.0,
                       help="Max requests/sec during fuzzing (default 2)")
    run_p.add_argument("--callback-host",     default="127.0.0.1",
                       help="Host to use in XXE SSRF payloads (your listener)")
    run_p.add_argument("--callback-port",     type=int, default=9999,
                       help="Port to use in XXE SSRF payloads")
    run_p.add_argument("--fuzz-classes",      nargs="+", default=None,
                       metavar="CLASS",
                       help="Limit fuzzing to specific vuln classes: "
                            "billion_laughs quadratic_blowup xxe_file_disclosure "
                            "xxe_ssrf xxe_dtd_external oversized_payload "
                            "deep_nesting malformed_xml namespace_confusion")
    run_p.add_argument("--authorized-scope",  nargs="+", metavar="CIDR", default=None,
                       help="IPs/CIDRs you are authorized to test (required unless "
                            "--skip-fuzz)")
    run_p.add_argument("--allow-disruptive",  action="store_true",
                       help="Confirm you accept that fuzzing can crash the target "
                            "(required unless --skip-fuzz)")
    run_p.add_argument("--output",            default="sep2_results.json", metavar="FILE")

    # ── fuzz (standalone fuzzing against a known target) ──────────────
    fuzz_p = sub.add_parser("fuzz", help="XML fuzzing phase against a single target")
    fuzz_p.add_argument("host")
    fuzz_p.add_argument("--port",             type=int,   default=15388)
    fuzz_p.add_argument("--hostname",         default=None)
    fuzz_p.add_argument("--client-cert",      default=None, metavar="PEM")
    fuzz_p.add_argument("--client-key",       default=None, metavar="PEM")
    fuzz_p.add_argument("--ca-bundle",        default=None, metavar="PEM")
    fuzz_p.add_argument("--timeout",          type=float, default=10.0)
    fuzz_p.add_argument("--rate-limit",       type=float, default=2.0)
    fuzz_p.add_argument("--callback-host",    default="127.0.0.1")
    fuzz_p.add_argument("--callback-port",    type=int,   default=9999)
    fuzz_p.add_argument("--fuzz-classes",     nargs="+",  default=None,
                        metavar="CLASS",
                        help="Limit to specific vuln classes (see 'run --help')")
    fuzz_p.add_argument("--output",           default=None, metavar="FILE")
    fuzz_p.add_argument("--skip-xml-fuzz",   action="store_true",
                        help="Skip XML fuzzing (billion laughs, XXE, etc.)")
    fuzz_p.add_argument("--skip-http-fuzz",  action="store_true",
                        help="Skip HTTP fuzzing (IDOR, pagination)")
    fuzz_p.add_argument("--idor-range",      type=int, default=10,
                        help="How many adjacent IDs to probe for IDOR (default 10)")
    fuzz_p.add_argument("--authorized-scope", nargs="+", metavar="CIDR", default=None,
                        help="IPs/CIDRs you are authorized to test (required)")
    fuzz_p.add_argument("--allow-disruptive", action="store_true",
                        help="Confirm you accept that fuzzing can crash the target")

    return parser


# ---------------------------------------------------------------------------
# Sub-command: fuzz
# ---------------------------------------------------------------------------

def cmd_fuzz(
    args:           argparse.Namespace,
    targets:        list[ServiceTarget] | None = None,
    map_results:    list | None                = None,
) -> tuple[list[dict], list[Finding]]:
    from der_common.scope import assert_in_scope, require_disruptive_consent
    from der_sep2.fuzzing.http_fuzzer import HTTPFuzzer, print_http_fuzzing_result
    from der_sep2.fuzzing.xml_fuzzer import XMLFuzzer, print_fuzzing_result
    from der_sep2.fuzzing.xml_payloads import VulnClass

    log = logging.getLogger("cli.fuzz")

    if targets is None:
        targets = [ServiceTarget(
            ip       = args.host,
            port     = args.port,
            hostname = getattr(args, "hostname", None) or args.host,
        )]

    # Fail closed: every target must be in-scope and disruptive consent explicit,
    # same gate der-dnp3 fuzz / der-sunspec fuzz enforce.
    require_disruptive_consent(getattr(args, "allow_disruptive", False))
    authorized_scope = getattr(args, "authorized_scope", None) or []
    for target in targets:
        assert_in_scope(target.ip, authorized_scope)

    factory = TLSContextFactory(
        ca_bundle   = getattr(args, "ca_bundle",   None),
        client_cert = getattr(args, "client_cert", None),
        client_key  = getattr(args, "client_key",  None),
    )

    # Parse vuln class filter for XML fuzzer
    vuln_classes = None
    raw_classes  = getattr(args, "fuzz_classes", None)
    if raw_classes:
        try:
            vuln_classes = [VulnClass(c) for c in raw_classes]
        except ValueError as e:
            print(f"  Unknown vuln class: {e}")
            sys.exit(1)

    skip_xml  = getattr(args, "skip_xml_fuzz",  False)
    skip_http = getattr(args, "skip_http_fuzz",  False)

    all_fuzz_dicts: list[dict]    = []
    all_findings:   list[Finding] = []
    per_target_findings: list[list[Finding]] = []

    for i, target in enumerate(targets):
        mapping_result = map_results[i] if map_results and i < len(map_results) else None
        target_dict: dict = {"target": f"{target.ip}:{target.port}"}
        target_findings: list[Finding] = []

        # ── XML fuzzing ───────────────────────────────────────────────
        if not skip_xml:
            log.info(f"XML fuzzing {target.ip}:{target.port}")
            xml_fuzzer = XMLFuzzer(
                target          = target,
                context_factory = factory,
                mapping_result  = mapping_result,
                rate_limit_rps  = getattr(args, "fuzz_rate_limit",
                                  getattr(args, "rate_limit", 2.0)),
                timeout         = args.timeout,
                callback_host   = getattr(args, "callback_host", "127.0.0.1"),
                callback_port   = getattr(args, "callback_port", 9999),
                vuln_classes    = vuln_classes,
            )
            xml_result = xml_fuzzer.run()
            print_fuzzing_result(xml_result)
            all_findings.extend(xml_result.findings)
            target_findings.extend(xml_result.findings)
            target_dict["xml_payloads_sent"] = len(xml_result.results)
            target_dict["xml_findings"] = [
                _finding_dict(f) for f in xml_result.findings
            ]

        # ── HTTP fuzzing ──────────────────────────────────────────────
        if not skip_http:
            log.info(f"HTTP fuzzing {target.ip}:{target.port}")
            http_fuzzer = HTTPFuzzer(
                target          = target,
                context_factory = factory,
                mapping_result  = mapping_result,
                rate_limit_rps  = getattr(args, "fuzz_rate_limit",
                                  getattr(args, "rate_limit", 3.0)),
                timeout         = args.timeout,
                idor_range      = getattr(args, "idor_range", 10),
            )
            http_result = http_fuzzer.run()
            print_http_fuzzing_result(http_result)
            all_findings.extend(http_result.findings)
            target_findings.extend(http_result.findings)
            target_dict["idor_probes"]    = len(http_result.idor_results)
            target_dict["pag_probes"]     = len(http_result.pagination_results)
            target_dict["http_findings"]  = [
                _finding_dict(f) for f in http_result.findings
            ]

        all_fuzz_dicts.append(target_dict)
        per_target_findings.append(target_findings)

    return all_fuzz_dicts, all_findings, per_target_findings


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = _build_parser()
    args   = parser.parse_args()
    _setup_logging(args.verbose)
    _print_banner()

    try:
        if args.command == "discover":
            cmd_discover(args)
        elif args.command == "tls":
            cmd_tls(args)
        elif args.command == "map":
            result_dicts, findings, map_results = cmd_map(args)
            if getattr(args, "output", None):
                from der_sep2.adapter import build_attack_surface
                gen = datetime.now(tz=timezone.utc).isoformat()
                used_cert = bool(getattr(args, "client_cert", None))
                surfaces = [
                    build_attack_surface(mr, used_cert=used_cert, generated_at=gen).model_dump()
                    for mr in map_results
                ]
                out = {
                    "generated_at": gen,
                    "attack_surfaces": surfaces,
                    "resource_maps": result_dicts,
                    "findings": [_finding_dict(f) for f in findings],
                }
                Path(args.output).write_text(json.dumps(out, indent=2, default=str))
                print(f"  Results saved to: {args.output}")
        elif args.command == "fuzz":
            fuzz_dicts, findings, _ = cmd_fuzz(args)
            if getattr(args, "output", None):
                out = {
                    "generated_at": datetime.now(tz=timezone.utc).isoformat(),
                    "fuzz_results": fuzz_dicts,
                    "findings": [_finding_dict(f) for f in findings],
                }
                Path(args.output).write_text(json.dumps(out, indent=2, default=str))
                print(f"  Results saved to: {args.output}")
        elif args.command == "run":
            cmd_run(args)
    except Exception as e:
        print(f"error: {type(e).__name__}: {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
