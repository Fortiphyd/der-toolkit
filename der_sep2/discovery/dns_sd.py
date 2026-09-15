"""
der_sep2.discovery.dns_sd
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
IEEE 2030.5 service discovery via DNS-SD (RFC 6763) and mDNS (RFC 6762).

Implements both:
  - Unicast DNS-SD  (via dnspython) for site-scoped deployments
  - mDNS probing    (via zeroconf)  for link-local / HAN deployments

Produces a deduplicated list of ServiceTarget objects ready for the
TLS and HTTP phases.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from der_sep2.models import ServiceTarget

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# 2030.5 service type definitions
# Each entry is (service_type, description, function_set_key)
# ---------------------------------------------------------------------------

SEP2_SERVICE_TYPES: list[tuple[str, str, str]] = [
    ("_2030-5._tcp",      "IEEE 2030.5 base server",        "base"),
    ("_2030-5-der._tcp",  "DER function set",               "der"),
    ("_2030-5-dr._tcp",   "Demand Response function set",   "dr"),
    ("_2030-5-ps._tcp",   "Pricing function set",           "ps"),
    ("_2030-5-msg._tcp",  "Messaging function set",         "msg"),
    ("_2030-5-bill._tcp", "Billing function set",           "bill"),
    ("_2030-5-metr._tcp", "Metering function set",          "metr"),
]

DEFAULT_PORT     = 15388
DEFAULT_TIMEOUT  = 3.0   # seconds


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

@dataclass
class DiscoveredService:
    """
    Raw DNS-SD result before IP resolution.  Converted to ServiceTarget
    by the resolver step.
    """
    instance_name:  str
    service_type:   str
    hostname:       str
    port:           int
    ip_addresses:   list[str]         = field(default_factory=list)
    txt_properties: dict[str, str]    = field(default_factory=dict)
    source:         str               = "dns_sd"   # or "mdns"

    @property
    def base_path(self) -> str:
        return self.txt_properties.get("path", "/dcap")

    @property
    def tls(self) -> bool:
        ssl_val = self.txt_properties.get("ssl", "1")
        return ssl_val not in ("0", "false", "no")


# ---------------------------------------------------------------------------
# TXT record parser
# ---------------------------------------------------------------------------

def _parse_txt_record(txt_strings: list[bytes]) -> dict[str, str]:
    """
    Parse a DNS TXT record into a key=value dict.
    RFC 6763 §6: each string is either "key=value" or a bare "key".
    """
    result = {}
    for item in txt_strings:
        try:
            s = item.decode("utf-8", errors="replace")
        except AttributeError:
            s = str(item)
        if "=" in s:
            k, _, v = s.partition("=")
            result[k.strip().lower()] = v.strip()
        else:
            result[s.strip().lower()] = ""
    return result


# ---------------------------------------------------------------------------
# Unicast DNS-SD discovery
# ---------------------------------------------------------------------------

class UnicastDNSDiscovery:
    """
    Queries a real DNS server (unicast) for 2030.5 PTR/SRV/TXT records.
    Works for enterprise/utility deployments where DNS-SD is properly
    configured in the site DNS.
    """

    def __init__(
        self,
        nameserver:     str | None = None,
        domains:        list[str] | None = None,
        timeout:        float = DEFAULT_TIMEOUT,
    ):
        """
        Args:
            nameserver:  Override the system resolver (e.g. "192.168.1.1")
            domains:     Domains to search, e.g. ["example.com", "local"]
                         Defaults to ["local"] if not specified.
            timeout:     DNS query timeout in seconds.
        """
        try:
            import dns.rdatatype
            import dns.resolver
            self._dns = dns
        except ImportError:
            raise ImportError(
                "dnspython is required for unicast DNS-SD. "
                "Install with: pip install dnspython"
            )

        self.timeout = timeout
        self.domains = domains or ["local"]
        self._resolver = self._dns.resolver.Resolver()
        self._resolver.lifetime = timeout
        if nameserver:
            self._resolver.nameservers = [nameserver]

    def discover(self) -> list[DiscoveredService]:
        """Run PTR queries for all 2030.5 service types across all domains."""
        found: list[DiscoveredService] = []

        for svc_type, description, _ in SEP2_SERVICE_TYPES:
            for domain in self.domains:
                query_name = f"{svc_type}.{domain}."
                log.debug(f"[DNS-SD] PTR query: {query_name}")
                instances = self._query_ptr(query_name)

                for instance_name in instances:
                    log.info(f"[DNS-SD] Found instance: {instance_name} ({description})")
                    svc = self._resolve_instance(instance_name, svc_type)
                    if svc:
                        found.append(svc)

        return _deduplicate(found)

    def _query_ptr(self, query_name: str) -> list[str]:
        try:
            answers = self._resolver.resolve(query_name, "PTR")
            return [str(r.target) for r in answers]
        except Exception as e:
            log.debug(f"[DNS-SD] PTR query failed for {query_name}: {e}")
            return []

    def _resolve_instance(
        self, instance_name: str, svc_type: str
    ) -> DiscoveredService | None:
        hostname, port = self._query_srv(instance_name)
        if not hostname:
            return None

        txt_raw  = self._query_txt(instance_name)
        txt_props = _parse_txt_record(txt_raw)
        ips       = self._resolve_host(hostname)

        return DiscoveredService(
            instance_name  = instance_name,
            service_type   = svc_type,
            hostname        = hostname.rstrip("."),
            port            = port,
            ip_addresses    = ips,
            txt_properties  = txt_props,
            source          = "dns_sd",
        )

    def _query_srv(self, name: str) -> tuple[str | None, int]:
        try:
            answers = self._resolver.resolve(name, "SRV")
            r = answers[0]   # use highest-priority record
            return str(r.target), int(r.port)
        except Exception as e:
            log.debug(f"[DNS-SD] SRV query failed for {name}: {e}")
            return None, DEFAULT_PORT

    def _query_txt(self, name: str) -> list[bytes]:
        try:
            answers = self._resolver.resolve(name, "TXT")
            result = []
            for r in answers:
                result.extend(r.strings)
            return result
        except Exception as e:
            log.debug(f"[DNS-SD] TXT query failed for {name}: {e}")
            return []

    def _resolve_host(self, hostname: str) -> list[str]:
        ips = []
        for rdtype in ("A", "AAAA"):
            try:
                answers = self._resolver.resolve(hostname, rdtype)
                ips.extend(str(r.address) for r in answers)
            except Exception:
                pass
        return ips


# ---------------------------------------------------------------------------
# mDNS discovery
# ---------------------------------------------------------------------------

class MDNSDiscovery:
    """
    Sends mDNS queries to 224.0.0.251:5353 on the local link.
    Discovers 2030.5 servers that haven't been registered in any DNS server —
    typical of HAN devices (meters, gateways, EV chargers).

    Uses the `zeroconf` library for the heavy lifting, but can also fall back
    to a raw socket approach if zeroconf is unavailable.
    """

    def __init__(
        self,
        timeout:    float = 5.0,
        interface:  str | None = None,
    ):
        self.timeout   = timeout
        self.interface = interface

    def discover(self) -> list[DiscoveredService]:
        try:
            return self._discover_zeroconf()
        except ImportError:
            log.warning(
                "zeroconf not installed; falling back to raw mDNS socket. "
                "Install with: pip install zeroconf"
            )
            return self._discover_raw()

    def _discover_zeroconf(self) -> list[DiscoveredService]:
        from zeroconf import ServiceBrowser, ServiceInfo, Zeroconf

        found: list[DiscoveredService] = []

        class _Listener:
            def add_service(self_, zc: Zeroconf, svc_type: str, name: str):
                info: ServiceInfo = zc.get_service_info(svc_type, name)
                if not info:
                    return
                txt_props = {
                    k.decode(): v.decode() if isinstance(v, bytes) else str(v)
                    for k, v in (info.properties or {}).items()
                    if isinstance(k, bytes)
                }
                ips = [str(ipaddress.ip_address(a)) for a in info.addresses]
                svc = DiscoveredService(
                    instance_name  = name,
                    service_type   = svc_type.rstrip("."),
                    hostname       = (info.server or "").rstrip("."),
                    port           = info.port or DEFAULT_PORT,
                    ip_addresses   = ips,
                    txt_properties = txt_props,
                    source         = "mdns",
                )
                found.append(svc)
                log.info(
                    f"[mDNS] Found: {name} @ "
                    f"{', '.join(ips)}:{info.port}"
                )

            def remove_service(self_, *_): pass
            def update_service(self_, *_): pass

        zc       = Zeroconf()
        listener = _Listener()
        # Must stay referenced for the scan's duration -- each ServiceBrowser's
        # background listener thread stops firing if the object is GC'd.
        browsers = [  # noqa: F841
            ServiceBrowser(zc, f"{svc_type}.local.", listener)
            for svc_type, _, _ in SEP2_SERVICE_TYPES
        ]

        time.sleep(self.timeout)
        zc.close()

        return _deduplicate(found)

    def _discover_raw(self) -> list[DiscoveredService]:
        """
        Minimal raw-socket mDNS query as a fallback.
        Sends a DNS PTR query to the mDNS multicast group and collects
        responses for up to `timeout` seconds.

        Note: response parsing here is intentionally minimal — install
        zeroconf for full support.
        """
        import struct

        MDNS_ADDR = "224.0.0.251"
        MDNS_PORT = 5353

        def _build_ptr_query(service_type: str) -> bytes:
            # Build a minimal DNS PTR query packet
            name  = service_type + ".local."
            parts = name.split(".")
            qname = b""
            for part in parts:
                if part:
                    encoded = part.encode()
                    qname  += bytes([len(encoded)]) + encoded
            qname += b"\x00"
            header = struct.pack(">HHHHHH", 0x0001, 0x0000, 1, 0, 0, 0)
            qtype  = struct.pack(">HH", 12, 1)   # PTR, IN
            return header + qname + qtype

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(self.timeout)
        sock.bind(("", MDNS_PORT))

        # Join multicast group
        mreq = socket.inet_aton(MDNS_ADDR) + socket.inet_aton("0.0.0.0")
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

        # Send queries
        for svc_type, _, _ in SEP2_SERVICE_TYPES:
            try:
                pkt = _build_ptr_query(svc_type)
                sock.sendto(pkt, (MDNS_ADDR, MDNS_PORT))
            except Exception as e:
                log.debug(f"[mDNS raw] Send failed for {svc_type}: {e}")

        found_ips: list[DiscoveredService] = []
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            try:
                data, (src_ip, _) = sock.recvfrom(4096)
                log.info(f"[mDNS raw] Got response from {src_ip} ({len(data)} bytes)")
                # Minimal: record the IP and port, full parse needs zeroconf
                found_ips.append(DiscoveredService(
                    instance_name  = f"raw-{src_ip}",
                    service_type   = "_2030-5._tcp",
                    hostname       = src_ip,
                    port           = DEFAULT_PORT,
                    ip_addresses   = [src_ip],
                    txt_properties = {},
                    source         = "mdns_raw",
                ))
            except TimeoutError:
                break
            except Exception as e:
                log.debug(f"[mDNS raw] Recv error: {e}")

        sock.close()
        return _deduplicate(found_ips)


# ---------------------------------------------------------------------------
# Port-scan-based fallback discovery
# ---------------------------------------------------------------------------

class PortScanner:
    """
    TCP connect scan across a list of hosts and candidate ports.
    Runs after DNS-SD to catch servers that don't advertise themselves.
    """

    SEP2_PORTS = [15388, 443, 8443, 8080, 8888, 5000, 5001]

    def __init__(
        self,
        targets:  list[str],           # CIDRs or individual IPs
        ports:    list[int] | None = None,
        timeout:  float = 1.0,
        workers:  int   = 50,
        on_found: Callable[[str, int], None] | None = None,
    ):
        self.targets  = targets
        self.ports    = ports or self.SEP2_PORTS
        self.timeout  = timeout
        self.workers  = workers
        self.on_found = on_found

    def scan(self) -> list[DiscoveredService]:
        """Expand CIDRs, probe each (ip, port) pair, return open ones."""
        from concurrent.futures import ThreadPoolExecutor, as_completed

        pairs = list(self._expand_targets())
        log.info(f"[PortScan] Scanning {len(pairs)} (ip, port) pairs "
                 f"with {self.workers} workers")

        found: list[DiscoveredService] = []

        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            futures = {pool.submit(self._probe, ip, port): (ip, port)
                       for ip, port in pairs}
            for future in as_completed(futures):
                ip, port = futures[future]
                try:
                    open_ = future.result()
                except Exception:
                    open_ = False
                if open_:
                    log.info(f"[PortScan] Open: {ip}:{port}")
                    if self.on_found:
                        self.on_found(ip, port)
                    found.append(DiscoveredService(
                        instance_name  = f"portscan-{ip}-{port}",
                        service_type   = "_2030-5._tcp",
                        hostname       = ip,
                        port           = port,
                        ip_addresses   = [ip],
                        txt_properties = {},
                        source         = "port_scan",
                    ))

        return found

    def _probe(self, ip: str, port: int) -> bool:
        try:
            with socket.create_connection((ip, port), timeout=self.timeout):
                return True
        except (TimeoutError, ConnectionRefusedError, OSError):
            return False

    def _expand_targets(self):
        for target in self.targets:
            try:
                network = ipaddress.ip_network(target, strict=False)
                for ip in network.hosts():
                    for port in self.ports:
                        yield str(ip), port
            except ValueError:
                for port in self.ports:
                    yield target, port


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class DiscoveryOrchestrator:
    """
    Runs DNS-SD, mDNS, and port scanning and merges results into a
    deduplicated list of ServiceTarget objects.
    """

    def __init__(
        self,
        nameserver:   str | None       = None,
        domains:      list[str] | None = None,
        scan_targets: list[str] | None = None,
        scan_ports:   list[int] | None = None,
        mdns_timeout: float               = 5.0,
        dns_timeout:  float               = 3.0,
        scan_timeout: float               = 1.0,
        skip_mdns:    bool                = False,
        skip_dns_sd:  bool                = False,
        skip_scan:    bool                = False,
    ):
        self.nameserver   = nameserver
        self.domains      = domains
        self.scan_targets = scan_targets or []
        self.scan_ports   = scan_ports
        self.mdns_timeout = mdns_timeout
        self.dns_timeout  = dns_timeout
        self.scan_timeout = scan_timeout
        self.skip_mdns    = skip_mdns
        self.skip_dns_sd  = skip_dns_sd
        self.skip_scan    = skip_scan

    def run(self) -> list[ServiceTarget]:
        all_services: list[DiscoveredService] = []

        if not self.skip_dns_sd:
            log.info("[Discovery] Starting unicast DNS-SD")
            try:
                dns_disc = UnicastDNSDiscovery(
                    nameserver=self.nameserver,
                    domains=self.domains,
                    timeout=self.dns_timeout,
                )
                results = dns_disc.discover()
                log.info(f"[Discovery] DNS-SD found {len(results)} service(s)")
                all_services.extend(results)
            except Exception as e:
                log.warning(f"[Discovery] DNS-SD failed: {e}")

        if not self.skip_mdns:
            log.info("[Discovery] Starting mDNS discovery")
            try:
                mdns = MDNSDiscovery(timeout=self.mdns_timeout)
                results = mdns.discover()
                log.info(f"[Discovery] mDNS found {len(results)} service(s)")
                all_services.extend(results)
            except Exception as e:
                log.warning(f"[Discovery] mDNS failed: {e}")

        if not self.skip_scan and self.scan_targets:
            log.info(f"[Discovery] Starting port scan of {self.scan_targets}")
            scanner = PortScanner(
                targets=self.scan_targets,
                ports=self.scan_ports,
                timeout=self.scan_timeout,
            )
            results = scanner.scan()
            log.info(f"[Discovery] Port scan found {len(results)} open port(s)")
            all_services.extend(results)

        # Convert to ServiceTarget and deduplicate
        seen:    set[tuple[str, int]] = set()
        targets: list[ServiceTarget]  = []

        for svc in all_services:
            for ip in (svc.ip_addresses or [svc.hostname]):
                key = (ip, svc.port)
                if key in seen:
                    continue
                seen.add(key)
                targets.append(ServiceTarget(
                    ip             = ip,
                    port           = svc.port,
                    base_path      = svc.base_path,
                    hostname       = svc.hostname,
                    tls            = svc.tls,
                    instance_name  = svc.instance_name,
                    service_type   = svc.service_type,
                    txt_properties = svc.txt_properties,
                    source         = svc.source,
                ))

        log.info(
            f"[Discovery] Complete. "
            f"{len(targets)} unique target(s) after deduplication."
        )
        return targets


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _deduplicate(services: list[DiscoveredService]) -> list[DiscoveredService]:
    seen = set()
    result = []
    for svc in services:
        key = (svc.hostname, svc.port)
        if key not in seen:
            seen.add(key)
            result.append(svc)
    return result
