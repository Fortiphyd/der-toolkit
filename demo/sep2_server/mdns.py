"""
mdns.py
───────
Advertise the SEP 2.0 test server via mDNS / DNS-SD so the mapper's
discovery phase can find it automatically.

Service type: _2030-5._tcp.local.
This matches the IEEE 2030.5 DNS-SD profile and is what most
conformant SEP2 clients scan for.

Requires:  pip install zeroconf
"""

import logging
import socket
import threading

log = logging.getLogger(__name__)

try:
    from zeroconf import ServiceInfo, Zeroconf
    _ZEROCONF_AVAILABLE = True
except ImportError:
    _ZEROCONF_AVAILABLE = False
    log.warning(
        "zeroconf package not installed – mDNS advertisement disabled. "
        "Install with: pip install zeroconf"
    )


_zc: "Zeroconf | None" = None
_info: "ServiceInfo | None" = None


def _local_ip() -> str:
    """Best-effort: return the primary non-loopback IPv4 address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def start(service_name: str, port: int):
    """
    Register the service in a background thread.
    Does nothing (with a warning) if zeroconf is not installed.
    """
    if not _ZEROCONF_AVAILABLE:
        return

    global _zc, _info

    ip = _local_ip()
    # Service type per IEEE 2030.5 §10.3 and IANA registration:
    #   _smartenergy._tcp
    # Instance name format: <instance>._smartenergy._tcp.<domain>.
    SERVICE_TYPE = "_smartenergy._tcp.local."
    fqsn = f"{service_name}.{SERVICE_TYPE}"

    _info = ServiceInfo(
        type_=SERVICE_TYPE,
        name=fqsn,
        addresses=[socket.inet_aton(ip)],
        port=port,
        properties={
            b"path": b"/dcap",
            b"version": b"2030.5",
        },
        server=f"{socket.gethostname()}.local.",
    )

    def _register():
        global _zc
        _zc = Zeroconf()
        _zc.register_service(_info)
        log.info(
            "mDNS: advertising  %s  at %s:%d  (_smartenergy._tcp.local.)",
            service_name, ip, port,
        )

    t = threading.Thread(target=_register, daemon=True)
    t.start()


def stop():
    """Unregister the mDNS service gracefully."""
    global _zc, _info
    if _zc and _info:
        try:
            _zc.unregister_service(_info)
            _zc.close()
            log.info("mDNS: service unregistered")
        except Exception as exc:
            log.warning("mDNS shutdown error: %s", exc)
    _zc = None
    _info = None
