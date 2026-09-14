"""
ssl_server.py
─────────────
A minimal SSL-capable WSGI server built on Python's stdlib wsgiref.
Key feature: injects the raw DER bytes of the client certificate (if any)
into the WSGI environ as 'SSL_CLIENT_CERT_DER' so application code can
compute the LFDI without relying on a reverse proxy.
"""

import ssl
import logging
from wsgiref.simple_server import WSGIServer, WSGIRequestHandler, ServerHandler
from socketserver import ThreadingMixIn

log = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# Quiet the default wsgiref request log – we do our own structured logging
# ──────────────────────────────────────────────────────────────────────────────
class _QuietHandler(WSGIRequestHandler):
    def log_message(self, fmt, *args):  # noqa: D102
        pass  # suppress – Flask/app layer logs instead

    def get_environ(self):
        env = super().get_environ()
        # Inject peer-cert DER bytes stored on the socket object by the server
        peer_der = getattr(self.connection, "_sep2_peer_cert_der", None)
        if peer_der is not None:
            env["SSL_CLIENT_CERT_DER"] = peer_der
        env["wsgi.url_scheme"] = "https"
        return env


class _ThreadedWSGIServer(ThreadingMixIn, WSGIServer):
    """Thread-per-request to avoid blocking during slow TLS handshakes."""
    daemon_threads = True

    # ── hook: called by WSGIServer.get_request() ──────────────────────────────
    def get_request(self):
        raw_sock, client_addr = self.socket.accept()
        # Stash the peer DER on the (already-SSL-wrapped) socket so the handler
        # can pick it up in get_environ() above.
        try:
            der = raw_sock.getpeercert(binary_form=True)
            raw_sock._sep2_peer_cert_der = der  # may be None if no client cert
        except Exception:
            raw_sock._sep2_peer_cert_der = None
        return raw_sock, client_addr


# ──────────────────────────────────────────────────────────────────────────────
# Public factory
# ──────────────────────────────────────────────────────────────────────────────

def build_ssl_context(cfg: dict) -> ssl.SSLContext:
    """
    Build an ssl.SSLContext from the [tls] section of config.yaml.

    The TLS layer ALWAYS uses CERT_OPTIONAL — IEEE 2030.5 has open resources
    (/dcap, /tm, /msg, /ps) that must be reachable without a client cert.
    Per-resource enforcement is handled at the application layer in auth.py.

    validate_cert_chain=true  → CA is loaded; any cert that IS presented must
                                chain to it (self-signed / unknown-CA certs are
                                rejected at TLS handshake time).
    validate_cert_chain=false → CA is NOT loaded; any cert (including
                                self-signed) is accepted by TLS (Probe B passes).

    enforce_mtls is intentionally NOT applied here — it is read by auth.py and
    used to block cert-required routes at the HTTP layer instead.
    """
    tls = cfg["tls"]

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(tls["cert_file"], tls["key_file"])

    # Always OPTIONAL at TLS — application layer enforces per-resource policy.
    ctx.verify_mode = ssl.CERT_OPTIONAL

    validate_chain = tls.get("validate_cert_chain", True)
    if validate_chain and "ca_file" in tls:
        ctx.load_verify_locations(tls["ca_file"])
        log.info(
            "TLS: CERT_OPTIONAL + CA loaded — presented certs must chain to CA; "
            "cert-less connections allowed (open resources reachable as Probe A)"
        )
    else:
        log.warning(
            "TLS: CERT_OPTIONAL + NO CA — self-signed certs accepted at TLS layer "
            "(vulnerability mode: validate_cert_chain=false)"
        )

    version_map = {
        "TLS1_0": ssl.TLSVersion.TLSv1,
        "TLS1_1": ssl.TLSVersion.TLSv1_1,
        "TLS1_2": ssl.TLSVersion.TLSv1_2,
    }
    min_ver = tls.get("minimum_tls_version", "TLS1_2")
    ctx.minimum_version = version_map.get(min_ver, ssl.TLSVersion.TLSv1_2)
    return ctx


def make_server(host: str, port: int, app, ssl_ctx: ssl.SSLContext):
    """Return a ready-to-serve threaded WSGI+TLS server."""
    httpd = _ThreadedWSGIServer((host, port), _QuietHandler)
    httpd.set_app(app)
    # Wrap the listening socket *after* binding so SO_REUSEADDR works
    httpd.socket = ssl_ctx.wrap_socket(httpd.socket, server_side=True)
    return httpd
