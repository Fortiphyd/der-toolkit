#!/usr/bin/env python3
"""
server.py  –  IEEE 2030.5 (SEP 2.0) Test Server
═════════════════════════════════════════════════
A purpose-built test target for SEP2 security mappers / fuzzers.

Usage
─────
  # Normal run
  python server.py

  # Override config file
  python server.py --config /path/to/config.yaml

  # Print the LFDI of a certificate (useful for populating acl.registered_lfdis)
  python server.py --show-lfdi certs/client_registered.crt

  # Dump the effective config and exit
  python server.py --dump-config

Probe types produced by a mapper
─────────────────────────────────
  A – no client cert           → 401 on cert-required resources
  B – self-signed cert         → 401 if validate_cert_chain=true; pass if false
  C – valid cert, unregistered → 404 on registration-required resources
  D – valid cert, registered   → 200 on all resources
"""

import argparse
import hashlib
import logging
import os
import signal
import sys

import yaml
from flask import Flask

import mdns
import routes
import ssl_server

# ──────────────────────────────────────────────────────────────────────────────
# Logging
# ──────────────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s  %(levelname)-7s  %(name)s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("sep2.server")

# Silence noisy internal loggers
logging.getLogger("werkzeug").setLevel(logging.WARNING)


# ──────────────────────────────────────────────────────────────────────────────
# Config helpers
# ──────────────────────────────────────────────────────────────────────────────

def load_config(path: str) -> dict:
    with open(path) as f:
        cfg = yaml.safe_load(f)
    return cfg


def apply_log_level(cfg: dict):
    level = cfg.get("server", {}).get("log_level", "INFO").upper()
    logging.getLogger().setLevel(getattr(logging, level, logging.INFO))


# ──────────────────────────────────────────────────────────────────────────────
# LFDI utility
# ──────────────────────────────────────────────────────────────────────────────

def cert_file_to_lfdi(cert_path: str) -> str:
    """
    Compute LFDI from a PEM certificate file.
    LFDI = first 40 hex chars (upper) of SHA-256(DER-encoded cert)
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding
        with open(cert_path, "rb") as f:
            pem = f.read()
        cert = x509.load_pem_x509_certificate(pem)
        der = cert.public_bytes(Encoding.DER)
        return hashlib.sha256(der).hexdigest()[:40].upper()
    except ImportError:
        # Fallback: strip PEM headers and decode base64
        import base64, re
        with open(cert_path, "r") as f:
            pem_text = f.read()
        b64 = re.sub(r"-----[^-]+-----|\s", "", pem_text)
        der = base64.b64decode(b64)
        return hashlib.sha256(der).hexdigest()[:40].upper()


# ──────────────────────────────────────────────────────────────────────────────
# Flask app factory
# ──────────────────────────────────────────────────────────────────────────────

def create_app(cfg: dict) -> Flask:
    app = Flask(__name__)
    app.config["SEP2_CFG"] = cfg
    app.register_blueprint(routes.bp)
    return app


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="IEEE 2030.5 test server")
    parser.add_argument("--config",      default="config.yaml", help="Path to config.yaml")
    parser.add_argument("--show-lfdi",   metavar="CERT",        help="Print LFDI of a PEM cert and exit")
    parser.add_argument("--dump-config", action="store_true",   help="Print effective config and exit")
    args = parser.parse_args()

    # ── Utility modes ─────────────────────────────────────────────────────────
    if args.show_lfdi:
        lfdi = cert_file_to_lfdi(args.show_lfdi)
        print(f"\nLFDI for {args.show_lfdi}:\n  {lfdi}\n")
        print("Add this to config.yaml  acl.registered_lfdis  to register the device.")
        sys.exit(0)

    cfg = load_config(args.config)
    apply_log_level(cfg)

    if args.dump_config:
        import json
        print(json.dumps(cfg, indent=2))
        sys.exit(0)

    # ── Summary banner ────────────────────────────────────────────────────────
    srv_cfg = cfg.get("server", {})
    tls_cfg = cfg.get("tls", {})
    acl_cfg = cfg.get("acl", {})
    vul_cfg = cfg.get("vulnerability", {})

    host = srv_cfg.get("host", "0.0.0.0")
    port = srv_cfg.get("port", 8443)

    log.info("══════════════════════════════════════════════════════")
    log.info("  IEEE 2030.5 Test Server")
    log.info("  Listening  https://%s:%d", host, port)
    log.info("  mTLS enforce (app) : %s  (TLS layer always CERT_OPTIONAL)", tls_cfg.get("enforce_mtls", True))
    log.info("  Chain validation  : %s", tls_cfg.get("validate_cert_chain", True))
    log.info("  Registration enf. : %s", acl_cfg.get("enforce_registration", True))
    open_res = vul_cfg.get("open_resources", [])
    if open_res:
        log.warning("  ⚠  open_resources overrides active: %s", open_res)
    registered = acl_cfg.get("registered_lfdis", [])
    log.info("  Registered LFDIs  : %d configured", len(registered))
    for lfdi in registered:
        log.info("    • %s", lfdi)
    log.info("══════════════════════════════════════════════════════")

    # ── Warn about missing certs ──────────────────────────────────────────────
    for key in ("cert_file", "key_file"):
        path = tls_cfg.get(key)
        if path and not os.path.exists(path):
            log.error("TLS file not found: %s  (run gen_certs.sh first)", path)
            sys.exit(1)

    # ── Build Flask app & SSL context ─────────────────────────────────────────
    app     = create_app(cfg)
    ssl_ctx = ssl_server.build_ssl_context(cfg)
    httpd   = ssl_server.make_server(host, port, app, ssl_ctx)

    # ── mDNS advertisement ────────────────────────────────────────────────────
    mdns_cfg = cfg.get("mdns", {})
    if mdns_cfg.get("enabled", True):
        mdns.start(mdns_cfg.get("service_name", "SEP2-TestServer"), port)

    # ── Graceful shutdown ─────────────────────────────────────────────────────
    def _shutdown(sig, frame):
        log.info("Shutting down…")
        mdns.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    log.info("Server ready.  Ctrl-C to stop.")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
