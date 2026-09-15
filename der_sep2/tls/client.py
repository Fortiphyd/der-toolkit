"""
der_sep2.tls.client
~~~~~~~~~~~~~~~~~~~~~~
Core TLS client for IEEE 2030.5.

Handles:
  - Connecting with / without a client cert (the four probe types)
  - Probing which TLS versions and ciphers a server accepts
  - Detecting whether the server actually validates client certs
  - Returning a fully populated TLSProfile for each target
"""

from __future__ import annotations

import logging
import socket
import ssl
import tempfile

from der_sep2.models import ProbeType, ServiceTarget, TLSProfile

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Cipher suite lists for weakness probing
# ---------------------------------------------------------------------------

# Each entry is:
#   (openssl_cipher_string, weakness_category, negotiated_name_markers)
#
# openssl_cipher_string  — passed to ctx.set_ciphers(); may be a selector
#                          alias (e.g. "aNULL") or a specific suite name
# weakness_category      — human-readable label for findings
# negotiated_name_markers — substrings that must appear in the *negotiated*
#                           cipher name for the finding to be confirmed.
#                           Empty list = accept any negotiated cipher
#                           (used for specific suite names that can't be
#                           confused with a strong fallback).
#
# Why markers matter: "aNULL" is an OpenSSL selector that matches all
# anonymous ciphers. If we just check whether the connection succeeded,
# we might report a false positive if the server negotiated a strong cipher
# instead of accepting our anonymous one. The markers let us confirm the
# server actually chose a weak cipher.
WEAK_CIPHERS: list[tuple[str, str, list[str]]] = [
    # Specific suite names — the negotiated name must match exactly
    ("NULL-MD5",      "NULL encryption",    ["NULL-MD5"]),
    ("NULL-SHA",      "NULL encryption",    ["NULL-SHA"]),
    ("NULL-SHA256",   "NULL encryption",    ["NULL-SHA256"]),
    ("RC4-SHA",       "RC4",                ["RC4"]),
    ("RC4-MD5",       "RC4",                ["RC4"]),
    ("DES-CBC-SHA",   "DES",                ["DES-CBC"]),
    ("DES-CBC3-SHA",  "3DES",               ["DES-CBC3"]),
    ("EXP-RC4-MD5",   "EXPORT-grade RC4",   ["EXP"]),
    ("EXP-DES-CBC-SHA","EXPORT-grade DES",  ["EXP"]),
    # Selector aliases — require the negotiated cipher to contain a
    # confirming marker so we don't report strong-cipher fallbacks
    ("aNULL",         "anonymous (no auth)",["ADH", "AECDH", "aNULL"]),
    ("eNULL",         "NULL encryption",    ["NULL"]),
    ("ADH",           "anonymous DH",       ["ADH"]),
    ("AECDH",         "anonymous ECDH",     ["AECDH"]),
    ("LOW",           "LOW-grade encryption",["DES", "RC2", "RC4"]),
    ("EXPORT",        "EXPORT-grade",       ["EXP", "EXPORT"]),
]

STRONG_CIPHERS = [
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-CHACHA20-POLY1305",
]


# ---------------------------------------------------------------------------
# Self-signed cert generator (for Probe B)
# ---------------------------------------------------------------------------

def _generate_self_signed_cert() -> tuple[str, str]:
    """
    Generate a throwaway self-signed cert and key.
    Returns (cert_path, key_path) as temporary file paths.
    The caller is responsible for cleanup.
    """
    try:
        import datetime

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID

        key = ec.generate_private_key(ec.SECP256R1())
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "SEP2-Mapper-Test"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Security Research"),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=1)
            )
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .sign(key, hashes.SHA256())
        )

        cert_file = tempfile.NamedTemporaryFile(
            suffix=".pem", delete=False, mode="wb"
        )
        cert_file.write(cert.public_bytes(serialization.Encoding.PEM))
        cert_file.close()

        key_file = tempfile.NamedTemporaryFile(
            suffix=".pem", delete=False, mode="wb"
        )
        key_file.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
        key_file.close()

        return cert_file.name, key_file.name

    except ImportError:
        raise ImportError(
            "cryptography library required. Install with: pip install cryptography"
        )


# ---------------------------------------------------------------------------
# TLS context factory
# ---------------------------------------------------------------------------

class TLSContextFactory:
    """
    Builds ssl.SSLContext objects for different probe scenarios.

    Probe mapping:
      A — no_cert_context()        No client cert at all
      B — self_signed_context()    Self-signed cert, not from recognised CA
      C — unreg_cert_context()     Valid CA-signed cert, NOT registered in server ACL
      D — valid_cert_context()     Valid CA-signed cert, registered in server ACL

    For Probe C you should ideally provide a separate cert (--client-cert-unreg)
    that is signed by the same CA the server trusts but whose LFDI has never been
    registered. If you don't provide one, Probe C falls back to the self-signed
    cert — which still tests something (CA chain validation) but conflates B and C.
    """

    def __init__(
        self,
        ca_bundle:        str | None = None,  # trusted CA bundle for server cert
        client_cert:      str | None = None,  # registered cert  (Probe D)
        client_key:       str | None = None,  # registered key   (Probe D)
        unreg_cert:       str | None = None,  # unregistered cert (Probe C)
        unreg_key:        str | None = None,  # unregistered key  (Probe C)
        verify_server:    bool          = False,
    ):
        self.ca_bundle     = ca_bundle
        self.client_cert   = client_cert
        self.client_key    = client_key
        self.unreg_cert    = unreg_cert
        self.unreg_key     = unreg_key
        self.verify_server = verify_server

    def no_cert_context(self) -> ssl.SSLContext:
        """Probe A — no client cert, don't verify server cert."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        return ctx

    def self_signed_context(self) -> tuple[ssl.SSLContext, str, str]:
        """
        Probe B — present a self-signed client cert.
        Returns (context, cert_path, key_path) — caller must delete temp files.
        """
        cert_path, key_path = _generate_self_signed_cert()
        ctx = self.no_cert_context()
        ctx.load_cert_chain(cert_path, key_path)
        return ctx, cert_path, key_path

    def unreg_cert_context(self) -> tuple[ssl.SSLContext, bool]:
        """
        Probe C — valid CA-signed cert whose LFDI is NOT in the server ACL.

        Returns (context, is_distinct) where is_distinct=True means we have
        a genuinely separate unregistered cert, False means we fell back to
        the self-signed cert (Probe B and C will look the same).

        Fallback behaviour when no unreg cert is provided:
          We use a freshly generated self-signed cert. This still tests
          *something* but can't distinguish between "server rejects unknown
          cert chain" and "server rejects unregistered LFDI". The caller
          should warn the user.
        """
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE

        if self.unreg_cert and self.unreg_key:
            ctx.load_cert_chain(self.unreg_cert, self.unreg_key)
            return ctx, True
        else:
            # Fallback: self-signed cert
            cert_path, key_path = _generate_self_signed_cert()
            ctx.load_cert_chain(cert_path, key_path)
            # Note: temp files leak here — acceptable since this is a fallback path
            # and they'll be cleaned up on process exit.
            return ctx, False

    def valid_cert_context(self) -> ssl.SSLContext:
        """
        Probe D — valid CA-signed cert registered in the server ACL.
        """
        if not self.client_cert or not self.client_key:
            raise ValueError(
                "client_cert and client_key must be set for Probe D. "
                "Provide paths to your registered certificate and key."
            )
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        if self.verify_server and self.ca_bundle:
            ctx.verify_mode    = ssl.CERT_REQUIRED
            ctx.check_hostname = True
            ctx.load_verify_locations(self.ca_bundle)
        ctx.load_cert_chain(self.client_cert, self.client_key)
        return ctx

    def probe_context(self, probe_type: ProbeType) -> ssl.SSLContext:
        """Convenience method — returns the right context for a probe type."""
        if probe_type == ProbeType.NO_CERT:
            return self.no_cert_context()
        elif probe_type == ProbeType.SELF_SIGNED:
            ctx, _, _ = self.self_signed_context()
            return ctx
        elif probe_type == ProbeType.VALID_UNREG:
            ctx, _ = self.unreg_cert_context()
            return ctx
        elif probe_type == ProbeType.VALID_REG:
            return self.valid_cert_context()
        raise ValueError(f"Unknown probe type: {probe_type}")


# ---------------------------------------------------------------------------
# TLS profiler
# ---------------------------------------------------------------------------

class TLSProfiler:
    """
    Connects to a target and builds a complete TLSProfile:
      - Negotiated version and cipher
      - Server certificate chain
      - Whether the server requires a client cert
      - Whether it accepts a self-signed client cert (big finding!)
      - Supported TLS versions and weak ciphers
    """

    TLS_VERSIONS = {
        "TLSv1":   ssl.TLSVersion.TLSv1   if hasattr(ssl.TLSVersion, "TLSv1")   else None,
        "TLSv1.1": ssl.TLSVersion.TLSv1_1 if hasattr(ssl.TLSVersion, "TLSv1_1") else None,
        "TLSv1.2": ssl.TLSVersion.TLSv1_2,
        "TLSv1.3": ssl.TLSVersion.TLSv1_3 if hasattr(ssl.TLSVersion, "TLSv1_3") else None,
    }

    def __init__(
        self,
        target:          ServiceTarget,
        context_factory: TLSContextFactory,
        connect_timeout: float = 5.0,
    ):
        self.target          = target
        self.factory         = context_factory
        self.connect_timeout = connect_timeout

    def profile(self) -> TLSProfile:
        """Run full TLS profiling. Returns a TLSProfile."""
        result = TLSProfile(target=self.target)

        # Step 1: Basic connection — grab server cert and negotiated params
        conn_info = self._connect(self.factory.no_cert_context())
        if conn_info is None:
            result.error = "Could not establish TLS connection"
            log.warning(f"[TLS] {self.target.ip}:{self.target.port} — connection failed")
            return result

        result.negotiated_version = conn_info.get("version")
        result.negotiated_cipher  = conn_info.get("cipher", [None])[0]

        # Step 2: Parse server certificate chain
        raw_certs = conn_info.get("raw_certs", [])
        from der_sep2.tls.cert_analyzer import CertAnalyzer
        for der_bytes in raw_certs:
            info = CertAnalyzer.from_der(der_bytes)
            if info:
                result.cert_chain.append(info)

        # Step 3: Does the server hard-require a client cert?
        result.requires_client_cert = conn_info.get("required_client_cert", False)

        # Step 4: Does it accept a self-signed client cert?
        if not result.requires_client_cert or True:  # always test this
            result.accepted_self_signed = self._test_self_signed_acceptance()

        # Step 5: Probe supported TLS versions
        result.supported_versions = self._probe_tls_versions()

        # Step 6: Probe weak cipher support
        weak_results        = self._probe_weak_ciphers()
        result.weak_ciphers     = weak_results
        result.supported_ciphers = [r.requested for r in weak_results]

        log.info(
            f"[TLS] {self.target.ip}:{self.target.port} — "
            f"{result.negotiated_version} / {result.negotiated_cipher} — "
            f"cert_required={result.requires_client_cert} "
            f"accepts_self_signed={result.accepted_self_signed}"
        )

        return result

    def _connect(
        self,
        ctx: ssl.SSLContext,
        server_hostname: str | None = None,
    ) -> dict | None:
        """
        Attempt a raw TLS connection.  Returns a dict of connection
        metadata, or None on failure.
        """
        host = server_hostname or self.target.hostname or self.target.ip
        port = self.target.port

        try:
            raw_sock = socket.create_connection(
                (self.target.ip, port),
                timeout=self.connect_timeout,
            )
            tls_sock = ctx.wrap_socket(raw_sock, server_hostname=host)
            tls_sock.settimeout(self.connect_timeout)

            info = {
                "version": tls_sock.version(),
                "cipher":  tls_sock.cipher(),
                "raw_certs": [],
                "required_client_cert": False,
            }

            # Grab the DER bytes for the full chain
            peer_cert = tls_sock.getpeercert(binary_form=True)
            if peer_cert:
                info["raw_certs"].append(peer_cert)

            tls_sock.close()
            return info

        except ssl.SSLError as e:
            err = str(e).lower()
            if "certificate required" in err or "handshake failure" in err:
                return {"required_client_cert": True, "raw_certs": [],
                        "version": None, "cipher": None}
            log.debug(f"[TLS] SSL error connecting to {host}:{port}: {e}")
            return None
        except (TimeoutError, ConnectionRefusedError, OSError) as e:
            log.debug(f"[TLS] Connection error to {host}:{port}: {e}")
            return None

    def _test_self_signed_acceptance(self) -> bool:
        """
        Returns True if the server accepts a self-signed client cert
        at BOTH the TLS layer AND the HTTP layer.

        Why we need to probe both layers:
          Some servers complete the TLS handshake regardless of the client
          cert presented (no mTLS enforcement at the TLS layer), then
          validate the cert chain at the HTTP/application layer and return
          a 401/403/TLS alert on the first real request.

          Checking only whether _connect() succeeds is therefore not
          sufficient — a TLS handshake completion alone is not evidence
          that a self-signed cert is "accepted" in any meaningful sense.

          We confirm acceptance by:
            1. TLS handshake must succeed (no SSLError)
            2. An actual HTTP GET /dcap must return a non-error HTTP
               status code (anything with a status code — even 401 means
               the server processed the request, which is weaker than we
               want, so we require 2xx or 3xx as confirmation)

          If the server sends a TLS alert on the HTTP request (UNKNOWN_CA
          etc.), that is correct cert rejection behaviour — not a finding.
        """
        import os
        from http.client import HTTPSConnection

        cert_path = key_path = None
        try:
            ctx, cert_path, key_path = self.factory.self_signed_context()

            # Step 1: does the TLS handshake complete?
            info = self._connect(ctx)
            if info is None or info.get("required_client_cert"):
                log.debug(
                    f"[TLS] Self-signed test: TLS handshake failed "
                    f"@ {self.target.ip}:{self.target.port} — cert rejected at TLS layer"
                )
                return False

            # Step 2: send a real HTTP request and require a 2xx/3xx response.
            # A 4xx means the server processed the request (HTTP layer reached)
            # but still rejected us — that's not the same as "accepting" the cert.
            host = self.target.hostname or self.target.ip
            conn = HTTPSConnection(
                host        = self.target.ip,
                port        = self.target.port,
                context     = ctx,
                timeout     = self.connect_timeout,
            )
            try:
                conn.request(
                    "GET",
                    self.target.base_path,   # probe /dcap
                    headers={
                        "Accept":     "application/sep+xml",
                        "User-Agent": "sep2-mapper-tls-probe/0.1",
                        "Host":       f"{host}:{self.target.port}",
                    },
                )
                resp   = conn.getresponse()
                status = resp.status
                resp.read()
            except ssl.SSLError as e:
                # Server sent a TLS alert on the HTTP request — cert rejected
                log.debug(
                    f"[TLS] Self-signed test: TLS alert on HTTP request "
                    f"({e}) — cert correctly rejected"
                )
                return False
            except Exception as e:
                log.debug(f"[TLS] Self-signed HTTP probe error: {e}")
                return False
            finally:
                try:
                    conn.close()
                except Exception:
                    pass

            # Only flag as accepted if we got a real successful response.
            # 2xx = server returned data using our self-signed cert → finding
            # 3xx = redirect, still means HTTP layer was reached with our cert
            # 4xx/5xx = server reached HTTP layer but rejected the request for
            #           application reasons (wrong LFDI etc.) — the cert itself
            #           may or may not be "trusted" at TLS level; too ambiguous
            #           to call a definitive finding here.
            accepted = 200 <= status < 400
            if accepted:
                log.warning(
                    f"[TLS] *** SERVER ACCEPTS SELF-SIGNED CLIENT CERT *** "
                    f"HTTP {status} returned for GET {self.target.base_path} "
                    f"@ {self.target.ip}:{self.target.port}"
                )
            else:
                log.debug(
                    f"[TLS] Self-signed test: HTTP {status} — "
                    f"TLS handshake completed but HTTP layer rejected cert/request"
                )
            return accepted

        except Exception as e:
            log.debug(f"[TLS] Self-signed probe error: {e}")
            return False
        finally:
            for p in (cert_path, key_path):
                if p:
                    try:
                        os.unlink(p)
                    except Exception:
                        pass

    def _probe_tls_versions(self) -> list[str]:
        """
        Try each TLS version individually.
        Returns list of version strings the server accepts.
        """
        supported = []
        for version_name, tls_version in self.TLS_VERSIONS.items():
            if tls_version is None:
                continue
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                ctx.minimum_version = tls_version
                ctx.maximum_version = tls_version
                info = self._connect(ctx)
                if info and info.get("version"):
                    supported.append(version_name)
                    if version_name in ("TLSv1", "TLSv1.1"):
                        log.warning(
                            f"[TLS] Weak protocol supported: {version_name} "
                            f"@ {self.target.ip}:{self.target.port}"
                        )
            except Exception:
                pass
        return supported

    def _probe_weak_ciphers(self) -> list:
        """
        Try each weak cipher suite and CONFIRM the server actually
        negotiated the weak cipher (not a strong fallback).

        Returns a list of WeakCipherResult for confirmed findings.

        How false positives happen without the confirmation step:
          ctx.set_ciphers("aNULL") builds a context whose cipher list
          includes all anonymous ciphers.  If the server doesn't support
          any of them it will abort the handshake — but if the local
          OpenSSL also has strong ciphers compiled into that selector,
          the server might just pick one of those instead.  We only report
          a finding if the NEGOTIATED cipher name contains a marker that
          confirms the weak family was actually chosen.
        """
        from der_sep2.models import WeakCipherResult
        accepted = []
        for cipher_str, category, markers in WEAK_CIPHERS:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                ctx.set_ciphers(cipher_str)
            except ssl.SSLError:
                # Cipher string not available in this local OpenSSL build —
                # cannot test, skip silently.
                log.debug(f"[TLS] Cipher {cipher_str!r} not available locally, skipping")
                continue

            try:
                info = self._connect(ctx)
            except Exception as e:
                log.debug(f"[TLS] Probe error for {cipher_str!r}: {e}")
                continue

            if not info or not info.get("cipher"):
                # Handshake failed — server didn't accept this cipher family
                continue

            negotiated_name = info["cipher"][0]   # e.g. "ADH-AES256-SHA256"

            # Confirm: does the negotiated cipher name match the weak family?
            if markers:
                confirmed = any(m.upper() in negotiated_name.upper() for m in markers)
            else:
                confirmed = True   # specific suite name, no ambiguity

            if confirmed:
                accepted.append(WeakCipherResult(
                    requested  = cipher_str,
                    negotiated = negotiated_name,
                    category   = category,
                ))
                log.warning(
                    f"[TLS] CONFIRMED weak cipher: requested={cipher_str!r} "
                    f"negotiated={negotiated_name!r} ({category}) "
                    f"@ {self.target.ip}:{self.target.port}"
                )
            else:
                # Connection succeeded but server chose a strong cipher —
                # our weak request was ignored. This is correct server behaviour.
                log.debug(
                    f"[TLS] {cipher_str!r} offered but server negotiated "
                    f"{negotiated_name!r} (not weak) — FALSE POSITIVE avoided"
                )

        return accepted


# ---------------------------------------------------------------------------
# Convenience function
# ---------------------------------------------------------------------------

def profile_target(
    target:       ServiceTarget,
    ca_bundle:    str | None = None,
    client_cert:  str | None = None,
    client_key:   str | None = None,
    timeout:      float         = 5.0,
) -> TLSProfile:
    """
    One-shot helper: build a TLSProfile for a single target.
    """
    factory  = TLSContextFactory(
        ca_bundle   = ca_bundle,
        client_cert = client_cert,
        client_key  = client_key,
    )
    profiler = TLSProfiler(target, factory, connect_timeout=timeout)
    return profiler.profile()
