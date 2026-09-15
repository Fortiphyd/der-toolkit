"""
der_sep2.tls.cert_analyzer
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Parse X.509 certificates from TLS connections and generate
security findings from them.

Findings generated here:
  - Expired certificate
  - Certificate expiring soon (< 30 days)
  - Self-signed server certificate
  - Weak signature algorithm (MD5, SHA1)
  - Hostname mismatch
  - Overly broad SAN (wildcard abuse)
  - Missing SAN (CN-only)
"""

from __future__ import annotations

import logging
from datetime import timezone

from der_sep2.models import CertInfo, Finding, ServiceTarget, Severity, TLSProfile

log = logging.getLogger(__name__)

EXPIRY_WARN_DAYS = 30


class CertAnalyzer:
    """Parse DER/PEM certificate bytes into a CertInfo."""

    @staticmethod
    def from_der(der_bytes: bytes) -> CertInfo | None:
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes

            cert = x509.load_der_x509_certificate(der_bytes)

            # Subject / Issuer as dicts
            def _name_dict(name) -> dict[str, str]:
                result = {}
                for attr in name:
                    oid_name = attr.oid._name if hasattr(attr.oid, "_name") else str(attr.oid)
                    result[oid_name] = attr.value
                return result

            # SAN
            san_values = []
            try:
                san_ext = cert.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName
                )
                for name in san_ext.value:
                    san_values.append(str(name.value))
            except x509.ExtensionNotFound:
                pass

            # Fingerprint
            fp = cert.fingerprint(hashes.SHA256()).hex()

            # Convert naive datetimes to UTC-aware if needed
            not_before = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") \
                         else cert.not_valid_before.replace(tzinfo=timezone.utc)
            not_after  = cert.not_valid_after_utc  if hasattr(cert, "not_valid_after_utc")  \
                         else cert.not_valid_after.replace(tzinfo=timezone.utc)

            return CertInfo(
                subject             = _name_dict(cert.subject),
                issuer              = _name_dict(cert.issuer),
                san                 = san_values,
                not_before          = not_before,
                not_after           = not_after,
                serial              = cert.serial_number,
                fingerprint_sha256  = fp,
                sig_algorithm       = cert.signature_hash_algorithm.name
                                      if cert.signature_hash_algorithm else "unknown",
            )
        except ImportError:
            log.error("cryptography library required: pip install cryptography")
            return None
        except Exception as e:
            log.debug(f"[CertAnalyzer] Failed to parse cert: {e}")
            return None

    @staticmethod
    def from_pem(pem_bytes: bytes) -> CertInfo | None:
        try:
            from cryptography import x509
            cert = x509.load_pem_x509_certificate(pem_bytes)
            from cryptography.hazmat.primitives.serialization import Encoding
            return CertAnalyzer.from_der(cert.public_bytes(Encoding.DER))
        except Exception as e:
            log.debug(f"[CertAnalyzer] PEM parse failed: {e}")
            return None


class TLSFindingGenerator:
    """
    Takes a completed TLSProfile and a ServiceTarget and produces
    a list of security Findings.
    """

    def __init__(self, target: ServiceTarget, profile: TLSProfile):
        self.target  = target
        self.profile = profile

    def findings(self) -> list[Finding]:
        found = []
        found.extend(self._cert_findings())
        found.extend(self._protocol_findings())
        found.extend(self._auth_findings())
        return found

    # ------------------------------------------------------------------
    # Certificate findings
    # ------------------------------------------------------------------

    def _cert_findings(self) -> list[Finding]:
        findings = []
        cert = self.profile.leaf_cert
        if not cert:
            findings.append(Finding(
                severity    = Severity.MEDIUM,
                title       = "Could not retrieve server certificate",
                description = "TLS connection succeeded but no server certificate "
                              "was returned. This may indicate a TLS interception proxy "
                              "or a very unusual server configuration.",
                target      = self.target,
            ))
            return findings

        # Expired cert
        if cert.is_expired:
            findings.append(Finding(
                severity    = Severity.HIGH,
                title       = "Server certificate is expired",
                description = (
                    f"The server certificate expired on "
                    f"{cert.not_after.strftime('%Y-%m-%d')}. "
                    f"Expired certificates undermine TLS trust and may indicate "
                    f"a lack of certificate lifecycle management."
                ),
                target   = self.target,
                evidence = {
                    "not_after":   str(cert.not_after),
                    "subject":     cert.subject,
                    "fingerprint": cert.fingerprint_sha256,
                },
            ))

        # Expiring soon
        elif 0 < cert.days_until_expiry <= EXPIRY_WARN_DAYS:
            findings.append(Finding(
                severity    = Severity.MEDIUM,
                title       = f"Server certificate expires in {cert.days_until_expiry} days",
                description = (
                    f"The certificate will expire on "
                    f"{cert.not_after.strftime('%Y-%m-%d')}. "
                    f"Failure to renew will cause TLS handshake failures for clients "
                    f"that enforce cert validity."
                ),
                target   = self.target,
                evidence = {"days_remaining": cert.days_until_expiry},
            ))

        # Self-signed server cert
        if cert.is_self_signed:
            findings.append(Finding(
                severity    = Severity.HIGH,
                title       = "Server is using a self-signed certificate",
                description = (
                    "The server certificate is self-signed (subject == issuer). "
                    "Clients that perform proper chain validation will reject this. "
                    "IEEE 2030.5 requires certificates issued by a recognized CA — "
                    "typically the IEEE SERCA or a utility-operated CA."
                ),
                target   = self.target,
                evidence = {
                    "subject": cert.subject,
                    "issuer":  cert.issuer,
                },
            ))

        # Weak signature algorithm
        weak_algs = ("md5", "sha1")
        if cert.sig_algorithm.lower() in weak_algs:
            findings.append(Finding(
                severity    = Severity.HIGH,
                title       = f"Weak signature algorithm: {cert.sig_algorithm}",
                description = (
                    f"The server certificate uses {cert.sig_algorithm}, which is "
                    f"cryptographically broken. An attacker could forge a certificate "
                    f"with the same signature."
                ),
                target   = self.target,
                evidence = {"algorithm": cert.sig_algorithm},
            ))

        # Missing SAN — CN-only is deprecated (RFC 2818)
        if not cert.san:
            findings.append(Finding(
                severity    = Severity.LOW,
                title       = "Certificate has no Subject Alternative Name extension",
                description = (
                    "The certificate relies solely on the Common Name for hostname "
                    "matching. RFC 2818 deprecated this in favour of SAN. Modern "
                    "TLS clients may reject such certificates."
                ),
                target   = self.target,
                evidence = {"subject": cert.subject},
            ))

        # Overly broad wildcard SAN
        for san_val in cert.san:
            if san_val.startswith("*."):
                parts = san_val.split(".")
                if len(parts) <= 2:   # *.com or *.local — too broad
                    findings.append(Finding(
                        severity    = Severity.MEDIUM,
                        title       = f"Overly broad wildcard SAN: {san_val}",
                        description = (
                            f"The SAN {san_val!r} is a single-level wildcard covering "
                            f"an entire TLD or near-TLD. This would validate for any "
                            f"hostname in that domain."
                        ),
                        target   = self.target,
                        evidence = {"san": san_val},
                    ))

        return findings

    # ------------------------------------------------------------------
    # Protocol / cipher findings
    # ------------------------------------------------------------------

    def _protocol_findings(self) -> list[Finding]:
        findings = []

        for version in self.profile.supported_versions:
            if version in ("TLSv1", "TLSv1.1"):
                findings.append(Finding(
                    severity    = Severity.HIGH,
                    title       = f"Deprecated TLS version supported: {version}",
                    description = (
                        f"The server accepts {version}, which has known cryptographic "
                        f"weaknesses (BEAST, POODLE). NIST SP 800-52r2 prohibits these "
                        f"versions. IEEE 2030.5 deployments should require TLS 1.2 minimum."
                    ),
                    target   = self.target,
                    evidence = {"version": version},
                ))

        for result in self.profile.weak_ciphers:
            sev = Severity.CRITICAL if any(
                w in result.requested for w in ("NULL", "EXP", "aNULL", "eNULL")
            ) else Severity.HIGH
            findings.append(Finding(
                severity    = sev,
                title       = f"Weak cipher suite accepted: {result.category}",
                description = (
                    f"Offered cipher selector {result.requested!r} and the server "
                    f"negotiated {result.negotiated!r}. "
                    f"This was confirmed by checking the actual negotiated cipher name, "
                    f"not just connection success."
                ),
                target   = self.target,
                evidence = {
                    "requested":  result.requested,
                    "negotiated": result.negotiated,
                    "category":   result.category,
                },
            ))

        return findings

    # ------------------------------------------------------------------
    # Authentication / mTLS findings
    # ------------------------------------------------------------------

    def _auth_findings(self) -> list[Finding]:
        findings = []

        if self.profile.accepted_self_signed:
            findings.append(Finding(
                severity    = Severity.CRITICAL,
                title       = "Server accepts self-signed client certificates",
                description = (
                    "The server completed the TLS handshake when presented with a "
                    "self-signed client certificate not issued by any recognized CA. "
                    "This means client certificate chain validation is not enforced — "
                    "any device with any cert (or a trivially generated one) can "
                    "authenticate. IEEE 2030.5 requires client certs to chain to an "
                    "approved CA (e.g., IEEE SERCA)."
                ),
                target = self.target,
            ))

        if not self.profile.requires_client_cert:
            # This might be expected (e.g. for /dcap), but flag for awareness
            findings.append(Finding(
                severity    = Severity.INFO,
                title       = "Server does not require a client certificate at TLS layer",
                description = (
                    "The server completed the TLS handshake without requesting a "
                    "client certificate. This is expected for function sets with "
                    "aclDefaultAccess that permit unauthenticated access (e.g., "
                    "DeviceCapability, Time, Pricing). Verify that protected resources "
                    "enforce client cert requirements at the application layer."
                ),
                target = self.target,
            ))

        return findings
