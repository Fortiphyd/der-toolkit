"""
xml_parser.py
─────────────
Configurable XML parsing with explicit safe / vulnerable modes.

Vulnerable mode (allow_xxe=true) uses lxml with:
  - load_dtd=True        → parser loads the inline DTD
  - resolve_entities=True → SYSTEM/PUBLIC entities are fetched and substituted
  - no_network=False     → network URIs (http://) are followed
  - huge_tree=False      → entity-expansion depth not bounded (Billion Laughs)

Safe mode uses defusedxml, which raises on any of these attacks.

The parsed tree is returned along with a ParseResult that records:
  - which entities were declared
  - whether any external URIs were referenced
  - the raw text of any element that looks like exfiltrated content

This gives the mapper something concrete to diff between safe and vulnerable
responses beyond just HTTP status codes.
"""

import logging
import re
import xml.etree.ElementTree as stdlib_et  # fallback
from dataclasses import dataclass, field

log = logging.getLogger(__name__)

# ── Dependency check ──────────────────────────────────────────────────────────
try:
    from lxml import etree as lxml_etree
    _LXML_AVAILABLE = True
except ImportError:
    _LXML_AVAILABLE = False
    log.warning("lxml not installed – XXE vulnerability mode unavailable. "
                "Install with: pip install lxml")

try:
    import defusedxml.ElementTree as safe_et
    _DEFUSEDXML_AVAILABLE = True
except ImportError:
    _DEFUSEDXML_AVAILABLE = False
    log.warning("defusedxml not installed – falling back to stdlib xml.etree "
                "(has partial protections in Python 3.8+). "
                "Install with: pip install defusedxml")

# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class ParseResult:
    """
    Structured output from parse_request_xml().
    The mapper can inspect these fields to confirm whether XXE fired.
    """
    success: bool = False
    tree: object = None                      # lxml _Element or ET Element

    # XXE telltales
    entities_declared: list[str] = field(default_factory=list)
    external_uris: list[str] = field(default_factory=list)
    resolved_entity_values: dict[str, str] = field(default_factory=dict)

    # Error info
    error: str | None = None
    blocked_reason: str | None = None     # set when defusedxml raises


# ──────────────────────────────────────────────────────────────────────────────
# Entity extraction helpers (work on raw XML text before full parsing)
# ──────────────────────────────────────────────────────────────────────────────

_ENTITY_DECL_RE  = re.compile(r'<!ENTITY\s+(\S+)\s+(SYSTEM|PUBLIC)\s+"([^"]+)"', re.IGNORECASE)
_INLINE_ENTITY_RE = re.compile(r'<!ENTITY\s+(\S+)\s+"([^"]+)"', re.IGNORECASE)
_ENTITY_REF_RE   = re.compile(r'&([a-zA-Z_][\w.-]*);')


def _extract_entity_metadata(xml_bytes: bytes) -> tuple[list[str], list[str]]:
    """
    Scan raw XML for entity declarations without parsing.
    Returns (entity_names, external_uris).
    """
    text = xml_bytes.decode("utf-8", errors="replace")
    external = _ENTITY_DECL_RE.findall(text)
    entity_names = [e[0] for e in external]
    uris         = [e[2] for e in external]
    return entity_names, uris


# ──────────────────────────────────────────────────────────────────────────────
# Vulnerable parser  (lxml, entities resolved)
# ──────────────────────────────────────────────────────────────────────────────

def _parse_vulnerable(xml_bytes: bytes, allow_billion_laughs: bool) -> ParseResult:
    """
    Deliberately insecure parse:
      - loads DTD
      - resolves SYSTEM/PUBLIC entities (file://, http://, etc.)
      - optionally unbounded entity expansion (Billion Laughs)

    OOB / HTTP exfil note
    ─────────────────────
    lxml delegates http:// entity fetches to libxml2's network loader, which is
    disabled or compiled out in many distro builds.  To test OOB exfil reliably
    we implement it directly: after parsing, any http:// entity URI is fetched
    with urllib so the callback always fires regardless of the libxml2 build.
    This simulates what a fully vulnerable server would do.
    """
    if not _LXML_AVAILABLE:
        return ParseResult(
            success=False,
            error="lxml not installed; cannot exercise XXE vulnerability mode",
        )

    result = ParseResult()
    result.entities_declared, result.external_uris = _extract_entity_metadata(xml_bytes)

    # ── Log what was *declared* (regex scan – not yet resolved) ──────────────
    if result.external_uris:
        log.warning("XXE: external URIs declared in DTD: %s", result.external_uris)

    try:
        parser = lxml_etree.XMLParser(
            load_dtd=True,           # parse and load the inline DTD
            resolve_entities=True,   # substitute entities where possible
            no_network=False,        # permit libxml2 network loader if available
            huge_tree=not allow_billion_laughs,
        )
        root = lxml_etree.fromstring(xml_bytes, parser=parser)
        result.success = True
        result.tree = root

        # ── Capture resolved text (may contain exfil content) ────────────────
        for el in root.iter():
            if el.text and len(el.text) > 20:
                tag = lxml_etree.QName(el.tag).localname
                result.resolved_entity_values[tag] = el.text[:512]

        if result.resolved_entity_values:
            log.warning("XXE: entity values found in parsed tree (may be exfil content): %s",
                        {k: v[:60] + "…" for k, v in result.resolved_entity_values.items()})

        # ── OOB HTTP callback – fire even if libxml2 loader is disabled ──────
        # For each http(s):// URI declared, make a real outbound request so
        # the listener always sees the hit. This is the reliable OOB signal.
        _fire_oob_callbacks(result.external_uris)

    except lxml_etree.XMLSyntaxError as exc:
        result.success = False
        result.error = str(exc)

    return result


def _fire_oob_callbacks(uris: list[str]):
    """
    Make outbound HTTP requests for any http(s):// entity URIs.
    Runs in a background thread so it never blocks the response.
    libxml2's own network loader is unreliable across distros; this ensures
    the OOB callback fires regardless of how libxml2 was compiled.
    """
    import threading
    from urllib.error import URLError
    from urllib.request import urlopen

    http_uris = [u for u in uris if u.startswith("http://") or u.startswith("https://")]
    if not http_uris:
        return

    def _fetch(uri):
        try:
            urlopen(uri, timeout=3)
            log.warning("XXE OOB callback sent: %s", uri)
        except URLError as exc:
            # Connection refused / no listener – log it so the operator knows
            # the callback fired but nobody was home.
            log.warning("XXE OOB callback attempted %s – no listener: %s", uri, exc.reason)
        except Exception as exc:
            log.warning("XXE OOB callback error %s: %s", uri, exc)

    for uri in http_uris:
        threading.Thread(target=_fetch, args=(uri,), daemon=True).start()


# ──────────────────────────────────────────────────────────────────────────────
# Safe parser  (defusedxml or stdlib fallback)
# ──────────────────────────────────────────────────────────────────────────────

def _parse_safe(xml_bytes: bytes) -> ParseResult:
    """
    Secure parse that blocks all known XML attack vectors.
    defusedxml raises descriptive exceptions for each attack type.
    """
    result = ParseResult()
    # Still record what the attacker *tried* to declare, even though we block it
    result.entities_declared, result.external_uris = _extract_entity_metadata(xml_bytes)

    if result.external_uris:
        log.info(
            "XXE attempt BLOCKED (safe parser) – declared entities: %s, URIs: %s",
            result.entities_declared, result.external_uris,
        )

    try:
        if _DEFUSEDXML_AVAILABLE:
            root = safe_et.fromstring(xml_bytes.decode("utf-8", errors="replace"))
        else:
            root = stdlib_et.fromstring(xml_bytes.decode("utf-8", errors="replace"))

        result.success = True
        result.tree = root

    except Exception as exc:
        # defusedxml raises DTDForbidden, EntitiesForbidden, ExternalReferenceForbidden, etc.
        result.success = False
        exc_name = type(exc).__name__
        result.error = str(exc)
        result.blocked_reason = exc_name
        log.info("XML parse blocked: %s – %s", exc_name, exc)

    return result


# ──────────────────────────────────────────────────────────────────────────────
# Public entry point
# ──────────────────────────────────────────────────────────────────────────────

def parse_request_xml(xml_bytes: bytes, cfg: dict) -> ParseResult:
    """
    Parse XML from a request body according to the vulnerability config.

    Config keys read from cfg['vulnerability']:
      allow_xxe: bool               – enable entity resolution (default: false)
      allow_billion_laughs: bool    – remove entity-expansion limits (default: false)
                                      only meaningful when allow_xxe is also true
    """
    vuln_cfg = cfg.get("vulnerability", {})
    allow_xxe             = vuln_cfg.get("allow_xxe", False)
    allow_billion_laughs  = vuln_cfg.get("allow_billion_laughs", False)

    if allow_xxe:
        log.warning(
            "XML parser: VULNERABLE mode (allow_xxe=true%s)",
            ", allow_billion_laughs=true" if allow_billion_laughs else "",
        )
        return _parse_vulnerable(xml_bytes, allow_billion_laughs)
    else:
        return _parse_safe(xml_bytes)
