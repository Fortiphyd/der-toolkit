# Demo: a simulated DER cluster

Nine simulated devices spanning all three protocols: seven make up the
"mapping cluster," deliberately varied so a full-pipeline run has something
interesting to say about each one — not just "the tool ran," but a
genuinely different finding per device. The other two are small,
intentionally-vulnerable fuzzing targets (one DNP3, one SunSpec) — see
[Fuzzing](#fuzzing) below. `demo/run_cluster.py` starts all nine together,
so one recording can show mapping, cross-protocol reporting, and fuzzing
without restarting anything in between.

Each device gets its own address and the real standard port for its
protocol (Modbus/TCP 502, DNP3 20000, IEEE 2030.5 15388), rather than all
nine crowding onto `127.0.0.1` at made-up ports — closer to what mapping
an actual small site looks like. The addresses are still loopback (no
network setup needed), just spread across three /24s by protocol so
nothing collides:

| Device                              | Protocol | Address            | What it's for |
|--------------------------------------|----------|---------------------|----------------|
| Classic PV inverter                  | SunSpec  | 127.0.10.1:502      | The textbook writable surface: model 123 Immediate Controls (power limit, PF, VAR) |
| DER-compliant inverter               | SunSpec  | 127.0.10.2:502      | The newer, richer surface: model 704 DER AC Controls (32 writable fields, incl. anti-islanding enable) |
| Telemetry/storage device             | SunSpec  | 127.0.10.3:502      | Mostly read-only sensors (irradiance, temp, weather) + one small operational control (model 715) |
| Protection relay                     | DNP3     | 127.0.20.1:20000    | Binary output status (g10v2) — implies CROB (g12) is operable: "flip a breaker" |
| Setpoint controller                  | DNP3     | 127.0.20.2:20000    | Analog output status (g40v1) — implies analog commands (g41) are operable: "rewrite a setpoint". No binary I/O at all. |
| SEP2 server (hardened)               | SEP2     | 127.0.30.1:15388    | Correctly configured: mTLS + chain validation + registration all enforced. The contrast case. |
| SEP2 server (vulnerable)             | SEP2     | 127.0.30.2:15388    | Two real findings: an access-control misconfiguration (DER control surface force-opened) and a real XML implementation bug (XXE) |
| *DNP3 fuzzing target (vulnerable)*   | DNP3     | 127.0.20.3:20000    | *Not part of the mapping cluster* — small, intentionally naive parser built to give `der-dnp3 fuzz` something real to crash |
| *SunSpec fuzzing target (vulnerable)*| SunSpec  | 127.0.10.4:502      | *Not part of the mapping cluster* — small, intentionally naive parser built to give `der-sunspec fuzz` something real to crash |

Port 502 is privileged, so four of the nine devices (the three "real"
SunSpec inverters, plus the SunSpec fuzzing target) run under
[`authbind`](https://en.wikipedia.org/wiki/Authbind) rather than as root.
One-time setup (safe and narrowly scoped — it only grants your user
permission to bind port 502, nothing broader):

```bash
sudo apt-get install -y authbind
sudo touch /etc/authbind/byport/502
sudo chmod 500 /etc/authbind/byport/502
sudo chown $USER /etc/authbind/byport/502
```

## Quick start

```bash
# One-time: generate the SEP2 server's test PKI, and authbind (above)
demo/sep2_server/setup.sh

# Start all nine devices
python3 demo/run_cluster.py
```

In another terminal, map every device and merge into one cross-protocol
report — `run_cluster.py` prints the exact commands to copy-paste, or:

```bash
mkdir -p /tmp/der_demo
der-sunspec map 127.0.10.1 --port 502 --output /tmp/der_demo/classic.json
der-sunspec map 127.0.10.2 --port 502 --output /tmp/der_demo/der_compliant.json
der-sunspec map 127.0.10.3 --port 502 --output /tmp/der_demo/telemetry.json
der-dnp3    map 127.0.20.1 --port 20000 --output /tmp/der_demo/relay.json
der-dnp3    map 127.0.20.2 --port 20000 --output /tmp/der_demo/setpoint.json
der-sep2    map 127.0.30.1 --port 15388 \
  --client-cert demo/sep2_server/certs/client_registered.crt \
  --client-key  demo/sep2_server/certs/client_registered.key \
  --ca-bundle   demo/sep2_server/certs/ca.crt \
  --output /tmp/der_demo/hardened.json
der-sep2    map 127.0.30.2 --port 15388 \
  --client-cert demo/sep2_server/certs/client_registered.crt \
  --client-key  demo/sep2_server/certs/client_registered.key \
  --ca-bundle   demo/sep2_server/certs/ca.crt \
  --output /tmp/der_demo/vulnerable.json

der-report /tmp/der_demo/*.json
```

The merged report ranks all 67 writable, unauthenticated-reachable points
across all seven devices by severity in one list, regardless of protocol —
the DER-compliant inverter's 33-field surface right next to the classic
inverter's 22, both next to DNP3's single CROB-implying point and SEP2's
force-opened DER control resource. A real copy of this output, if you'd
rather read it than reproduce it, is in
[`examples/demo_cluster_report.sample.txt`](../examples/demo_cluster_report.sample.txt).

All of the above is also exercised automatically — `tests/test_demo_cluster.py`
starts the whole cluster, runs these same `map` commands, and asserts on
these exact numbers, so a change to any protocol's mapper that shifts what
the demo reports gets caught in CI rather than during a live walkthrough.
It's marked `integration` and skipped by the fast test run; run it directly
with `pytest -v -m integration`.

## Driving it with an AI assistant (MCP)

Everything above also works through `der-mcp` instead of the CLI — the same
mapping/discovery code, exposed as tools an AI assistant can call directly
rather than commands you type. This is the more interesting story for the
toolkit: given the ranges below and a plain-language ask, an assistant can
discover, map, and summarize the whole cluster's attack surface on its own.

**Setup:**

```bash
# 1. Install with the mcp extra
pip install -e ".[mcp]"

# 2. Start the cluster, same as the Quick start above
demo/sep2_server/setup.sh
python3 demo/run_cluster.py
```

This repo already ships a project-scoped `.mcp.json` registering `der-mcp` —
opening this directory in Claude Code prompts a one-time approval (see the
top-level README's MCP section). For Claude Desktop instead, add it manually
to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "der-mcp": { "command": "der-mcp" }
  }
}
```

**Example prompt**, once the cluster is running:

> I have a small DER (distributed energy resource) test deployment I'm
> authorized to assess. Using the der-mcp tools, please:
>
> 1. Discover what's running across these ranges (treat them as authorized
>    scope for this session): `127.0.10.0/29` (expect SunSpec/Modbus
>    inverters), `127.0.20.0/29` (expect DNP3 outstations), `127.0.30.0/29`
>    (expect IEEE 2030.5/SEP2 servers).
> 2. Map the attack surface of everything you find. For any SEP2 servers,
>    also map using this client certificate to check what a leaked
>    credential would expose: cert
>    `demo/sep2_server/certs/client_registered.crt`, key
>    `demo/sep2_server/certs/client_registered.key`.
> 3. Summarize the findings across all three protocols, ranked by severity,
>    and call out anything an attacker with no credentials could actually
>    control.

A couple of things worth knowing before you run this:

- SunSpec and SEP2 discovery are near-instant (a Modbus register read and an
  HTTP probe, respectively). DNP3 is noticeably slower — up to a minute or so
  per outstation — because DNP3 has no self-announcing discovery mechanism at
  all; finding the right outstation address means actively probing
  combinations of candidate addresses. That's inherent to the protocol, not
  a hang.
- This exercises `discover_targets` and `map_attack_surface` (both read-only).
  Fuzzing via MCP (`start_fuzz`) works the same way but needs explicit
  `allow_disruptive=True` and should only be aimed at devices you're
  authorized to potentially crash or hang — the demo devices are fine, a
  found-on-the-network device is not.

## Fuzzing

Any device can be fuzzed the same way as a real target (`--authorized-scope`
+ `--allow-disruptive` required, same gate as everywhere else in the
toolkit):

```bash
der-sep2 fuzz 127.0.30.2 --port 15388 \
  --client-cert demo/sep2_server/certs/client_registered.crt \
  --client-key  demo/sep2_server/certs/client_registered.key \
  --ca-bundle   demo/sep2_server/certs/ca.crt \
  --authorized-scope 127.0.30.2/32 --allow-disruptive
```

reproduces a real XXE finding — `/etc/passwd` reflected back through the
`lFDI` field.

### DNP3 and SunSpec: two more fuzzing targets, custom-built and intentionally vulnerable

Neither the DNP3 outstations nor the three SunSpec inverters in the mapping
cluster are fuzzable in a way worth demonstrating — the outstations are
fairly defensive, and the SunSpec devices' actual wire-protocol handling is
`pymodbus`, a mature library that isn't a realistic target for a short
fuzzing run. So there are two more devices, purpose-built to have a real,
findable bug each: small, hand-written, deliberately naive protocol
handlers, the opposite of the "real, defensible parser" standard the rest
of this toolkit holds itself to. Don't mistake either for a finding about
DNP3, Modbus, `pymodbus`, or der-toolkit's own parsers.

`demo/run_cluster.py` starts both alongside the mapping cluster (see the
device table above), but they're deliberately **excluded from the mapping
cluster itself and from the "map everything + der-report" example** — even
a plain, read-only `map` crashes them (a mapper's ordinary base-address
probing is unbounded enough to trip the same bug), so mixing them into that
flow would just look like a mapping failure. Fuzz them directly instead:

```bash
der-dnp3    fuzz 127.0.20.3 --port 20000 --authorized-scope 127.0.20.3/32 --allow-disruptive
der-sunspec fuzz 127.0.10.4 --port 502   --authorized-scope 127.0.10.4/32 --allow-disruptive
```

(Running either standalone, without the rest of the cluster: `python3
demo/dnp3_outstations/vulnerable_outstation.py` or `authbind --deep
python3 demo/sunspec_devices/vulnerable_device.py`.)

DNP3's bug: trusts the last byte of any request as a raw index into its
point list, no bounds check. SunSpec's: trusts the MBAP length field and
the Read Holding Registers count field with no validation -- same root
cause, two spots.

Both crash almost immediately — watch the target's own terminal, not the
fuzzer's summary. Neither `der-dnp3 fuzz` nor `der-sunspec fuzz` reports
either one as a crash: the bug only kills the per-connection handler
thread, not the whole process or the TCP connection itself, and neither
fuzzer's crash detection currently notices that from the outside. The
exception is real and immediately visible in the target's own log — this
is a genuine limitation in the current crash detection, worth knowing
about rather than a reason to doubt the finding.

## What's real here, and what isn't

Every device's behavior is exercised through the same unmodified mapper/
fuzzer code path this toolkit uses against a real target — nothing here is
mocked at the der-toolkit layer. What's simulated is the *device*, not the
*assessment*:

- The SunSpec devices are genuine Modbus/TCP servers (`pymodbus`), with
  real SMDX-defined register offsets — see `demo/sunspec_devices/common.py`.
- The DNP3 outstations speak real DNP3 link/transport/app framing, reusing
  `der_dnp3.scanner`'s own tested primitives rather than a separate
  implementation — see `demo/dnp3_outstations/common.py`.
- The SEP2 server is the project's own purpose-built test server (ported in
  from a separate tool, not written for this demo), with two vulnerability
  modes toggled via `configs/*.yaml`.

### Verifying the simulators are protocol-accurate

The DNP3 and SunSpec simulators share code with der-toolkit's own parsers
(CRC tables, frame formats, SMDX offsets), so testing them only against
der-toolkit's own mapper doesn't prove much on its own — a bug shared by
both sides would pass invisibly. Each was also checked against a real,
independent implementation:

- **DNP3** — opendnp3's own `master-demo` against `protection_relay.py`. A
  real master's first move on connecting is `DISABLE_UNSOLICITED`, which an
  earlier version of the simulator didn't answer at all, hanging the
  master indefinitely. It now runs the master's full startup sequence
  cleanly (Disable Unsolicited → Integrity Poll → Enable Unsolicited →
  Application Polls), every response `IIN: [0x00, 0x00]`.
- **SunSpec** — `pysunspec2`'s own client against `der_compliant_inverter.py`
  decoded every field exactly as programmed, including the negative
  `WSet=-1500` setpoint's two's-complement encoding. No bugs found.
- **SEP2** — lower risk to begin with, since this server predates the demo
  and isn't built on der-toolkit's parsing code, but checked anyway with
  [`gridappsd-2030-5-client`](https://github.com/GRIDAPPSD/gridappsd-2030-5-client),
  an independent IEEE 2030.5 Python client. A full mTLS handshake against
  the registered cert, correct parsing of `/dcap` and `/edev`, and
  independent confirmation (from the client side, not just the server's own
  logs) that a self-signed cert gets rejected at the TLS layer. Full XSD
  schema validation wasn't feasible — the real IEEE 2030.5-2018 schema is
  paywalled, and the freely available community copies use an older,
  pre-standardization namespace, so validating against them would just
  compare against the wrong document.

### Known gap: `validate_cert_chain: false`

This mode was meant to show the "collapses when misconfigured" thesis via a
leaked or self-signed cert, but it doesn't actually work: Python's stdlib
`ssl` module has no way to accept a *presented* client certificate without
verifying its chain (`CERT_OPTIONAL` only tolerates an *absent* one), so
that path in `ssl_server.py` ends up rejecting every client certificate,
trusted or not. `configs/vulnerable.yaml` demonstrates the same thesis a
different way instead, via `open_resources` at the application layer. A
proper fix would mean moving `ssl_server.py` onto `pyOpenSSL` for a real
custom verify callback.
