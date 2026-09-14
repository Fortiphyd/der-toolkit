# Demo: a simulated DER cluster

Seven simulated devices spanning all three protocols, deliberately varied
so a full-pipeline run has something interesting to say about each one —
not just "the tool ran," but a genuinely different finding per device.

| Device                              | Protocol | Port  | What it's for |
|--------------------------------------|----------|-------|----------------|
| Classic PV inverter                  | SunSpec  | 5601  | The textbook writable surface: model 123 Immediate Controls (power limit, PF, VAR) |
| DER-compliant inverter               | SunSpec  | 5602  | The newer, richer surface: model 704 DER AC Controls (32 writable fields, incl. anti-islanding enable) |
| Telemetry/storage device             | SunSpec  | 5603  | Mostly read-only sensors (irradiance, temp, weather) + one small operational control (model 715) |
| Protection relay                     | DNP3     | 21000 | Binary output status (g10v2) — implies CROB (g12) is operable: "flip a breaker" |
| Setpoint controller                  | DNP3     | 21001 | Analog output status (g40v1) — implies analog commands (g41) are operable: "rewrite a setpoint". No binary I/O at all. |
| SEP2 server (hardened)               | SEP2     | 18443 | Correctly configured: mTLS + chain validation + registration all enforced. The contrast case. |
| SEP2 server (vulnerable)             | SEP2     | 18444 | Two real findings: an access-control misconfiguration (DER control surface force-opened) and a real XML implementation bug (XXE) |

## Quick start

```bash
# One-time: generate the SEP2 server's test PKI
demo/sep2_server/setup.sh

# Start all seven devices
python3 demo/run_cluster.py
```

In another terminal, map every device and merge into one cross-protocol
report — `run_cluster.py` prints the exact commands to copy-paste, or:

```bash
mkdir -p /tmp/der_demo
der-sunspec map 127.0.0.1 --port 5601 --output /tmp/der_demo/5601.json
der-sunspec map 127.0.0.1 --port 5602 --output /tmp/der_demo/5602.json
der-sunspec map 127.0.0.1 --port 5603 --output /tmp/der_demo/5603.json
der-dnp3    map 127.0.0.1 --port 21000 --output /tmp/der_demo/21000.json
der-dnp3    map 127.0.0.1 --port 21001 --output /tmp/der_demo/21001.json
der-sep2    map 127.0.0.1 --port 18443 \
  --client-cert demo/sep2_server/certs/client_registered.crt \
  --client-key  demo/sep2_server/certs/client_registered.key \
  --ca-bundle   demo/sep2_server/certs/ca.crt \
  --output /tmp/der_demo/18443.json
der-sep2    map 127.0.0.1 --port 18444 \
  --client-cert demo/sep2_server/certs/client_registered.crt \
  --client-key  demo/sep2_server/certs/client_registered.key \
  --ca-bundle   demo/sep2_server/certs/ca.crt \
  --output /tmp/der_demo/18444.json

der-report /tmp/der_demo/*.json
```

The merged report ranks all 67 writable, unauthenticated-reachable points
across all seven devices by severity in one list, regardless of protocol —
the DER-compliant inverter's 33-field surface right next to the classic
inverter's 22, both next to DNP3's single CROB-implying point and SEP2's
force-opened DER control resource.

## Fuzzing

Any device can be fuzzed the same way as a real target (`--authorized-scope`
+ `--allow-disruptive` required, same gate as everywhere else in the
toolkit):

```bash
der-sep2 fuzz 127.0.0.1 --port 18444 \
  --client-cert demo/sep2_server/certs/client_registered.crt \
  --client-key  demo/sep2_server/certs/client_registered.key \
  --ca-bundle   demo/sep2_server/certs/ca.crt \
  --authorized-scope 127.0.0.1/32 --allow-disruptive
```

reproduces the XXE finding this project's own live-target validation found
in the SEP2 fuzzer itself (see `docs/` history) — a real `/etc/passwd`
reflected back through the `lFDI` field.

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

### On trusting these simulators

The DNP3 and SunSpec simulators were built by reading der-toolkit's *own*
parsing code as the spec (CRC tables, frame formats, SMDX offsets), and
initially validated only by confirming der-toolkit's own mapper reads them
back correctly. That proves the simulator and der-toolkit *agree with each
other* — not that either is actually correct against the real protocol. A
bug shared between the two would pass that check invisibly.

So each was re-verified against a real, independent implementation that
shares no code with der-toolkit's decode path:

- **DNP3**: opendnp3's own `master-demo` (a real, widely-deployed C++ DNP3
  stack) against `protection_relay.py`. This actually caught a bug —
  the simulator only ever answered `READ` requests, since der-toolkit's own
  scanner never sends anything else; a real master's first action is
  `DISABLE_UNSOLICITED`, which hung waiting for a response that never came.
  Fixed in `demo/dnp3_outstations/common.py`. Re-verified: the real master
  now completes its full standard startup sequence (Disable Unsolicited →
  Startup Integrity Poll → Enable Unsolicited → repeating Application Polls)
  cleanly, every response `IIN: [0x00, 0x00]`.
- **SunSpec**: `pysunspec2`'s own client (the SunSpec Alliance's reference
  Python implementation) against `der_compliant_inverter.py`. Every field
  decoded exactly as programmed, including the negative `WSet=-1500` int32
  setpoint's two's-complement encoding — no bugs found here.
- **SEP2** wasn't re-verified this way; it's lower risk since that server
  predates this session's involvement entirely and isn't derived from
  der-toolkit's own parsing code at all.

One known gap, found while building this: the SEP2 server's
`validate_cert_chain: false` mode (meant to demonstrate the abstract's
"collapses the moment validation is misconfigured" thesis via a leaked/
self-signed cert) doesn't actually work — Python's stdlib `ssl` module has
no way to accept a *presented* client certificate without verifying its
chain, so that code path in `ssl_server.py` fails the handshake for every
client that presents *any* certificate, not just untrusted ones. The
vulnerable config demonstrates the same "misconfiguration collapses the
surface" thesis a different way instead (`vulnerability.open_resources`,
which operates at the application layer and has no such issue). Fixing the
TLS-layer version properly would mean moving `ssl_server.py` onto
`pyOpenSSL` for a real custom verify callback.
