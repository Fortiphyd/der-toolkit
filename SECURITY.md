# Security & Responsible Use

This toolkit maps and fuzzes DER protocol implementations. It exists to help
asset owners and authorized assessors understand their own exposure.

## Authorized use only

- Use these tools **only** against equipment you own or are **explicitly
  authorized in writing** to test.
- **Mapping** (`map_attack_surface`, `der-* map`) is read-only and low-risk.
- **Fuzzing** (`start_fuzz`, `der-* fuzz`) is **disruptive** and can hang, crash,
  or corrupt the state of live grid equipment. Never run it against production
  DER without an authorized maintenance window and stakeholder sign-off.

## Built-in guardrails

- Every active operation requires an explicit `authorized_scope` (IPs/CIDRs) and
  fails closed if none is given (`der_common/scope.py`).
- Fuzzing additionally requires `allow_disruptive=True`, so an AI agent cannot
  start a disruptive run by default.
- Client certificates and keys are supplied by the operator at runtime and are
  never bundled or committed (`.gitignore` blocks `*.key`/`*.crt`/`*.pem`).

## Reporting a vulnerability

Found a vulnerability in the toolkit itself? Email <security@fortiphyd.com>
rather than opening a public issue. For vulnerabilities the toolkit *finds* in a
vendor's device, follow coordinated disclosure with that vendor and, where
appropriate, CISA.
