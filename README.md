# DER Toolkit

Attack-surface mapping and protocol fuzzing for distributed energy resource (DER)
protocols — **DNP3**, **SunSpec Modbus**, and **IEEE 2030.5** — with an **MCP
server** that lets an AI assistant drive the tools and reason over the results.

Built as part of a DOE-funded research effort to help asset owners answer a
concrete question: *which device commands and registers are reachable by an
unauthenticated attacker on my network?*

> ⚠️ **These are offensive tools.** Mapping is read-only; fuzzing can hang or
> crash live grid equipment. Only use them against devices you own or are
> explicitly authorized to assess. See [SECURITY.md](SECURITY.md).

## Layout

```
der_common/   shared AttackSurface schema + safety/scope gate + run storage
der_sep2/     IEEE 2030.5: discover / tls / map / fuzz   (most mature)
der_dnp3/     DNP3: scan / map / fuzz (boofuzz)
der_sunspec/  SunSpec Modbus: self-describing model map + device/client fuzzers
der_mcp/      MCP server exposing all of the above
examples/     sample outputs + a quickstart device simulator fixture
```

Every mapper/fuzzer normalizes to one `AttackSurface` model
(`der_common/schema.py`) so results are comparable across protocols — the point
the toolkit is built to demonstrate.

## Install

```bash
pip install -e ".[all]"      # everything, or pick groups:
pip install -e ".[sunspec]"  # just the SunSpec mapper
pip install -e ".[mcp]"      # + the MCP server
```

## Quickstart

See it work end to end against a real (simulated) device — no hardware, no
vendor docs, no target of your own required.

```bash
# 1. Install der-toolkit and a SunSpec reference simulator
pip install -e ".[sunspec]"
pip install pysunspec2

# 2. Start a reference SunSpec/Modbus device on 127.0.0.1:5503
suns -P 5503 -s -m examples/quickstart_device.model

# 3. In another terminal, map its attack surface
der-sunspec map 127.0.0.1 --port 5503
```

```
[sunspec] 1 device(s) mapped, 0 failed
  127.0.0.1 unit=1: 1 models, 0 writable control model(s) , 1 unauth-writable field(s)
```

That one unauth-writable field is real: the device's Modbus `DA` (Device
Address) register accepts unauthenticated writes, flagged `critical` in the
full JSON output (`der-sunspec map ... --output result.json`). Compare against
[examples/sunspec_attack_surface.sample.json](examples/sunspec_attack_surface.sample.json)
for the complete shape.

`suns` is the SunSpec Alliance's own reference implementation (from
[`pysunspec2`](https://pypi.org/project/pysunspec2/)) — the same tool this
project's own live-target testing uses, not a mock built for this demo.

## Other CLIs

```bash
der-sep2    map <host> --client-cert c.crt --client-key c.key
der-dnp3    map <host> --port 20000
```

## MCP server

`der-mcp` speaks MCP over stdio; point Claude Desktop / Claude Code at it. Tools:
`list_capabilities`, `discover_targets`, `map_attack_surface` (read-only),
`start_fuzz` / `get_job` / `get_findings` (async, gated behind explicit consent).

This repo ships a project-scoped `.mcp.json` that registers `der-mcp` (after
`pip install -e ".[mcp]"`). Claude Code will prompt you to approve it the first
time you open this directory — that one-time prompt is Claude Code's own trust
gate for repo-committed MCP servers, not something this project can or should
skip. To register it manually instead: `claude mcp add --scope project der-mcp
-- der-mcp`.

## Status

All three protocol packages and the MCP server are working end-to-end, including
live validation against a real reference implementation for each protocol: a real
DNP3 outstation, a real SunSpec device simulator, and a real IEEE 2030.5 test
server. Known gaps: no testing yet against physical vendor hardware, and 9 of
the newer 700-series SunSpec DER control models (the ones with a runtime-sized
curve table) still fall back to a coarse, model-level control point rather
than field-level decode — see `der_sunspec/smdx/NOTICE.md`.
