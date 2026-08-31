"""SunSpec Modbus attack-surface mapper and fuzzers.

  mapper.py          -> walk the self-describing SunSpec model chain over Modbus/TCP
  models_catalog.py  -> model ID -> name, and which models are writable controls
  adapter.py         -> mapper output -> der_common.AttackSurface
  fuzzer.py          -> boofuzz-based fuzzer of the device's Modbus/TCP server
                        (optional 'sunspec' extra; imported lazily)
  client_fuzzer/     -> malicious Modbus server that fuzzes connecting masters/clients

Migrated from ../DER/sunspec (mapper, client_fuzzer) and ../DER/boofuzz/modbus.py
(fuzzer.py). The 2011 C SunSpec Alliance tool is intentionally dropped in favor
of the Python mapper. fuzzer.py is NOT imported here so that `import der_sunspec`
works without boofuzz installed.
"""
