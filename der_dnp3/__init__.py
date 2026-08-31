"""DNP3 attack-surface scanner and fuzzer.

  scanner.py  -> object-model inventory over unauthenticated DNP3/TCP
  adapter.py  -> scanner output -> der_common.AttackSurface
  fuzzer.py   -> boofuzz-based fuzzer (optional 'dnp3' extra; imported lazily)

Migrated from ../DER/boofuzz/dnp3. The fuzzer is NOT imported here so that
`import der_dnp3` works without boofuzz installed.
"""
