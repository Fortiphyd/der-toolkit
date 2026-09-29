"""der_mcp.mappers.discover() has to tolerate scanning a range where most
addresses aren't listening -- that's the normal case for any real
discovery scan, not an edge case. _discover_dnp3 used to crash with an
unhandled ConnectionRefusedError as soon as it hit the first dead host in
a CIDR, found by actually running discover_targets against the demo
cluster's /29s (only 3 of 8 addresses in each range are live).
"""

from der_mcp import mappers


def test_discover_dnp3_skips_unreachable_hosts(monkeypatch):
    def fake_discover(ip, port, **kwargs):
        if ip == "127.0.20.1":
            return (1, 10)
        raise ConnectionRefusedError(111, "Connection refused")

    monkeypatch.setattr("der_dnp3.scanner.discover_outstation_address", fake_discover)
    found = mappers._discover_dnp3(["127.0.20.0/29"], timeout=0.1)
    assert found == [{"ip": "127.0.20.1", "port": 20000, "protocol": "dnp3",
                       "outstation_addr": 10, "master_addr": 1}]
