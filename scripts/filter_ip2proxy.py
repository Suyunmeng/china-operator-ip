#!/usr/bin/env python3
"""Retired compatibility entry point.

IP2Proxy/IP2Location data is deliberately not part of asset ownership or country
classification. Use the optional --geo-file CSV supported by the Rust pipeline
for location metadata only.
"""

raise SystemExit(
    "filter_ip2proxy.py is retired: use BGP + RIR WHOIS classification; "
    "Geo data may only enrich location metadata"
)
