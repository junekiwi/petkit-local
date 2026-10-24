"""The names a certificate this add-on mints is valid for.

Two places issue TLS certificates — the device-facing broker's self-signed one
(`mqtt/broker.py::ensure_self_signed`) and the leaf the ESP32 CA signs
(`patchers/firmware.py::issue_server_cert`) — and both are handed a mix of
addresses and hostnames by callers that cannot always tell which is which: an
`api_url` may name either. Deciding that in one place is the point.
"""
from __future__ import annotations

import ipaddress
from collections.abc import Iterable


def subject_alt_names(hosts: Iterable[str]) -> list:
    """`x509.GeneralName`s naming every host in `hosts`, in order, once each.

    An address becomes an IP SAN and anything else a DNS SAN — a name is
    exactly the case an IP SAN can never satisfy. Empty entries are skipped, so
    a caller can pass an optional host without filtering it first.
    """
    from cryptography import x509  # noqa: PLC0415 - optional dependency, probed at use

    names: list = []
    seen: set[str] = set()
    for host in hosts:
        if not host or host in seen:
            continue
        seen.add(host)
        try:
            names.append(x509.IPAddress(ipaddress.ip_address(host)))
        except ValueError:
            names.append(x509.DNSName(host))
    return names
