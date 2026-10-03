"""Protocol knowledge: what a port number usually means, and how to recognise
HTTP / TLS from the first bytes of a TCP payload.

Two different kinds of "protocol identification" are used in this project:

1. EVIDENCE   - we looked at the packet and saw proof (a DNS layer, an HTTP
                request line, a TLS record header).            -> `protocol`
2. HINT       - we only know the port number (e.g. 22 -> ssh). A port is a
                convention, not proof, so it is shown as a hint. -> `service`
"""

from __future__ import annotations

from typing import Optional

# Well-known service ports. Deliberately short: enough to be useful, easy to explain.
WELL_KNOWN_PORTS = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    67: "dhcp-server",
    68: "dhcp-client",
    80: "http",
    110: "pop3",
    123: "ntp",
    143: "imap",
    443: "https",
    465: "smtps",
    587: "smtp-submission",
    853: "dns-over-tls",
    993: "imaps",
    995: "pop3s",
    1900: "ssdp",
    3306: "mysql",
    3389: "rdp",
    5353: "mdns",
    8080: "http-alt",
}

# Services that are normally wrapped in TLS. If we see binary data on one of these
# ports and could not recognise a TLS header (e.g. the middle of a large TLS record),
# it is almost certainly encrypted, so we say so instead of printing meaningless hex.
ENCRYPTED_SERVICES = {"https", "smtps", "imaps", "pop3s", "dns-over-tls"}

# HTTP/1.x messages start with a method (requests) or "HTTP/1." (responses).
_HTTP_STARTS = (
    b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ", b"PATCH ",
    b"HTTP/1.",
)

# TLS record types (RFC 8446 / RFC 5246, section "record layer").
TLS_RECORD_TYPES = {
    20: "ChangeCipherSpec",
    21: "Alert",
    22: "Handshake",
    23: "Application Data",
}

# First byte of a TLS handshake message.
TLS_HANDSHAKE_TYPES = {
    1: "ClientHello",
    2: "ServerHello",
    4: "NewSessionTicket",
    11: "Certificate",
    16: "ClientKeyExchange",
}


def service_name(port: Optional[int]) -> Optional[str]:
    """Return the conventional service name for a port, or None."""
    if port is None:
        return None
    return WELL_KNOWN_PORTS.get(port)


def guess_service(src_port: Optional[int], dst_port: Optional[int]) -> Optional[str]:
    """Port-based HINT. The destination port is checked first because the
    server side of a connection is usually the well-known port."""
    return service_name(dst_port) or service_name(src_port)


def looks_like_http(payload: bytes) -> bool:
    """True if the payload begins like a plain-text HTTP/1.x request or response."""
    return payload.startswith(_HTTP_STARTS)


def looks_like_tls(payload: bytes) -> bool:
    """True if the payload begins with a valid-looking TLS record header.

    A TLS record header is 5 bytes:  type(1) | version(2) | length(2)
    We check that the type is one of the 4 known values and that the major
    version byte is 3 (SSL 3.0 = 3.0, TLS 1.0 = 3.1 ... TLS 1.3 = 3.4 on the wire).
    """
    return (
        len(payload) >= 5
        and payload[0] in TLS_RECORD_TYPES
        and payload[1] == 3
        and payload[2] <= 4
    )


def describe_tls(payload: bytes) -> str:
    """Human-readable one-liner for a TLS record, e.g. 'TLS Handshake (ClientHello)'.

    Only the unencrypted record header is read. The application data itself is
    encrypted and cannot (and must not) be read by a passive sniffer.
    """
    record = TLS_RECORD_TYPES.get(payload[0], "Record")
    if payload[0] == 22 and len(payload) > 5:
        handshake = TLS_HANDSHAKE_TYPES.get(payload[5])
        if handshake:
            return f"TLS Handshake ({handshake})"
    return f"TLS {record}"
