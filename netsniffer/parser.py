"""Packet parsing: turn a raw Scapy packet into a simple `PacketInfo` object.

Scapy has already split the packet into layers (Ethernet / IP / TCP / ...).
This module walks those layers from the outside in and copies out the fields
we care about. Nothing here prints or stores anything - it is a pure function
of the packet, which makes it easy to test and easy to explain.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from scapy.all import (
    ARP, DNS, ICMP, IP, IPv6, TCP, UDP, Ether, Packet, Padding,
)

from .protocols import (
    describe_tls, guess_service, looks_like_http, looks_like_tls,
)
from .payload import redact_sensitive

# TCP flag bits -> names (RFC 793 + ECN bits from RFC 3168).
_TCP_FLAG_BITS = (
    (0x02, "SYN"), (0x10, "ACK"), (0x01, "FIN"), (0x04, "RST"),
    (0x08, "PSH"), (0x20, "URG"), (0x40, "ECE"), (0x80, "CWR"),
)

_ICMP_TYPES = {
    0: "Echo reply",
    3: "Destination unreachable",
    5: "Redirect",
    8: "Echo request",
    11: "Time exceeded",
}

_DNS_QTYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
    16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS", 255: "ANY",
}


@dataclass
class PacketInfo:
    """Everything the rest of the program needs to know about ONE packet."""

    number: int                       # 1, 2, 3 ... in capture order
    timestamp: float                  # seconds since the epoch (from the capture)
    length: int                       # size of the whole frame in bytes
    protocol: str = "Unknown"         # best label backed by evidence: TCP, DNS, HTTP, TLS, ARP...
    transport: Optional[str] = None   # TCP / UDP / ICMP / ICMPv6 (None for ARP etc.)
    service: Optional[str] = None     # port-based hint, e.g. 'https' (NOT proof)
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    ip_version: Optional[int] = None  # 4, 6, or None
    ttl: Optional[int] = None         # IPv4 TTL / IPv6 hop limit
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    tcp_flags: str = ""               # e.g. 'SYN,ACK'
    info: str = ""                    # one-line human summary
    payload: bytes = b""              # application payload (headers stripped)
    layers: List[str] = field(default_factory=list)  # e.g. ['Ether', 'IP', 'TCP', 'Raw']


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #
def _first(value):
    """Scapy >= 2.5 returns DNS question/answer fields as lists, older versions
    as a single packet. Return the first item either way (or None)."""
    if value is None:
        return None
    if isinstance(value, (list, tuple)):
        return value[0] if value else None
    return value


def _to_text(value) -> str:
    """bytes -> printable-ASCII str for names Scapy returns as bytes (e.g. DNS qname).
    Anything outside printable ASCII becomes '.', so hostile packet data can never
    inject control characters or break a console."""
    if isinstance(value, bytes):
        value = value.decode("latin-1")
    return "".join(ch if 32 <= ord(ch) <= 126 else "." for ch in str(value))


def _addr_text(value) -> str:
    """Address fields are normally str ('192.168.1.1') but Scapy returns raw bytes
    for protocol types it does not understand (malformed / unusual ARP)."""
    if isinstance(value, bytes):
        return value.hex(":")
    return str(value)


def format_tcp_flags(flags: int) -> str:
    """0x12 -> 'SYN,ACK'"""
    names = [name for bit, name in _TCP_FLAG_BITS if flags & bit]
    return ",".join(names)


def extract_payload(pkt: Packet, transport_layer: Packet) -> bytes:
    """Return the application-layer bytes carried by a TCP/UDP segment.

    Ethernet frames shorter than 60 bytes are padded with zeros by the network
    card. Scapy exposes that as a `Padding` layer *inside* the payload, so we
    cut it off - otherwise every empty ACK would look like it carried data.
    """
    payload = transport_layer.payload
    if isinstance(payload, Padding):
        return b""
    data = bytes(payload)
    padding = payload.getlayer(Padding)
    if padding is not None:
        data = data[: len(data) - len(bytes(padding))]
    return data


def _top_layer_name(pkt: Packet) -> str:
    """Name of the last 'real' layer, ignoring Raw/Padding (used for unknown protocols)."""
    for layer in reversed(pkt.layers()):
        if layer.__name__ not in ("Raw", "Padding"):
            return layer.__name__
    return "Unknown"


# --------------------------------------------------------------------------- #
# Per-protocol summaries
# --------------------------------------------------------------------------- #
def _dns_summary(dns: Packet) -> str:
    question = _first(dns.qd)
    # getattr with a default: a corrupted question may not have these fields.
    qname = getattr(question, "qname", None)
    name = _to_text(qname).rstrip(".") if qname is not None else "?"
    qtype = _DNS_QTYPES.get(getattr(question, "qtype", None), "?")
    if dns.qr == 0:
        return f"DNS query {qtype} {name}"
    return f"DNS response {name} ({dns.ancount} answer{'s' if dns.ancount != 1 else ''})"


def _icmp_summary(icmp: Packet) -> str:
    text = _ICMP_TYPES.get(icmp.type, f"type {icmp.type}")
    if icmp.type in (0, 8):  # echo request / reply carry an id and sequence number
        text += f" id={icmp.id} seq={icmp.seq}"
    return f"ICMP {text}"


def _http_summary(payload: bytes) -> str:
    """First line of an HTTP message (request line or status line), redacted and capped."""
    first_line = payload[:120].split(b"\r\n", 1)[0].split(b"\n", 1)[0]
    text = "".join(chr(b) if 32 <= b <= 126 else "." for b in first_line)
    return "HTTP " + redact_sensitive(text)


# --------------------------------------------------------------------------- #
# The main function
# --------------------------------------------------------------------------- #
def parse_packet(pkt: Packet, number: int) -> PacketInfo:
    """Convert one Scapy packet into a PacketInfo (see module docstring)."""
    info = PacketInfo(
        number=number,
        timestamp=float(pkt.time),
        length=len(pkt),
        layers=[layer.__name__ for layer in pkt.layers()],
    )

    # ---- Layer 2: Ethernet (MAC addresses) -------------------------------- #
    if pkt.haslayer(Ether):
        info.src_mac = pkt[Ether].src
        info.dst_mac = pkt[Ether].dst

    # ---- ARP has no IP layer: it maps IP addresses to MAC addresses ------- #
    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        info.protocol = "ARP"
        sender, target = _addr_text(arp.psrc), _addr_text(arp.pdst)
        info.src_ip, info.dst_ip = sender, target
        if arp.op == 1:
            info.info = f"Who has {target}? Tell {sender}"
        elif arp.op == 2:
            info.info = f"{sender} is at {_addr_text(arp.hwsrc)}"
        else:
            info.info = f"ARP opcode {arp.op}"
        return info

    # ---- Layer 3: IPv4 / IPv6 --------------------------------------------- #
    if pkt.haslayer(IP):
        ip = pkt[IP]
        info.ip_version, info.ttl = 4, ip.ttl
        info.src_ip, info.dst_ip = ip.src, ip.dst
    elif pkt.haslayer(IPv6):
        ip = pkt[IPv6]
        info.ip_version, info.ttl = 6, ip.hlim
        info.src_ip, info.dst_ip = ip.src, ip.dst
    else:
        # Not an IP packet (STP, LLC, raw 802.11 ...): report what Scapy calls it.
        info.protocol = _top_layer_name(pkt)
        info.info = f"{info.protocol} frame"
        return info

    # ---- Layer 4: TCP / UDP / ICMP ---------------------------------------- #
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        info.transport = info.protocol = "TCP"
        info.src_port, info.dst_port = tcp.sport, tcp.dport
        info.tcp_flags = format_tcp_flags(int(tcp.flags))
        info.payload = extract_payload(pkt, tcp)
        info.service = guess_service(info.src_port, info.dst_port)

        # Application layer: evidence from the first payload bytes.
        if looks_like_tls(info.payload):
            info.protocol = "TLS"
            info.info = describe_tls(info.payload)
        elif looks_like_http(info.payload):
            info.protocol = "HTTP"
            info.info = _http_summary(info.payload)
        else:
            info.info = f"[{info.tcp_flags}]" if info.tcp_flags else "TCP segment"

    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        info.transport = info.protocol = "UDP"
        info.src_port, info.dst_port = udp.sport, udp.dport
        info.payload = extract_payload(pkt, udp)
        info.service = guess_service(info.src_port, info.dst_port)

        if pkt.haslayer(DNS):
            info.protocol = "DNS"
            info.info = _dns_summary(pkt[DNS])
        else:
            info.info = f"UDP datagram, {len(info.payload)} bytes"

    elif pkt.haslayer(ICMP):
        info.transport = info.protocol = "ICMP"
        info.info = _icmp_summary(pkt[ICMP])

    else:
        # ICMPv6 has many layer classes (ICMPv6EchoRequest, ICMPv6ND_NS ...);
        # they all start with "ICMPv6".
        icmp6 = next(
            (l for l in pkt.iterpayloads() if l.__class__.__name__.startswith("ICMPv6")),
            None,
        )
        if icmp6 is not None:
            info.transport = info.protocol = "ICMPv6"
            info.info = _to_text(icmp6.name)
        else:
            info.protocol = _top_layer_name(pkt)
            info.info = f"{info.protocol} packet"

    return info
