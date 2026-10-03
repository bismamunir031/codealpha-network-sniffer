from scapy.all import (
    ARP, DNS, DNSQR, DNSRR, ICMP, IP, IPv6, TCP, UDP, Ether, Padding, Raw,
    ICMPv6EchoRequest,
)

from netsniffer.parser import format_tcp_flags, parse_packet
from tests.helpers import dissect

CLIENT, SERVER = "192.168.1.10", "93.184.216.34"


def test_tcp_syn_fields():
    pkt = dissect(Ether() / IP(src=CLIENT, dst=SERVER, ttl=57) / TCP(sport=51544, dport=443, flags="S"))
    info = parse_packet(pkt, 1)
    assert (info.protocol, info.transport) == ("TCP", "TCP")
    assert (info.src_ip, info.dst_ip) == (CLIENT, SERVER)
    assert (info.src_port, info.dst_port) == (51544, 443)
    assert info.ip_version == 4 and info.ttl == 57
    assert info.tcp_flags == "SYN"
    assert info.service == "https"          # port hint only
    assert info.length == len(pkt)
    assert info.layers[:3] == ["Ether", "IP", "TCP"]


def test_ethernet_padding_is_not_reported_as_payload():
    # A short ACK gets zero-padded to 60 bytes on the wire.
    pkt = dissect(Ether() / IP() / TCP(flags="A") / Padding(b"\x00" * 6))
    assert parse_packet(pkt, 1).payload == b""


def test_real_payload_kept_and_padding_removed():
    pkt = dissect(Ether() / IP() / TCP() / Raw(b"hello") / Padding(b"\x00\x00"))
    assert parse_packet(pkt, 1).payload == b"hello"


def test_http_request_detected_and_secrets_redacted():
    body = b"GET /login?password=hunter2 HTTP/1.1\r\nHost: example.com\r\n\r\n"
    pkt = dissect(Ether() / IP() / TCP(dport=80, flags="PA") / Raw(body))
    info = parse_packet(pkt, 1)
    assert info.protocol == "HTTP"
    assert "GET /login" in info.info
    assert "hunter2" not in info.info
    assert "[REDACTED]" in info.info


def test_http_response_detected():
    pkt = dissect(Ether() / IP() / TCP(sport=80, flags="PA") / Raw(b"HTTP/1.1 200 OK\r\n\r\n"))
    info = parse_packet(pkt, 1)
    assert info.protocol == "HTTP" and "200 OK" in info.info


def test_tls_client_hello_detected():
    # record header: handshake(22), TLS1.0 (3,1), length 5; handshake type 1 = ClientHello
    record = bytes([22, 3, 1, 0, 5, 1, 0, 0, 1, 0])
    pkt = dissect(Ether() / IP() / TCP(dport=443, flags="PA") / Raw(record))
    info = parse_packet(pkt, 1)
    assert info.protocol == "TLS"
    assert "ClientHello" in info.info


def test_tls_on_unusual_port_still_detected():
    record = bytes([23, 3, 3, 0, 4, 1, 2, 3, 4])   # application data
    pkt = dissect(Ether() / IP() / TCP(dport=8443, flags="PA") / Raw(record))
    assert parse_packet(pkt, 1).protocol == "TLS"


def test_non_tls_binary_on_443_is_not_labelled_tls():
    pkt = dissect(Ether() / IP() / TCP(dport=443, flags="PA") / Raw(b"\x99\x99\x99\x99\x99\x99"))
    assert parse_packet(pkt, 1).protocol == "TCP"


def test_dns_query():
    pkt = dissect(Ether() / IP(dst="8.8.8.8") / UDP(sport=5353, dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com")))
    info = parse_packet(pkt, 1)
    assert info.protocol == "DNS" and info.transport == "UDP"
    assert info.info == "DNS query A example.com"


def test_dns_response_counts_answers():
    dns = DNS(qr=1, qd=DNSQR(qname="example.com"), an=DNSRR(rrname="example.com", rdata="93.184.216.34"))
    pkt = dissect(Ether() / IP() / UDP(sport=53, dport=5353) / dns)
    info = parse_packet(pkt, 1)
    assert info.protocol == "DNS"
    assert "response example.com (1 answer)" in info.info


def test_plain_udp():
    pkt = dissect(Ether() / IP() / UDP(sport=40000, dport=9999) / Raw(b"hi there"))
    info = parse_packet(pkt, 1)
    assert info.protocol == "UDP" and info.payload == b"hi there"
    assert info.service is None


def test_icmp_echo_request():
    pkt = dissect(Ether() / IP(dst="8.8.8.8") / ICMP(type=8, id=1, seq=7))
    info = parse_packet(pkt, 1)
    assert info.protocol == "ICMP"
    assert "Echo request" in info.info and "seq=7" in info.info
    assert info.src_port is None


def test_arp_request():
    pkt = dissect(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, psrc="192.168.1.5", pdst="192.168.1.1"))
    info = parse_packet(pkt, 1)
    assert info.protocol == "ARP"
    assert (info.src_ip, info.dst_ip) == ("192.168.1.5", "192.168.1.1")
    assert "Who has 192.168.1.1" in info.info


def test_ipv6_tcp():
    pkt = dissect(Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2", hlim=60) / TCP(sport=1234, dport=22, flags="S"))
    info = parse_packet(pkt, 1)
    assert info.ip_version == 6 and info.ttl == 60
    assert (info.src_ip, info.protocol, info.service) == ("2001:db8::1", "TCP", "ssh")


def test_icmpv6():
    pkt = dissect(Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2") / ICMPv6EchoRequest())
    info = parse_packet(pkt, 1)
    assert info.protocol == "ICMPv6" and "Echo Request" in info.info


def test_non_ip_frame_does_not_crash():
    pkt = dissect(Ether(type=0x9999) / Raw(b"whatever"))
    info = parse_packet(pkt, 1)
    assert info.src_ip is None
    assert info.protocol != ""


def test_tcp_flag_formatting():
    assert format_tcp_flags(0x12) == "SYN,ACK"
    assert format_tcp_flags(0x19) == "ACK,FIN,PSH"
    assert format_tcp_flags(0) == ""


# ---- regression tests for bugs found by fuzzing malformed packets ---------- #
def test_dns_with_corrupted_question_does_not_crash():
    # DNS header claims 1 question, but the bytes after it are not a valid name.
    header = bytes.fromhex("1234 0100 0001 0000 0000 0000")
    pkt = dissect(Ether() / IP() / UDP(sport=5000, dport=53) / Raw(header + b"\xff\xff\xff"))
    info = parse_packet(pkt, 1)          # must not raise
    assert info.transport == "UDP"


def test_arp_with_unknown_protocol_type_does_not_crash():
    # Build a normal ARP frame, then patch the 'protocol type' field (bytes 16-17 of
    # the frame) to a value Scapy does not know. Patching raw bytes works on every
    # Scapy version.
    raw = bytearray(bytes(Ether() / ARP(op=1, psrc="1.2.3.4", pdst="5.6.7.8")))
    raw[16:18] = b"\x12\x34"
    info = parse_packet(Ether(bytes(raw)), 1)
    assert info.protocol == "ARP"
    assert isinstance(info.src_ip, str) and isinstance(info.dst_ip, str)


def test_raw_only_packet_undissectable_frame():
    # Scapy hands us a bare Raw packet when it cannot even parse Ethernet.
    info = parse_packet(Raw(b"abc"), 1)
    assert info.src_ip is None and info.protocol
