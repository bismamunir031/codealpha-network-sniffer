from netsniffer.parser import PacketInfo
from netsniffer.stats import PacketStats


def make(protocol="TCP", length=100, ts=0.0, src="1.1.1.1", dst="2.2.2.2", dport=443, transport="TCP"):
    return PacketInfo(number=1, timestamp=ts, length=length, protocol=protocol,
                      transport=transport, src_ip=src, dst_ip=dst, dst_port=dport)


def test_empty_stats_are_safe():
    s = PacketStats()
    assert (s.total_packets, s.average_size, s.duration, s.packets_per_second) == (0, 0.0, 0.0, 0.0)


def test_totals_and_size_range():
    s = PacketStats()
    for length in (60, 100, 140):
        s.update(make(length=length))
    assert s.total_packets == 3 and s.total_bytes == 300
    assert (s.min_size, s.max_size, s.average_size) == (60, 140, 100.0)


def test_duration_and_rate_use_packet_timestamps():
    s = PacketStats()
    s.update(make(ts=100.0))
    s.update(make(ts=102.0))
    s.update(make(ts=104.0))
    assert s.duration == 4.0
    assert s.packets_per_second == 0.75


def test_protocol_and_top_counters():
    s = PacketStats()
    s.update(make("TCP", 100, src="10.0.0.1", dst="10.0.0.9", dport=443))
    s.update(make("TCP", 50, src="10.0.0.1", dst="10.0.0.9", dport=443))
    s.update(make("DNS", 80, src="10.0.0.2", dst="8.8.8.8", dport=53, transport="UDP"))
    assert s.protocol_packets == {"TCP": 2, "DNS": 1}
    assert s.protocol_bytes["TCP"] == 150
    assert s.top(s.src_ips, 1) == [("10.0.0.1", 2)]
    assert s.top(s.dst_ports, 1) == [(("TCP", 443), 2)]


def test_arp_has_no_port_entry():
    s = PacketStats()
    s.update(PacketInfo(number=1, timestamp=0, length=42, protocol="ARP", src_ip="1.1.1.1", dst_ip="1.1.1.2"))
    assert not s.dst_ports and s.total_packets == 1


def test_parse_errors_counted_separately():
    s = PacketStats()
    s.record_parse_error()
    assert s.parse_errors == 1 and s.total_packets == 0
