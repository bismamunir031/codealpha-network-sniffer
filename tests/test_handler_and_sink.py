import os

from scapy.all import IP, TCP, Ether, Raw, rdpcap

from netsniffer import cli
from netsniffer.cli import PacketHandler
from netsniffer.display import DisplayOptions, Painter
from netsniffer.pcap_sink import PcapSink
from netsniffer.stats import PacketStats
from tests.helpers import dissect


def _handler(writer=None):
    return PacketHandler(PacketStats(), Painter(False), DisplayOptions(), writer)


def test_malformed_packet_is_counted_not_fatal(monkeypatch, capsys):
    handler = _handler()
    pkt = dissect(Ether() / IP() / TCP())

    def boom(*_args, **_kwargs):
        raise ValueError("simulated dissection failure")

    monkeypatch.setattr(cli, "parse_packet", boom)
    handler(pkt)                                    # must not raise
    assert handler.stats.parse_errors == 1
    assert handler.stats.total_packets == 0
    assert capsys.readouterr().out == ""


def test_pcap_written_even_if_parsing_fails(monkeypatch, tmp_path):
    sink = PcapSink(str(tmp_path / "x.pcap"))
    handler = _handler(sink)
    monkeypatch.setattr(cli, "parse_packet", lambda *a, **k: 1 / 0)
    handler(dissect(Ether() / IP() / TCP()))
    sink.close()
    assert sink.count == 1                          # raw packet was still saved


def test_pcap_sink_round_trip(tmp_path):
    path = str(tmp_path / "out.pcap")
    sink = PcapSink(path)
    assert not os.path.exists(path)                 # lazy: nothing created yet
    sink.write(Ether() / IP(src="1.2.3.4") / TCP() / Raw(b"abc"))
    sink.write(Ether() / IP(src="5.6.7.8") / TCP())
    sink.close()
    packets = rdpcap(path)
    assert len(packets) == 2 and packets[0][IP].src == "1.2.3.4"


def test_empty_capture_creates_no_file(tmp_path):
    path = str(tmp_path / "never.pcap")
    sink = PcapSink(path)
    sink.close()
    assert not os.path.exists(path)
