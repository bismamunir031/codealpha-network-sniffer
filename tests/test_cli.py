"""End-to-end tests: build a small .pcap, run the real CLI on it, check the output.

--read mode uses exactly the same parse -> stats -> display pipeline as live
capture, and needs no administrator rights, so it is ideal for automated tests.
"""

import pytest
from scapy.all import DNS, DNSQR, IP, TCP, UDP, Ether, Raw, wrpcap

from netsniffer.capture import CaptureError, resolve_interface
from netsniffer.cli import main


@pytest.fixture
def sample_pcap(tmp_path):
    packets = [
        Ether() / IP(src="10.0.0.5", dst="93.184.216.34") / TCP(sport=40000, dport=80, flags="S"),
        Ether() / IP(src="10.0.0.5", dst="93.184.216.34") / TCP(sport=40000, dport=80, flags="PA")
        / Raw(b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        Ether() / IP(src="10.0.0.5", dst="8.8.8.8") / UDP(sport=5000, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.com")),
    ]
    path = tmp_path / "sample.pcap"
    wrpcap(str(path), packets)
    return str(path)


def test_read_pcap_end_to_end(sample_pcap, capsys):
    assert main(["-r", sample_pcap, "--no-color"]) == 0
    out = capsys.readouterr().out
    assert "10.0.0.5:40000" in out and "93.184.216.34:80" in out
    assert "HTTP GET /index.html" in out
    assert "DNS query A example.com" in out
    assert "CAPTURE SUMMARY" in out and "Packets captured : 3" in out


def test_count_limit(sample_pcap, capsys):
    main(["-r", sample_pcap, "-c", "2", "--no-color"])
    assert "Packets captured : 2" in capsys.readouterr().out


def test_no_payload_flag_hides_payload(sample_pcap, capsys):
    main(["-r", sample_pcap, "--no-color", "--no-payload"])
    assert "payload (" not in capsys.readouterr().out


def test_verbose_mode(sample_pcap, capsys):
    main(["-r", sample_pcap, "--no-color", "-v"])
    out = capsys.readouterr().out
    assert "Layers   : Ether / IP / TCP" in out and "TTL 64" in out


def test_missing_file_is_a_clean_error(capsys):
    assert main(["-r", "does_not_exist.pcap"]) == 1
    captured = capsys.readouterr()
    assert "not found" in captured.err
    assert "CodeAlpha Basic Network Sniffer" not in captured.out   # no banner before the error


def test_garbage_file_is_a_clean_error(tmp_path, capsys):
    bad = tmp_path / "bad.pcap"
    bad.write_bytes(b"this is not a pcap file at all")
    assert main(["-r", str(bad)]) == 1
    assert "Error" in capsys.readouterr().err


def test_bad_interface_is_a_clean_error(capsys):
    assert main(["-i", "definitely-not-an-interface"]) == 1
    assert "not found" in capsys.readouterr().err


def test_resolve_interface_raises_capture_error():
    with pytest.raises(CaptureError):
        resolve_interface("definitely-not-an-interface")


def test_read_conflicts_with_write(sample_pcap):
    with pytest.raises(SystemExit) as exc:
        main(["-r", sample_pcap, "-w", "out.pcap"])
    assert exc.value.code == 2


@pytest.mark.parametrize("bad_args", [["-c", "0"], ["-c", "-5"], ["-t", "0"], ["--payload-bytes", "0"], ["--payload-bytes", "9999"]])
def test_invalid_numbers_rejected(bad_args):
    with pytest.raises(SystemExit) as exc:
        main(bad_args)
    assert exc.value.code == 2


def test_list_interfaces(capsys):
    assert main(["--list-interfaces"]) == 0
    assert "NAME" in capsys.readouterr().out


def test_write_folder_must_exist(capsys):
    assert main(["-w", "/no/such/folder/out.pcap"]) == 1
    assert "folder does not exist" in capsys.readouterr().err
