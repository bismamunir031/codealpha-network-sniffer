"""Command-line interface and the main program flow.

    parse arguments -> open capture (live or .pcap) -> for every packet:
        save to PCAP (optional) -> parse -> update statistics -> print
    -> when capture ends: print summary
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional

from . import __version__
from .capture import (
    CaptureError, interface_label, list_interfaces, resolve_interface, run_capture,
)
from .display import (
    DisplayOptions, Painter, color_supported, format_banner, format_interfaces,
    format_packet, format_summary, format_table_header,
)
from .parser import parse_packet
from .pcap_sink import PcapSink
from .stats import PacketStats

EXAMPLES = """\
examples:
  python sniffer.py --list-interfaces
  sudo python3 sniffer.py -i eth0 -c 20
  sudo python3 sniffer.py -f "tcp port 80" -v
  sudo python3 sniffer.py -f "udp port 53" -t 30 -w dns.pcap
  python sniffer.py -r dns.pcap            (analyse a saved capture - no admin rights needed)
"""


# --------------------------------------------------------------------------- #
# Argument parsing
# --------------------------------------------------------------------------- #
def _positive_int(text: str) -> int:
    value = int(text)
    if value < 1:
        raise argparse.ArgumentTypeError("must be 1 or greater")
    return value


def _positive_float(text: str) -> float:
    value = float(text)
    if value <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return value


def _payload_size(text: str) -> int:
    value = int(text)
    if not 1 <= value <= 512:
        raise argparse.ArgumentTypeError("must be between 1 and 512")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sniffer.py",
        description="CodeAlpha Basic Network Sniffer - passive packet capture and analysis.",
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    src = parser.add_argument_group("capture source")
    src.add_argument("-i", "--interface", help="interface to capture on (default: system default)")
    src.add_argument("-l", "--list-interfaces", action="store_true", help="list interfaces and exit")
    src.add_argument("-r", "--read", metavar="FILE", help="analyse a saved .pcap file instead of live traffic")

    ctl = parser.add_argument_group("capture control")
    ctl.add_argument("-c", "--count", type=_positive_int, default=0, help="stop after N packets (default: unlimited)")
    ctl.add_argument("-t", "--timeout", type=_positive_float, help="stop after N seconds")
    ctl.add_argument("-f", "--filter", metavar="BPF", help="BPF filter, e.g. 'tcp port 80' or 'udp and port 53'")
    ctl.add_argument("-w", "--write", metavar="FILE", help="also save captured packets to a .pcap file")

    out = parser.add_argument_group("output")
    out.add_argument("-v", "--verbose", action="store_true", help="detailed multi-line view of every packet")
    out.add_argument("--no-payload", action="store_true", help="do not show payload previews")
    out.add_argument("--payload-bytes", type=_payload_size, default=64, metavar="N",
                     help="payload bytes to preview (1-512, default 64)")
    out.add_argument("--no-color", action="store_true", help="disable coloured output")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


# --------------------------------------------------------------------------- #
# Per-packet handler
# --------------------------------------------------------------------------- #
class PacketHandler:
    """Callable that Scapy invokes once for every captured packet."""

    def __init__(self, stats: PacketStats, painter: Painter, options: DisplayOptions, writer=None):
        self.stats = stats
        self.painter = painter
        self.options = options
        self.writer = writer
        self.number = 0

    def __call__(self, pkt) -> None:
        self.number += 1

        # 1. Save the untouched packet first, so the .pcap is complete even
        #    if our own parsing fails on it.
        if self.writer is not None:
            self.writer.write(pkt)

        # 2. Parse. One malformed packet must never crash the whole capture.
        try:
            info = parse_packet(pkt, self.number)
        except Exception:  # noqa: BLE001 - deliberate: any dissection problem is non-fatal
            self.stats.record_parse_error()
            return

        # 3. Statistics + display.
        self.stats.update(info)
        print(format_packet(info, self.painter, self.options), flush=True)


# --------------------------------------------------------------------------- #
# Main flow
# --------------------------------------------------------------------------- #
def _limit_text(count: int, timeout: Optional[float]) -> str:
    parts = []
    if count:
        parts.append(f"{count} packets")
    if timeout:
        parts.append(f"{timeout:g} seconds")
    return " or ".join(parts) if parts else "until Ctrl+C"


def _run(args: argparse.Namespace, painter: Painter) -> int:
    options = DisplayOptions(
        verbose=args.verbose,
        show_payload=not args.no_payload,
        payload_bytes=args.payload_bytes,
    )

    if args.read:
        # Validate BEFORE printing the banner so a typo gives one clean error.
        if not os.path.isfile(args.read):
            raise CaptureError(f"Capture file not found: {args.read}")
        iface, source = None, f"file: {args.read}"
    else:
        iface = resolve_interface(args.interface)
        source = f"interface: {interface_label(iface)}"

    writer = PcapSink(args.write) if args.write else None
    stats = PacketStats()
    handler = PacketHandler(stats, painter, options, writer)

    print(format_banner(source, args.filter, _limit_text(args.count, args.timeout), options))
    if not options.verbose:
        print(format_table_header())

    try:
        run_capture(
            handler,
            iface=iface,
            bpf_filter=args.filter,
            count=args.count,
            timeout=args.timeout,
            offline=args.read,
        )
    finally:
        if writer is not None:
            writer.close()

    print(format_summary(stats))
    if writer is not None:
        if writer.count:
            print(f"\nSaved {writer.count} packets to {args.write}")
            print("Warning: a .pcap contains full packet contents (possibly passwords or personal data). "
                  "Store it securely and do not publish it.")
        else:
            print("\nNo packets captured - no .pcap file was written.")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.read and (args.interface or args.write):
        parser.error("--read cannot be combined with --interface or --write")

    # Never crash on a character the console cannot display.
    try:
        sys.stdout.reconfigure(errors="replace")
    except (AttributeError, ValueError):
        pass

    painter = Painter(color_supported(args.no_color))
    try:
        if args.list_interfaces:
            print(format_interfaces(list_interfaces()))
            return 0
        return _run(args, painter)
    except CaptureError as exc:
        print(painter.paint("Error: ", "error") + str(exc), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130
