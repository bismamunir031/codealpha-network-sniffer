"""Everything that turns data into text for the terminal.

Functions here RETURN strings; only cli.py actually prints. Output is kept to
plain ASCII so it never crashes on older Windows consoles (cp1252 etc.).
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional

from . import __version__
from .parser import PacketInfo
from .payload import describe_payload, hexdump, is_mostly_text, printable_preview
from .stats import PacketStats
from .capture import InterfaceInfo
from .protocols import ENCRYPTED_SERVICES, service_name

RESET = "\033[0m"
_COLORS = {
    "TCP": "\033[36m",      # cyan
    "UDP": "\033[34m",      # blue
    "DNS": "\033[32m",      # green
    "HTTP": "\033[33m",     # yellow
    "TLS": "\033[35m",      # magenta
    "ICMP": "\033[31m",     # red
    "ICMPv6": "\033[31m",
    "ARP": "\033[93m",      # bright yellow
    "bold": "\033[1m",
    "dim": "\033[2m",
    "warn": "\033[33m",
    "error": "\033[31m",
}


class Painter:
    """Adds ANSI colours to text - or leaves it untouched when colour is off."""

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def paint(self, text: str, style: str) -> str:
        code = _COLORS.get(style)
        if not self.enabled or code is None:
            return text
        return f"{code}{text}{RESET}"


def color_supported(force_off: bool = False) -> bool:
    """Decide whether to use colours: only on a real terminal, and respect NO_COLOR."""
    if force_off or "NO_COLOR" in os.environ or not sys.stdout.isatty():
        return False
    if os.name == "nt":
        # Running an empty command switches the Windows 10+ console into ANSI mode.
        os.system("")
    return True


@dataclass
class DisplayOptions:
    verbose: bool = False
    show_payload: bool = True
    payload_bytes: int = 64


# --------------------------------------------------------------------------- #
# Small formatting helpers
# --------------------------------------------------------------------------- #
def human_bytes(n: float) -> str:
    """1536 -> '1.5 KB'"""
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"  # pragma: no cover


def format_time(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp).strftime("%H:%M:%S.%f")[:-3]


def format_endpoint(ip: Optional[str], port: Optional[int]) -> str:
    """'1.2.3.4:80', '[fe80::1]:443' (IPv6 needs brackets), or just the IP, or '-'."""
    if not ip:
        return "-"
    if port is None:
        return ip
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


def _likely_encrypted(info: PacketInfo, opts: DisplayOptions) -> bool:
    """Binary payload on a normally-encrypted port (e.g. 443) = TLS data we cannot read."""
    return (
        info.service in ENCRYPTED_SERVICES
        and not is_mostly_text(info.payload[: opts.payload_bytes])
    )


def _payload_line(info: PacketInfo, opts: DisplayOptions) -> Optional[str]:
    """One-line payload preview for the compact view (None = nothing to show)."""
    if not opts.show_payload or not info.payload:
        return None
    size = len(info.payload)
    if info.protocol == "DNS":
        return None  # the INFO column already decodes DNS
    if info.protocol == "TLS":
        return f"payload: {size} bytes of TLS (encrypted or binary - not displayed)"
    if _likely_encrypted(info, opts):
        return f"payload: {size} bytes, likely encrypted TLS data (not displayed)"
    kind, text = describe_payload(info.payload, opts.payload_bytes)
    label = "text" if kind == "text" else "binary/hex"
    return f"payload ({size} bytes, {label}): {text}"


# --------------------------------------------------------------------------- #
# Packet views
# --------------------------------------------------------------------------- #
def format_table_header() -> str:
    return (
        f"{'NO':>5}  {'TIME':<12}  {'PROTO':<7}  {'SOURCE':<22}  {'DESTINATION':<22}  "
        f"{'LEN':>5}  INFO\n" + "-" * 100
    )


def format_packet(info: PacketInfo, painter: Painter, opts: DisplayOptions) -> str:
    """Choose compact or verbose view."""
    if opts.verbose:
        return _format_verbose(info, painter, opts)
    return _format_compact(info, painter, opts)


def _format_compact(info: PacketInfo, painter: Painter, opts: DisplayOptions) -> str:
    proto = painter.paint(f"{info.protocol[:7]:<7}", info.protocol)
    text = info.info
    if info.service and info.protocol in ("TCP", "UDP"):
        text += f" ({info.service})"
    line = (
        f"{info.number:>5}  {format_time(info.timestamp)}  {proto}  "
        f"{format_endpoint(info.src_ip, info.src_port):<22}  "
        f"{format_endpoint(info.dst_ip, info.dst_port):<22}  "
        f"{info.length:>5}  {text}"
    )
    payload = _payload_line(info, opts)
    if payload:
        line += "\n" + painter.paint(" " * 7 + "|- " + payload, "dim")
    return line


def _format_verbose(info: PacketInfo, painter: Painter, opts: DisplayOptions) -> str:
    lines = [
        "-" * 78,
        painter.paint(
            f"Packet #{info.number} | {format_time(info.timestamp)} | {info.length} bytes",
            "bold",
        ),
        f"  Layers   : {' / '.join(info.layers)}",
    ]
    if info.src_mac:
        lines.append(f"  Ethernet : {info.src_mac} -> {info.dst_mac}")
    if info.ip_version:
        ttl_name = "TTL" if info.ip_version == 4 else "Hop limit"
        lines.append(
            f"  IPv{info.ip_version}     : {info.src_ip} -> {info.dst_ip}  ({ttl_name} {info.ttl})"
        )
    elif info.protocol == "ARP":
        lines.append(f"  ARP      : {info.src_ip} -> {info.dst_ip}")
    if info.src_port is not None:
        hint = ""
        if info.service:
            hint = f"  (service hint: {info.service})"
        flags = f"  flags [{info.tcp_flags}]" if info.tcp_flags else ""
        lines.append(
            f"  {info.transport:<8} : port {info.src_port} -> {info.dst_port}{flags}{hint}"
        )
    lines.append(f"  Protocol : {painter.paint(info.protocol, info.protocol)}")
    lines.append(f"  Info     : {info.info}")

    if opts.show_payload:
        size = len(info.payload)
        if size == 0:
            lines.append("  Payload  : none (headers only)")
        elif info.protocol == "DNS":
            lines.append(f"  Payload  : {size} bytes of DNS (decoded in Info above)")
        elif info.protocol == "TLS":
            lines.append(f"  Payload  : {size} bytes of TLS (encrypted or binary - not displayed)")
        elif _likely_encrypted(info, opts):
            lines.append(f"  Payload  : {size} bytes, likely encrypted TLS data (not displayed)")
        else:
            shown = info.payload[: opts.payload_bytes]
            if is_mostly_text(shown):
                lines.append(f"  Payload  : {size} bytes, text preview (secrets redacted):")
                lines.append("    " + printable_preview(info.payload, opts.payload_bytes))
            else:
                lines.append(f"  Payload  : {size} bytes, binary - hexdump of first {len(shown)} bytes:")
                lines.extend("    " + row for row in hexdump(shown).splitlines())
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Banner, interface list, summary
# --------------------------------------------------------------------------- #
def format_banner(source: str, bpf_filter: Optional[str], limit_text: str, opts: DisplayOptions) -> str:
    payload_text = f"{opts.payload_bytes} bytes" if opts.show_payload else "off"
    return "\n".join([
        f"CodeAlpha Basic Network Sniffer v{__version__}  (passive capture only)",
        f"  Source          : {source}",
        f"  BPF filter      : {bpf_filter or '(none - all packets)'}",
        f"  Limit           : {limit_text}",
        f"  Payload preview : {payload_text}",
        "  Use only on networks you own or are authorised to monitor.",
        "",
    ])


def format_interfaces(interfaces: List[InterfaceInfo]) -> str:
    rows = [f"{'NAME':<24} {'IP ADDRESS':<18} {'MAC ADDRESS':<18} DESCRIPTION", "-" * 90]
    for iface in interfaces:
        desc = iface.description if iface.description != iface.name else ""
        rows.append(f"{iface.name:<24} {iface.ip or '-':<18} {iface.mac or '-':<18} {desc}")
    return "\n".join(rows)


def _bar(fraction: float, width: int = 20) -> str:
    return "#" * max(1, round(fraction * width)) if fraction > 0 else ""


def format_summary(stats: PacketStats, top_n: int = 5) -> str:
    """The end-of-capture statistics report."""
    lines = ["", "=" * 30 + " CAPTURE SUMMARY " + "=" * 30]
    if stats.total_packets == 0:
        lines.append("No packets were captured.")
        if stats.parse_errors:
            lines.append(f"Packets that could not be parsed: {stats.parse_errors}")
        return "\n".join(lines)

    lines += [
        f"Packets captured : {stats.total_packets}",
        f"Total data       : {human_bytes(stats.total_bytes)} ({stats.total_bytes:,} bytes)",
        f"Packet size      : min {stats.min_size} B | avg {stats.average_size:.1f} B | max {stats.max_size} B",
        f"Duration         : {stats.duration:.2f} s ({stats.packets_per_second:.1f} packets/s)",
    ]
    if stats.parse_errors:
        lines.append(f"Unparsed packets : {stats.parse_errors} (malformed or unsupported)")

    lines += ["", "Protocol distribution", f"  {'PROTOCOL':<9}{'PACKETS':>8}{'SHARE':>8}{'BYTES':>12}"]
    for proto, count in stats.protocol_packets.most_common():
        share = count / stats.total_packets
        lines.append(
            f"  {proto:<9}{count:>8}{share * 100:>7.1f}%{human_bytes(stats.protocol_bytes[proto]):>12}  {_bar(share)}"
        )

    lines += ["", f"Top {top_n} source IPs"]
    lines += [f"  {ip:<40}{n:>6} packets" for ip, n in stats.top(stats.src_ips, top_n)] or ["  (none)"]
    lines += ["", f"Top {top_n} destination IPs"]
    lines += [f"  {ip:<40}{n:>6} packets" for ip, n in stats.top(stats.dst_ips, top_n)] or ["  (none)"]

    lines += ["", f"Top {top_n} destination ports"]
    port_rows = []
    for (transport, port), n in stats.top(stats.dst_ports, top_n):
        name = service_name(port)
        label = f"{transport}/{port}" + (f" ({name})" if name else "")
        port_rows.append(f"  {label:<40}{n:>6} packets")
    lines += port_rows or ["  (none)"]
    return "\n".join(lines)
