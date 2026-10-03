"""Packet capture: a thin, well-behaved wrapper around Scapy's `sniff()`.

This module is the ONLY place that talks to the network interface. Its jobs:
  * list / validate network interfaces
  * start a passive capture (live or from a .pcap file)
  * turn confusing low-level exceptions into clear, actionable messages
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from typing import Callable, List, Optional

from scapy.all import conf, sniff
from scapy.error import Scapy_Exception


class CaptureError(Exception):
    """A problem the user can fix (permissions, bad interface, bad filter...).
    The message is written for humans and is printed as-is by the CLI."""


@dataclass
class InterfaceInfo:
    name: str
    description: str
    ip: str
    mac: str


# --------------------------------------------------------------------------- #
# Interfaces
# --------------------------------------------------------------------------- #
def list_interfaces() -> List[InterfaceInfo]:
    """All interfaces Scapy can see (works on Windows, Linux and macOS)."""
    result = []
    for iface in conf.ifaces.values():
        result.append(
            InterfaceInfo(
                name=str(iface.name),
                description=str(getattr(iface, "description", "") or ""),
                ip=str(getattr(iface, "ip", "") or ""),
                mac=str(getattr(iface, "mac", "") or ""),
            )
        )
    return sorted(result, key=lambda i: i.name.lower())


def resolve_interface(name: Optional[str]):
    """Return a Scapy interface object.

    * name=None  -> Scapy's default interface (normally the one with the default route)
    * otherwise  -> the interface with that name/description, or CaptureError
    """
    if name is None:
        return conf.iface
    try:
        return conf.ifaces.dev_from_name(name)
    except (ValueError, KeyError) as exc:
        raise CaptureError(
            f"Network interface '{name}' was not found.\n"
            "Run:  python sniffer.py --list-interfaces   to see valid names."
        ) from exc


def interface_label(iface) -> str:
    """Printable name for an interface object."""
    return str(getattr(iface, "name", iface))


# --------------------------------------------------------------------------- #
# Error translation
# --------------------------------------------------------------------------- #
def _permission_help() -> str:
    if sys.platform.startswith("win"):
        return (
            "Permission denied. Open the terminal with 'Run as administrator' and make sure\n"
            "Npcap is installed (https://npcap.com)."
        )
    if sys.platform == "darwin":
        return (
            "Permission denied. Run with sudo, e.g.  sudo python3 sniffer.py\n"
            "(if you use a virtual environment: sudo venv/bin/python sniffer.py)"
        )
    return (
        "Permission denied - packet capture needs raw-socket access on Linux.\n"
        "Run with sudo, e.g.  sudo python3 sniffer.py\n"
        "(if you use a virtual environment: sudo venv/bin/python sniffer.py)"
    )


def _explain_error(exc: Exception) -> str:
    """Map low-level Scapy / OS errors to friendly text."""
    text = str(exc)
    low = text.lower()
    if "winpcap" in low or "npcap" in low or "layer 2" in low:
        return (
            "Packet capture driver not found. On Windows install Npcap from https://npcap.com\n"
            "(tick 'WinPcap API-compatible mode'), then restart the terminal.\n"
            f"Details: {text}"
        )
    if "libpcap is not available" in low or "tcpdump is not available" in low or "tcpdump" in low:
        return (
            "Filtering needs libpcap/tcpdump, which was not found.\n"
            "Linux: sudo apt install tcpdump  |  macOS: preinstalled  |  Windows: install Npcap.\n"
            f"Details: {text}"
        )
    if "filter" in low:
        return (
            "The BPF filter is not valid. Check its syntax, e.g. 'tcp port 80' or 'udp and port 53'.\n"
            f"Details: {text}"
        )
    if "not a supported capture file" in low or "bad magic" in low:
        return f"The file is not a valid .pcap/.pcapng capture. Details: {text}"
    if "no such device" in low or "unknown network interface" in low:
        return f"Network interface not available. Details: {text}"
    return f"Capture failed: {text}"


# --------------------------------------------------------------------------- #
# The capture itself
# --------------------------------------------------------------------------- #
def run_capture(
    handler: Callable,
    *,
    iface=None,
    bpf_filter: Optional[str] = None,
    count: int = 0,
    timeout: Optional[float] = None,
    offline: Optional[str] = None,
) -> None:
    """Capture packets and call `handler(packet)` for every one.

    Blocks until: `count` packets were seen, `timeout` seconds passed, the
    offline file ended, or the user pressed Ctrl+C.

    store=False tells Scapy not to keep packets in memory, so a long capture
    does not grow RAM usage.
    """
    kwargs = {"prn": handler, "store": False}
    if count:
        kwargs["count"] = count
    if timeout:
        kwargs["timeout"] = timeout
    if bpf_filter:
        kwargs["filter"] = bpf_filter
    if offline:
        if not os.path.isfile(offline):
            raise CaptureError(f"Capture file not found: {offline}")
        kwargs["offline"] = offline
    else:
        kwargs["iface"] = iface

    try:
        sniff(**kwargs)
    except KeyboardInterrupt:
        pass  # Ctrl+C is the normal way to stop a live capture, not an error
    except PermissionError as exc:
        raise CaptureError(_permission_help()) from exc
    except (Scapy_Exception, RuntimeError, OSError) as exc:
        # PermissionError is a subclass of OSError but was handled above.
        raise CaptureError(_explain_error(exc)) from exc
