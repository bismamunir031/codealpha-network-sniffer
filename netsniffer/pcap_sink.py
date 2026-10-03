"""Saving packets to a .pcap file (openable in Wireshark / tcpdump)."""

from __future__ import annotations

import os
import sys

from .capture import CaptureError


class PcapSink:
    """Writes each packet to disk as it arrives.

    * The file is created when the FIRST packet arrives (so a failed or empty
      capture leaves no empty file behind, and Scapy can detect the link type
      - Ethernet, loopback... - from that first packet).
    * sync=True flushes every packet, so pressing Ctrl+C never loses data.
    """

    def __init__(self, path: str) -> None:
        directory = os.path.dirname(os.path.abspath(path))
        if not os.path.isdir(directory):
            raise CaptureError(f"Cannot write '{path}': folder does not exist.")
        if not os.access(directory, os.W_OK):
            raise CaptureError(f"Cannot write '{path}': no permission to write in that folder.")
        if os.path.exists(path):
            print(f"Note: '{path}' already exists and will be overwritten.", file=sys.stderr)
        self.path = path
        self.count = 0
        self._writer = None

    def write(self, pkt) -> None:
        if self._writer is None:
            from scapy.utils import PcapWriter  # only needed when --write is used
            try:
                self._writer = PcapWriter(self.path, append=False, sync=True)
            except OSError as exc:
                raise CaptureError(f"Cannot write '{self.path}': {exc}") from exc
        self._writer.write(pkt)
        self.count += 1

    def close(self) -> None:
        if self._writer is not None:
            self._writer.close()
