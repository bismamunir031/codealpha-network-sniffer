"""Packet statistics.

Only counters are kept - packet payloads are NOT stored - so memory use stays
tiny even during a long capture.
"""

from __future__ import annotations

from collections import Counter
from typing import List, Optional, Tuple

from .parser import PacketInfo


class PacketStats:
    """Accumulates totals as packets arrive; read the results when capture ends."""

    def __init__(self) -> None:
        self.total_packets = 0
        self.total_bytes = 0
        self.min_size: Optional[int] = None
        self.max_size: Optional[int] = None
        self.first_timestamp: Optional[float] = None
        self.last_timestamp: Optional[float] = None
        self.parse_errors = 0

        self.protocol_packets: Counter = Counter()
        self.protocol_bytes: Counter = Counter()
        self.src_ips: Counter = Counter()
        self.dst_ips: Counter = Counter()
        self.dst_ports: Counter = Counter()   # key: (transport, port)

    # -- called once per packet -------------------------------------------- #
    def update(self, info: PacketInfo) -> None:
        self.total_packets += 1
        self.total_bytes += info.length
        self.min_size = info.length if self.min_size is None else min(self.min_size, info.length)
        self.max_size = info.length if self.max_size is None else max(self.max_size, info.length)

        if self.first_timestamp is None:
            self.first_timestamp = info.timestamp
        self.last_timestamp = info.timestamp

        self.protocol_packets[info.protocol] += 1
        self.protocol_bytes[info.protocol] += info.length
        if info.src_ip:
            self.src_ips[info.src_ip] += 1
        if info.dst_ip:
            self.dst_ips[info.dst_ip] += 1
        if info.transport in ("TCP", "UDP") and info.dst_port is not None:
            self.dst_ports[(info.transport, info.dst_port)] += 1

    def record_parse_error(self) -> None:
        """A packet Scapy could not dissect. Counted, never fatal."""
        self.parse_errors += 1

    # -- derived values ----------------------------------------------------- #
    @property
    def average_size(self) -> float:
        return self.total_bytes / self.total_packets if self.total_packets else 0.0

    @property
    def duration(self) -> float:
        """Seconds between the first and last packet (uses the packets' own
        timestamps, so it is also correct when reading a .pcap file)."""
        if self.first_timestamp is None or self.last_timestamp is None:
            return 0.0
        return max(0.0, self.last_timestamp - self.first_timestamp)

    @property
    def packets_per_second(self) -> float:
        return self.total_packets / self.duration if self.duration > 0 else 0.0

    def top(self, counter: Counter, n: int = 5) -> List[Tuple[object, int]]:
        """The n most common items as (item, count) pairs."""
        return counter.most_common(n)
