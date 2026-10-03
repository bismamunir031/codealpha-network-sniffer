"""Shared test helpers.

Unit tests need packets, and we cannot rely on live traffic in a test. So we
craft packets with Scapy - but we pass them through `dissect()` first. That
turns them into raw bytes and re-parses them, exactly what happens to a packet
that arrives from a network card. (Testing on hand-built, never-serialised
packets can hide bugs, e.g. the Ethernet 'Padding' layer only appears after
dissection.)
"""

from scapy.all import Ether


def dissect(pkt):
    """Serialise a crafted packet and parse it again, like a captured one."""
    return Ether(bytes(pkt))
