# CodeAlpha Basic Network Sniffer

A small, passive **packet sniffer written in Python with Scapy**. It captures live network
traffic, breaks every packet into its protocol layers, and shows source/destination
addresses, ports, protocol, size and a *safe* payload preview, followed by summary
statistics. Captures can be saved to `.pcap` (openable in Wireshark) and re-analysed later.

Built for **CodeAlpha Cyber Security Internship - Task 1: Basic Network Sniffer**.

> **Responsible use:** capture only on networks you own or have explicit permission to
> monitor. This tool is strictly passive (it never sends, modifies or injects packets).
> See [Responsible use](#responsible-use).

---

## Features

| Feature | Details |
|---|---|
| Live capture | Real packets from a real network interface via Scapy's `sniff()` |
| Packet analysis | Ethernet, IPv4, IPv6, ARP, TCP, UDP, ICMP, ICMPv6 dissected from real Scapy layers |
| Addresses | Source/destination IP (and MAC in verbose mode), ports, TTL / hop limit, TCP flags |
| Protocol identification | Evidence-based: DNS (Scapy layer), HTTP and TLS (payload signature). Port-based *hints* for other services (ssh, ntp...) |
| Packet size | Per packet + min / avg / max in the summary |
| Safe payload preview | Short, control-character-safe, with credentials redacted; encrypted data is not displayed |
| Statistics | Totals, packet rate, protocol distribution, top source/destination IPs and ports |
| PCAP export | `-w file.pcap` (streamed to disk, safe on Ctrl+C) and `-r file.pcap` to analyse offline |
| Filtering | Standard BPF filters, e.g. `tcp port 80` |
| Error handling | Clear messages for missing permissions, bad interface, bad filter, missing driver, bad files |
| Cross-platform | Windows (Npcap), Linux, macOS |

## Sample output

> **Sample output** - taken from a real capture on a Linux test machine and trimmed. Your
> addresses, times and traffic will differ. (`192.0.2.x` is the capturing machine.)

```
$ sudo python3 sniffer.py -i eth0 -f "udp port 53 or tcp port 80 or tcp port 443" -t 9 -w demo.pcap

CodeAlpha Basic Network Sniffer v1.0.0  (passive capture only)
  Source          : interface: eth0
  BPF filter      : udp port 53 or tcp port 80 or tcp port 443
  Limit           : 9 seconds
  Payload preview : 64 bytes
  Use only on networks you own or are authorised to monitor.

   NO  TIME          PROTO    SOURCE                  DESTINATION               LEN  INFO
----------------------------------------------------------------------------------------------------
    1  09:20:34.871  DNS      192.0.2.2:42278         8.8.8.8:53                 78  DNS query A archive.ubuntu.com
    2  09:20:34.873  DNS      8.8.8.8:53              192.0.2.2:42278           222  DNS response archive.ubuntu.com (9 answers)
    3  09:20:34.873  TCP      192.0.2.2:52388         185.125.190.82:80          74  [SYN] (http)
    4  09:20:34.873  TCP      185.125.190.82:80       192.0.2.2:52388            74  [SYN,ACK] (http)
    5  09:20:34.873  TCP      192.0.2.2:52388         185.125.190.82:80          66  [ACK] (http)
    6  09:20:34.873  HTTP     192.0.2.2:52388         185.125.190.82:80         201  HTTP GET /ubuntu/dists/noble/Release?user=demo&password=[REDACTED] HTTP/1.1
       |- payload (135 bytes, text): GET /ubuntu/dists/noble/Release?user=demo&password=[REDACTED] HTTP/ ...(+71 more bytes)
    7  09:20:34.873  TCP      185.125.190.82:80       192.0.2.2:52388            66  [ACK] (http)
    8  09:20:34.972  HTTP     185.125.190.82:80       192.0.2.2:52388          6806  HTTP HTTP/1.1 200 OK
       |- payload (6740 bytes, text): HTTP/1.1 200 OK\r\ndate: Sat, 19 Sep 2026 09:20:34 GMT\r\nserver: Ap ...(+6676 more bytes)
  ...
   27  09:20:34.982  DNS      192.0.2.2:41596         8.8.8.8:53                 68  DNS query A pypi.org
   28  09:20:34.983  DNS      8.8.8.8:53              192.0.2.2:41596           132  DNS response pypi.org (4 answers)
   29  09:20:34.986  TCP      192.0.2.2:43606         151.101.0.223:443          74  [SYN] (https)
   32  09:20:34.988  TLS      192.0.2.2:43606         151.101.0.223:443         583  TLS Handshake (ClientHello)
       |- payload: 517 bytes of TLS (encrypted or binary - not displayed)
   34  09:20:34.989  TLS      151.101.0.223:443       192.0.2.2:43606          3291  TLS Handshake (ServerHello)
  ...

============================== CAPTURE SUMMARY ==============================
Packets captured : 373
Total data       : 5.2 MB (5,408,177 bytes)
Packet size      : min 66 B | avg 14499.1 B | max 64770 B
Duration         : 0.65 s (573.8 packets/s)

Protocol distribution
  PROTOCOL  PACKETS   SHARE       BYTES
  TLS           290   77.7%      4.4 MB  ################
  TCP            77   20.6%    797.0 KB  ####
  DNS             4    1.1%       500 B  #
  HTTP            2    0.5%      6.8 KB  #

Top 5 destination ports
  TCP/43606                                  304 packets
  TCP/443 (https)                             41 packets
  TCP/80 (http)                               12 packets
  UDP/53 (dns)                                 2 packets

Saved 373 packets to demo.pcap
```

Things worth noticing in the sample: the **TCP three-way handshake** (`SYN`, `SYN,ACK`, `ACK`
in packets 3-5), a **DNS query/response pair**, a **plain-text HTTP** request whose
`password=` value was redacted, and **TLS** traffic whose content is (correctly) not shown.
Packet sizes above 1514 bytes appear here only because that virtual NIC merges packets
(GRO offload); on a typical PC you will see sizes up to about 1514.

**Verbose mode (`-v`)** shows the full layer breakdown of every packet:

```
Packet #6 | 09:20:34.873 | 201 bytes
  Layers   : Ether / IP / TCP / Raw
  Ethernet : 02:fc:00:00:00:01 -> 02:fc:00:00:00:05
  IPv4     : 192.0.2.2 -> 185.125.190.82  (TTL 64)
  TCP      : port 52388 -> 80  flags [ACK,PSH]  (service hint: http)
  Protocol : HTTP
  Info     : HTTP GET /ubuntu/dists/noble/Release?user=demo&password=[REDACTED] HTTP/1.1
  Payload  : 135 bytes, text preview (secrets redacted):
    GET /ubuntu/dists/noble/Release?user=demo&password=[REDACTED] HTTP/ ...(+71 more bytes)
```

---

## Requirements

* Python **3.8+**
* [Scapy](https://scapy.net) `>= 2.5.0` (installed via `requirements.txt`; tested with 2.5.0, 2.6.1 and 2.7.0)
* Permission to capture packets (see the platform notes)

| Platform | What you need in addition |
|---|---|
| **Windows 10/11** | **[Npcap](https://npcap.com)** (tick *"Install Npcap in WinPcap API-compatible mode"*) and a terminal opened with **Run as administrator** |
| **Linux** | Run with `sudo`. Install `tcpdump` (provides libpcap) so `--filter` works: `sudo apt install tcpdump` |
| **macOS** | Run with `sudo`. libpcap is preinstalled |

Reading a saved `.pcap` with `-r` needs **no** administrator rights and no Npcap.

## Installation

### Windows (PowerShell or CMD, *as Administrator*)

```powershell
git clone https://github.com/<your-username>/CodeAlpha_BasicNetworkSniffer.git
cd CodeAlpha_BasicNetworkSniffer
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python sniffer.py --list-interfaces
```

### Linux / macOS

```bash
git clone https://github.com/<your-username>/CodeAlpha_BasicNetworkSniffer.git
cd CodeAlpha_BasicNetworkSniffer
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python sniffer.py --list-interfaces          # listing needs no root
```

Because capturing needs root but your packages live in the virtual environment, start the
sniffer with the venv's own Python:

```bash
sudo venv/bin/python sniffer.py -i eth0 -c 20        # Linux (macOS interface is usually en0)
```

## Usage

```
python sniffer.py [options]

capture source
  -i, --interface NAME     interface to capture on (default: system default)
  -l, --list-interfaces    list interfaces and exit
  -r, --read FILE          analyse a saved .pcap file instead of live traffic

capture control
  -c, --count N            stop after N packets
  -t, --timeout SECONDS    stop after N seconds
  -f, --filter BPF         BPF filter, e.g. 'tcp port 80'
  -w, --write FILE         also save captured packets to a .pcap file

output
  -v, --verbose            detailed multi-line view of every packet
  --no-payload             do not show payload previews
  --payload-bytes N        payload bytes to preview (1-512, default 64)
  --no-color               disable coloured output
```

Press **Ctrl+C** at any time to stop; the summary is printed and any `.pcap` is closed safely.

### Common recipes

| Goal | Command |
|---|---|
| See available interfaces | `python sniffer.py -l` |
| Capture 20 packets | `sudo venv/bin/python sniffer.py -i eth0 -c 20` |
| Only DNS lookups | `... -f "udp port 53"` |
| Only web traffic | `... -f "tcp port 80 or tcp port 443"` |
| Only ping | `... -f icmp` |
| Traffic to/from one host | `... -f "host 8.8.8.8"` |
| Deep dive into a few packets | `... -c 5 -v` |
| Save 30 s of traffic | `... -t 30 -w capture.pcap` |
| Analyse it again, no admin needed | `python sniffer.py -r capture.pcap` |
| Hide payloads | `... --no-payload` |

On Windows use the friendly adapter name shown by `--list-interfaces`, e.g. `-i "Wi-Fi"`.

## How it works

```
 Network Interface ──► Scapy sniff() ──► PacketHandler ──► parse_packet() ──► PacketInfo
   (Wi-Fi/Ethernet)     capture.py          cli.py           parser.py        (simple object)
                                              │                                    │
                                              ├──► PcapSink (pcap_sink.py)         ├──► PacketStats.update()  (stats.py)
                                              │      raw packet -> .pcap           └──► format_packet()       (display.py)
                                              │                                              │
                                              └───────────────────────────────────────────────► terminal
```

1. **Capture** (`capture.py`): `sniff(prn=handler, store=False)` opens the interface and calls
   the handler for each packet. `store=False` keeps memory flat during long captures.
2. **Parse** (`parser.py`): Scapy has already split the frame into layers. `parse_packet()`
   walks them (Ethernet -> IP/IPv6/ARP -> TCP/UDP/ICMP -> application) and copies the fields
   into a plain `PacketInfo` object.
3. **Identify** (`protocols.py`): DNS via Scapy's DNS layer, HTTP via the request/status line,
   TLS via the 5-byte record header. Port numbers give *hints* only.
4. **Analyse** (`stats.py`): counters only - payloads are never accumulated.
5. **Display** (`display.py`): pure functions that return strings; compact or verbose.

### Project structure

```
codealpha-network-sniffer/
├── sniffer.py               # entry point:  python sniffer.py
├── netsniffer/
│   ├── __init__.py          # version
│   ├── cli.py               # argument parsing, PacketHandler, main flow
│   ├── capture.py           # interfaces, Scapy sniff() wrapper, friendly errors
│   ├── parser.py            # Scapy packet -> PacketInfo
│   ├── protocols.py         # port names, HTTP/TLS detection
│   ├── payload.py           # safe preview, redaction, hexdump
│   ├── stats.py             # PacketStats
│   ├── display.py           # colours, packet/summary formatting
│   └── pcap_sink.py         # .pcap writer
├── tests/                   # pytest suite (59 tests)
├── docs/VIVA_GUIDE.md       # explanation, viva Q&A, demo plan, checklists
├── requirements.txt
├── requirements-dev.txt
├── pytest.ini
├── LICENSE
└── README.md
```

## Protocol identification: evidence vs. hints

A port number is a *convention*, not proof (anything can run on port 443). So the tool
separates the two:

* **`PROTO` column = evidence.** `DNS` only if Scapy decoded a DNS layer; `HTTP` only if the
  payload starts like an HTTP message; `TLS` only if it starts with a valid TLS record
  header. Otherwise you see the transport: `TCP`, `UDP`, `ICMP`, `ARP`...
* **`(https)` next to the INFO = port hint.** Helpful, but not a guarantee.

## Privacy and safety design

* **Passive only** - the program contains no code that sends packets.
* **Short previews** - default 64 bytes; payloads are never stored or accumulated.
* **Terminal-safe** - control characters (including ESC sequences) become `.`.
* **Credential redaction** - `Authorization`, `Cookie`, `Set-Cookie` headers and
  `password=`/`token=`-style fields are replaced with `[REDACTED]`. This is *best effort*, not
  a guarantee.
* **Encrypted data is not displayed** - TLS payloads are labelled, not dumped.
* **PCAP warning** - a `.pcap` contains complete packets; the tool warns you, and `.gitignore`
  excludes `*.pcap` so captures are not committed by accident.

## Limitations

* **HTTPS/TLS content is encrypted.** A passive sniffer can see *that* a TLS connection exists
  (addresses, ports, handshake type, sizes) but never the page, form data or passwords inside.
  That is exactly what TLS is designed to guarantee.
* **Only traffic that reaches your network card.** On a switched or Wi-Fi network you see your
  own traffic plus broadcast/multicast, not other people's. (Scapy enables promiscuous mode by
  default, which does not change this on switched networks.)
* **No TCP stream reassembly.** Each packet is analysed on its own; a message split across
  packets shows up as several packets, and only the first one carries the HTTP/TLS signature.
* **Linux loopback (`lo`) shows every packet twice.** This is Scapy's native Linux socket
  behaviour, not a bug in this tool; real interfaces (`eth0`, `wlan0`) are not affected.
* **Loopback on Windows** needs the Npcap Loopback Adapter to be capturable at all.
* **Large sizes** (over 1514 bytes) can appear on machines whose network card merges packets
  (GRO/LRO/TSO offload).
* **Wi-Fi monitor mode / 802.11 frames** are out of scope.
* Protocol detection covers the common protocols only (see `protocols.py`).

## Testing

```bash
pip install -r requirements-dev.txt
python -m pytest -q
```

59 tests cover parsing of every supported protocol (using packets that go through Scapy's
real dissection), payload safety and redaction, statistics, malformed-packet handling
(including regression tests for bugs found by fuzzing), PCAP round-trips and end-to-end CLI
runs using `--read`. No administrator rights or live traffic are needed to run them.

## Learning outcomes

* How data is encapsulated: Ethernet frame -> IP packet -> TCP segment / UDP datagram -> payload
* The TCP handshake and flags, DNS lookups, ARP, ICMP (ping)
* Why HTTPS hides content and plain HTTP does not
* How raw-socket capture, BPF filters and libpcap/Npcap work together
* Writing a clean, modular, tested Python CLI with proper error handling
* Handling captured data responsibly

## Responsible use

Packet sniffing can expose private information. Use this tool only on networks and devices
you own, or where you have **explicit written permission**. Capturing other people's traffic
without authorisation may be illegal. The author accepts no responsibility for misuse. This
project is for education and for troubleshooting your own network.

## License

MIT - see [LICENSE](LICENSE).
