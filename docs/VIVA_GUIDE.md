# Mentor Guide: Viva, Demo and Submission

Everything you need to **understand, demonstrate and defend** this project.

Contents
1. [Evaluator's requirement check](#1-evaluators-requirement-check)
2. [Complete packet flow](#2-complete-packet-flow)
3. [The code, file by file (beginner language)](#3-the-code-file-by-file)
4. [What you MUST understand](#4-what-you-must-understand-for-the-viva)
5. [20 likely viva questions](#5-twenty-likely-viva-questions)
6. [Live demonstration plan](#6-live-demonstration-plan)
7. [Final checklist](#7-final-checklist)
8. [Weak points to admit honestly](#8-weak-points-to-admit-honestly)

---

## 1. Evaluator's requirement check

| # | Original CodeAlpha requirement | How it is met | Where | Verified by |
|---|---|---|---|---|
| 1 | Build a Python program to capture network traffic packets | Live capture from a network interface, optional `.pcap` export | `capture.py::run_capture`, `pcap_sink.py` | Live captures on a real interface; `test_pcap_sink_round_trip` |
| 2 | Analyze captured packets to understand structure and content | Every packet split into layers; `PacketInfo`; `-v` shows the layer stack (`Ether / IP / TCP / Raw`) | `parser.py::parse_packet` | `tests/test_parser.py` (20 tests) |
| 3 | Learn how data flows through the network and the basics of protocols | Evidence-based identification of ARP, IPv4/6, TCP (flags, handshake), UDP, ICMP/ICMPv6, DNS, HTTP, TLS; statistics show the traffic mix | `parser.py`, `protocols.py`, `stats.py` | Sample output shows a handshake, DNS pair, HTTP, TLS |
| 4 | Use `scapy` or `socket` | Scapy (`sniff`, layer classes, `PcapWriter`) | all modules | `requirements.txt` |
| 5 | Display source/destination IPs | `SOURCE`, `DESTINATION` columns (MACs in `-v`) | `display.py` | `test_read_pcap_end_to_end` |
| 6 | Display protocols | `PROTO` column + port-based service hint | `parser.py`, `protocols.py` | `test_parser.py` |
| 7 | Display payloads | Short, safe, redacted preview (text or hex); TLS labelled as encrypted | `payload.py`, `display.py` | `tests/test_payload.py` |

Extra items in *your* prompt that are also covered: ports, packet size, statistics, PCAP export,
error handling (permissions, bad interface, bad filter, missing Npcap, bad files), tests,
README, responsible-use notice, cross-platform notes.

**Verdict:** every requirement is satisfied with real captured data. Nothing is simulated.

---

## 2. Complete packet flow

```
┌────────────────────┐
│ 1. NETWORK CARD    │  Electrical/radio signal -> a "frame" of raw bytes arrives
│    (eth0 / Wi-Fi)  │
└─────────┬──────────┘
          ▼
┌────────────────────┐
│ 2. OS + DRIVER     │  Linux: AF_PACKET socket │ Windows: Npcap │ macOS: BPF device
│    (needs admin!)  │  The BPF filter (-f) is applied HERE, in the kernel: unwanted
└─────────┬──────────┘  packets are dropped before Python ever sees them.
          ▼
┌────────────────────┐
│ 3. SCAPY sniff()   │  Reads the raw bytes, dissects them into layer objects:
│    capture.py      │  Ether() / IP() / TCP() / Raw()   -> one Scapy "Packet"
└─────────┬──────────┘
          ▼   calls handler(packet) once per packet
┌────────────────────┐
│ 4. PacketHandler   │  cli.py::PacketHandler.__call__
│    (the callback)  │  a) number += 1
│                    │  b) write the RAW packet to .pcap (if -w)   <- before parsing!
│                    │  c) try: parse   except: count as parse error, carry on
└─────────┬──────────┘
          ▼
┌────────────────────┐
│ 5. PACKET PARSING  │  parser.py::parse_packet
│                    │  Ether -> MAC addresses
│                    │  ARP?  -> done (ARP has no IP layer)
│                    │  IP / IPv6 -> addresses, TTL
│                    │  TCP / UDP / ICMP -> ports, flags, payload (padding removed)
└─────────┬──────────┘
          ▼
┌────────────────────┐
│ 6. PROTOCOL        │  Evidence:  DNS layer? HTTP request line? TLS record header?
│    DETECTION       │  Hint only: port number -> "https", "ssh" ...
│    protocols.py    │  Result stored in PacketInfo.protocol / .service
└─────────┬──────────┘
          ▼
┌────────────────────┐
│ 7. DISPLAY +       │  stats.update(info)  -> counters
│    ANALYSIS        │  format_packet(info) -> one line (or verbose block) -> print()
│                    │  payload.py makes the preview safe + redacted
└─────────┬──────────┘
          ▼
┌────────────────────┐
│ 8. END OF CAPTURE  │  -c count reached / -t timeout / file ended / Ctrl+C
│                    │  close .pcap, print format_summary(stats)
└────────────────────┘
```

**One-sentence version for the viva:**
*"The network card receives a frame, the OS hands it to Scapy, Scapy splits it into layers,
my parser copies out the fields I care about, my protocol detector decides what it is, and my
display and statistics code show and count it."*

---

## 3. The code, file by file

Read them in this order. About 1,200 lines including comments and docstrings - small enough to know completely.

### `sniffer.py` - the front door
Three lines. Imports `main()` from `netsniffer/cli.py` and runs it.

### `netsniffer/capture.py` - talks to the network
* `list_interfaces()` - asks Scapy (`conf.ifaces`) for all network cards.
* `resolve_interface(name)` - turns a name like `"eth0"` into a Scapy interface object, or raises
  `CaptureError` with a helpful message. (Checks the name *before* capturing.)
* `run_capture(handler, ...)` - **the heart of live capture.** Calls Scapy's `sniff()` with
  `prn=handler` ("call this function for each packet") and `store=False` ("don't keep packets in
  RAM"). Wrapped in `try/except` that converts scary Python errors into friendly `CaptureError`s:
  `PermissionError` -> "run as admin/sudo"; missing Npcap; invalid BPF filter.
* `KeyboardInterrupt` (Ctrl+C) is caught and treated as a normal stop.

### `netsniffer/parser.py` - packet -> data
* `PacketInfo` - a plain container (a dataclass) holding everything about one packet.
* `parse_packet(pkt, number)` - **the most important function.** Reads like a checklist:
  1. Ethernet? copy MAC addresses.
  2. ARP? fill in and stop (ARP is not IP).
  3. IPv4 or IPv6? copy addresses and TTL.
  4. TCP? ports, flags, payload -> is it TLS? HTTP?
  5. UDP? ports, payload -> is it DNS?
  6. ICMP / ICMPv6? summarise the message.
* `extract_payload()` - returns the application bytes **without Ethernet padding** (tiny frames
  are zero-padded by the network card; without this fix every empty ACK would look like data).
* `format_tcp_flags(0x12)` -> `"SYN,ACK"` - each flag is one bit.

### `netsniffer/protocols.py` - "what protocol is this?"
* `looks_like_http(payload)` - does it start with `GET `, `POST `, `HTTP/1.`...?
* `looks_like_tls(payload)` - does it start with a valid 5-byte TLS record header
  (type 20-23, major version 3)?
* `WELL_KNOWN_PORTS` / `guess_service()` - port -> name, used only as a **hint**.

### `netsniffer/payload.py` - keeping the preview safe
* `printable_preview()` - first N bytes -> one safe line (control chars -> `.`, `\r\n` shown
  visibly, "(+N more bytes)" when cut).
* `redact_sensitive()` - regular expressions that replace `Authorization:`/`Cookie:` headers and
  `password=`/`token=` values with `[REDACTED]`.
* `hexdump()` / `hex_preview()` - hex views for binary data.

### `netsniffer/stats.py` - counting
`PacketStats.update(info)` is called per packet; it only increments counters (`Counter` objects)
and min/max/total numbers. Payloads are never stored.

### `netsniffer/display.py` - printing
Functions **return** strings (they don't print), which makes them testable. `format_packet()`
picks the compact line or verbose block; `format_summary()` builds the final report.
Output is plain ASCII so Windows consoles can't crash on it.

### `netsniffer/pcap_sink.py` - saving
Wraps Scapy's `PcapWriter`. Creates the file on the first packet, flushes every packet
(`sync=True`) so Ctrl+C never loses data.

### `netsniffer/cli.py` - the conductor
* `build_parser()` - all command-line options (`argparse`), with validation.
* `PacketHandler.__call__` - the per-packet routine (save, parse, count, print).
  The `try/except` around `parse_packet` means **one weird packet can't crash the sniffer**.
* `main()` - list interfaces, or validate -> open capture -> summary. Returns exit code
  0 (ok) / 1 (error) / 2 (bad arguments).

---

## 4. What you MUST understand for the viva

**Priority 1 - be able to explain line by line**
1. `capture.py::run_capture` - `sniff(prn=..., store=False, filter=..., iface=...)`.
2. `parser.py::parse_packet` - the layer-by-layer `haslayer()` checks.
3. `cli.py::PacketHandler.__call__` - the per-packet pipeline and *why* the pcap is written first.
4. `protocols.py::looks_like_tls` and `looks_like_http` - how protocol detection works.

**Priority 2 - explain in your own words**
5. The layer model: Ethernet -> IP -> TCP/UDP -> payload, and what each layer contributes.
6. TCP flags and the three-way handshake (you can *see* it in your own output).
7. Why HTTPS payloads can't be read.
8. Why admin/root is needed.
9. Evidence vs. hint in protocol identification.
10. What redaction does and why (privacy).

**Priority 3 - just know they exist**
`stats.py` (counters), `display.py` (formatting), `pcap_sink.py`, the tests.

**Numbers/facts to memorise**
Ports: 53 DNS, 80 HTTP, 443 HTTPS, 22 SSH. TCP flags: SYN, ACK, FIN, RST, PSH.
TLS record types: 22 = Handshake, 23 = Application Data. Ethernet minimum frame = 60 bytes
(+4 CRC). Typical maximum frame = 1514 bytes (MTU 1500 + 14-byte header).

---

## 5. Twenty likely viva questions

**1. What is a network sniffer? Is it legal?**
A program that captures packets passing through a network interface so they can be inspected.
It is legal and standard for troubleshooting and security work on networks you own or are
authorised to monitor (Wireshark and tcpdump are the same idea). Capturing other people's
traffic without permission can be illegal, which is why my tool prints a notice and is passive only.

**2. What does "passive" mean here?**
It only *listens*. It never sends, changes or replays packets. Active attacks (ARP spoofing,
injection) are deliberately out of scope for a *basic* sniffer.

**3. Why Scapy instead of the `socket` module?**
Both are allowed by the task. With raw sockets I would receive raw bytes and have to decode every
header by hand, and raw sockets behave very differently on Windows. Scapy handles capture on all
three operating systems and already understands hundreds of protocols, so I could spend my time
on analysis instead of byte-parsing.

**4. Walk me through your program.**
`sniffer.py` calls `main()`. It parses arguments, resolves the interface, and calls Scapy's
`sniff()` with my handler. For every packet the handler optionally saves it to a pcap, calls
`parse_packet()` to build a `PacketInfo`, updates the statistics and prints a line. When the
capture ends (count, timeout, Ctrl+C) it prints the summary.

**5. What are the layers of a packet?**
Encapsulation: the application data is wrapped in a TCP or UDP header (ports), which is wrapped
in an IP header (IP addresses), which is wrapped in an Ethernet header (MAC addresses). Scapy
shows this as `Ether / IP / TCP / Raw`; my `-v` mode prints exactly that.

**6. Where does a sniffer sit in the OSI/TCP-IP model?**
It captures at the **data-link layer** (whole Ethernet frames) and then *reads upward*: network
(IP), transport (TCP/UDP) and, where visible, application (DNS, HTTP).

**7. Difference between TCP and UDP? How does your code tell them apart?**
TCP is connection-oriented and reliable (handshake, sequence numbers, retransmission); UDP is
connectionless and fast with no guarantees (DNS, streaming). In code: `pkt.haslayer(TCP)` versus
`pkt.haslayer(UDP)`.

**8. What is the three-way handshake? Where can I see it?**
Client sends `SYN`, server replies `SYN,ACK`, client answers `ACK` - the connection is open. In
the sample output that is packets 3-5. Flags come from a bit-field in the TCP header; my
`format_tcp_flags` decodes it (`0x12` = SYN + ACK).

**9. IP address vs MAC address vs port?**
MAC: identifies a network card on the *local* link (Ethernet header). IP: identifies a host
across networks (IP header). Port: identifies the *application/service* on that host (TCP/UDP
header). Address = which machine; port = which program.

**10. How do you identify protocols?**
Two ways, kept separate. *Evidence:* Scapy decoded a DNS layer; the payload begins like an HTTP
request; it begins with a valid TLS record header. *Hint:* the port number (443 -> "https"). Ports
are only conventions - anything can run on any port - so a port alone never sets the `PROTO`
column.

**11. Why can't you see inside HTTPS?**
HTTPS = HTTP inside TLS encryption. The keys exist only on the two endpoints. A passive sniffer
sees addresses, ports, sizes and the unencrypted handshake headers, but the content is
ciphertext - that is exactly the protection TLS provides. My tool labels such payloads instead of
printing meaningless bytes.

**12. What is promiscuous mode?**
Normally a network card discards frames not addressed to it. In promiscuous mode it passes all
frames it receives up to the OS. Scapy enables it by default. On a switched network or Wi-Fi you
still only receive your own traffic plus broadcast/multicast, so it does not let you see everyone.

**13. Why does capturing need administrator/root?**
Reading raw frames bypasses the OS's normal protections: any program could read other programs'
network data. So Linux/macOS require root (raw socket / BPF device) and Windows requires
administrator plus the Npcap driver. If missing, my code catches `PermissionError` and explains
what to do.

**14. What is a BPF filter and why use it?**
Berkeley Packet Filter - the syntax used by tcpdump/Wireshark, like `tcp port 80`. It runs in the
kernel, so unwanted packets are dropped before reaching Python: faster, lower CPU, and I only
analyse what I asked for. Passed with `-f`.

**15. What is a PCAP file and why save one?**
The standard capture file format (readable by Wireshark, tcpdump). Saving lets me analyse later,
share evidence, and demo without live traffic; my `-r` option re-runs the same analysis on a
file. It contains full packets, so it can hold private data and must be handled carefully.

**16. How is your payload preview "safe"?**
(a) Only the first 64 bytes are shown and nothing is stored; (b) control characters become `.`,
so a malicious packet can't inject terminal escape codes; (c) `Authorization`/`Cookie` headers and
`password=`/`token=` values are replaced by `[REDACTED]`; (d) encrypted data is not printed.
Redaction is best-effort, not perfect - I say so in the README.

**17. What happens on Ctrl+C or a malformed packet? Does memory grow?**
Ctrl+C raises `KeyboardInterrupt`, which I catch as a normal stop, then close the pcap and print
the summary. Each packet is parsed inside `try/except`; a bad one is counted as "unparsed" and the
capture continues. `store=False` means Scapy doesn't keep packets and my statistics are counters
only, so memory stays flat.

**18. What are ARP, DNS and ICMP?**
ARP: "who has IP x.x.x.x?" - maps an IP to a MAC on the local network (no IP layer). DNS: turns
names like `pypi.org` into IP addresses (UDP port 53); I show the query name and answer count.
ICMP: control/diagnostic messages, e.g. ping (echo request/reply) - I show type, id and sequence.

**19. How did you test it?**
59 automated pytest tests: parsing of each protocol using packets that are serialised and
re-dissected (like real captures), payload safety and redaction, statistics, PCAP round-trip and
full command-line runs via `--read`. I also ran real live captures, tested error paths (no root,
bad interface, bad filter), and fuzzed the parser with thousands of corrupted packets, which
found two crash bugs that I fixed and covered with regression tests.

**20. Limitations and improvements?**
Limits: no TCP stream reassembly, can't read encrypted traffic, only sees traffic reaching my
NIC, limited protocol list. Next steps: reassemble TCP streams, extract TLS SNI (server name),
add per-conversation (flow) statistics, GUI or live dashboard, more protocols (DHCP, QUIC).
I kept it a *basic* sniffer on purpose.

---

## 6. Live demonstration plan

**Before the evaluation (do this the day before, on the same laptop/network you'll use)**
* Run once end to end. Note your **interface name** (`python sniffer.py -l`).
* `python -m pytest -q` -> all green.
* **Record a fallback capture** on your own machine: `... -t 30 -w demo.pcap` while browsing.
  Keep it *outside* the GitHub repo. If live capture fails at the venue (no admin rights,
  restricted Wi-Fi), you can still demo everything with `python sniffer.py -r demo.pcap`.
* Open **two** terminals: A (admin/sudo) runs the sniffer, B generates traffic.
* Use your own network / a hotspot you control.

**Script (about 10 minutes)**

| Step | Do | Say / point out |
|---|---|---|
| 1 | Show the folder tree and README top | "Modular: capture, parser, protocols, payload, stats, display, cli." |
| 2 | `python sniffer.py --help` | Options grouped: source, control, output. |
| 3 | `python sniffer.py -l` | "These are the interfaces Scapy sees; I'll use `<name>`." |
| 4 | **A:** `... -i <iface> -c 15` **B:** open a website | Explain the columns. Point at DNS query/response, then TCP `SYN`/`SYN,ACK`/`ACK`, then `TLS` `ClientHello`. |
| 5 | **A:** `... -f "icmp" -c 6` **B:** `ping 8.8.8.8` | ICMP echo request/reply, TTL. "BPF filter runs in the kernel." |
| 6 | **A:** `... -f "udp port 53" -c 4` **B:** `nslookup example.com` | DNS query name + answer count. |
| 7 | **A:** `... -f "tcp port 80" -c 8` **B:** `curl http://neverssl.com` | Plain HTTP request visible. "Compare with HTTPS: TLS payloads are not shown - encryption." |
| 8 | **A:** `... -c 5 -v` | Verbose: layers `Ether / IP / TCP`, MACs, TTL, flags. |
| 9 | **A:** `... -t 20 -w demo2.pcap`, then Ctrl+C early | "Ctrl+C is handled; file is complete; summary printed." Explain statistics. |
| 10 | `python sniffer.py -r demo2.pcap -c 5` | "Same analysis pipeline, offline, no admin needed." Optionally open the file in Wireshark. |
| 11 | Error handling: `-i wrongname`; run without admin | "Clear, actionable errors instead of tracebacks." |
| 12 | `python -m pytest -q` | "59 automated tests." |
| 13 | Open `parser.py::parse_packet` and `protocols.py::looks_like_tls` | Walk the code confidently (Section 4, priority 1). |

**If something goes wrong:** stay calm, say what the error means (the tool tells you), and switch
to the `-r demo.pcap` fallback. Handling failure gracefully is *part* of what the project shows.

**Windows notes for the demo:** terminal *as Administrator*; Npcap installed; use `-i "Wi-Fi"` (the
name from `-l`); `curl` and `nslookup` exist on Windows 10/11.

---

## 7. Final checklist

**Code**
- [ ] Runs on **your** machine: `-l`, a live capture, `-w`, `-r`
- [ ] `python -m pytest -q` passes (59 tests)
- [ ] You can explain every function in Section 4, priority 1
- [ ] No stray files: no `*.pcap`, no `venv/`, no `__pycache__/` (the `.gitignore` handles this)

**GitHub**
- [ ] Repository created (CodeAlpha usually asks for a name like `CodeAlpha_ProjectName` - **check your own internship instructions** for the exact format)
- [ ] `LICENSE`: replace `<Your Name>`
- [ ] README: replace `<your-username>` in the clone URLs
- [ ] Add **your own screenshot(s)** of it running (e.g. `docs/screenshot.png`) and reference them in the README
- [ ] Sample output in README is clearly marked as sample (it is)
- [ ] Never commit a capture file (it may contain private data)
- [ ] Add a short repo description and topics: `python`, `scapy`, `network-sniffer`, `packet-analysis`, `cybersecurity`
- [ ] First commit message like "Add basic network sniffer (CodeAlpha Task 1)"; commit in logical steps rather than one giant commit

**CodeAlpha submission** (follow *your* offer letter / portal; these are typical)
- [ ] GitHub link in the exact submission form/portal they specify
- [ ] Short demo video and/or LinkedIn post tagging CodeAlpha, if your instructions require it
- [ ] Repo is **public** (or accessible to the reviewers)
- [ ] Internship-tenure deadlines respected

**Personal readiness**
- [ ] Can explain the packet flow diagram from memory
- [ ] Can answer the 20 questions in your own words (don't memorise; understand)
- [ ] Have the fallback `demo.pcap` on your laptop
- [ ] Know your interface name and have practised the demo twice

---

## 8. Weak points to admit honestly

Evaluators respect honesty about limits more than exaggerated claims. Volunteer these:

1. **No TCP reassembly** - a request spanning several packets is analysed packet by packet.
2. **TLS is opaque** - by design; I identify the handshake, nothing more.
3. **Linux loopback duplicates packets** (Scapy's native socket behaviour); use a real interface.
4. **Development/testing was done on Linux.** The code uses cross-platform Scapy APIs and is
   written for Windows/macOS too, but confirm on your own machine before the demo.
5. **Redaction is best effort** - it catches common patterns, not every possible secret.
6. **Port hints can be wrong** - which is why they are shown separately from evidence.
