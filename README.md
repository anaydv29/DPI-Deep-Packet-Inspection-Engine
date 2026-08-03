# Packet Analyzer / DPI Engine (Java port)

A Java conversion of [perryvegehan/Packet_analyzer](https://github.com/perryvegehan/Packet_analyzer),
a C++ Deep Packet Inspection engine. This port covers the full modular
architecture (the one driven by `main_dpi.cpp` + `dpi_engine.cpp` + its
component files), which is a strict superset of the two standalone
`main_working.cpp` / `dpi_mt.cpp` demo builds — same PCAP I/O, same TLS
SNI / HTTP Host / DNS extraction, same multi-threaded load-balancer →
fast-path pipeline, same blocking rules.

## About this project

This is a **Deep Packet Inspection (DPI) engine** — the kind of system used
by network firewalls and traffic-shaping appliances to look inside packets
and decide, in real time, what should be forwarded and what should be
blocked. It reads a `.pcap` capture file (the same format Wireshark saves),
reconstructs each packet's Ethernet/IP/TCP/UDP headers, peeks into the
encrypted-but-still-readable parts of TLS and QUIC handshakes to figure out
*which website or app* a connection belongs to, and applies configurable
blocking rules — all without decrypting any traffic.

**Core capabilities:**
- **PCAP parsing** — reads raw capture files byte-by-byte, handling both
  little- and big-endian formats
- **Protocol parsing** — extracts Ethernet, IPv4, TCP, and UDP header fields
  directly from raw bytes (no external libraries)
- **Traffic classification without decryption** — extracts the **SNI**
  (Server Name Indication) from TLS Client Hello messages, the **Host**
  header from plaintext HTTP requests, and query names from DNS packets,
  then maps the domain to one of 15+ known applications (YouTube, Netflix,
  WhatsApp, Instagram, etc.)
- **Configurable firewall-style rules** — block traffic by source IP,
  destination port, application, or domain (with wildcard support like
  `*.facebook.com`), loadable/savable from a rules file
- **Multi-threaded pipeline** — a load-balancer layer hashes each
  connection's 5-tuple to consistently route it to the same worker thread,
  so per-flow state (like "have I already classified this connection?")
  stays correct even under concurrent processing
- **Live stats & reporting** — packet/byte counts, drop rates, per-app
  traffic breakdown, and top-domain reports generated after each run

**Why it's interesting:** it's a real demonstration of low-level network
programming (manual byte-order handling, bitwise header parsing, TLS
handshake structure) combined with concurrent systems design (thread pools,
blocking queues with proper shutdown semantics, lock-based shared state) —
translated from C++ into idiomatic, thread-safe Java using
`java.util.concurrent` primitives instead of raw pointers and mutexes.

## Build

```bash
mvn clean package
```

This produces `target/packet-analyzer.jar` (with `Main-Class` set, so it's
directly runnable).

If you don't have Maven, plain `javac`/`java` works too:

```bash
find src/main/java -name "*.java" > sources.txt
javac -d out @sources.txt
java -cp out com.dpi.packetanalyzer.Main <input.pcap> <output.pcap>
```

## Usage

### Full DPI engine (multi-threaded, blocking rules)

```bash
java -jar target/packet-analyzer.jar capture.pcap filtered.pcap
java -jar target/packet-analyzer.jar capture.pcap filtered.pcap --block-app YouTube
java -jar target/packet-analyzer.jar capture.pcap filtered.pcap --block-ip 192.168.1.50 --block-domain "*.tiktok.com"
java -jar target/packet-analyzer.jar capture.pcap filtered.pcap --rules blocking_rules.txt
```

Options: `--block-ip <ip>`, `--block-app <app>`, `--block-domain <dom>`
(wildcards supported, e.g. `*.facebook.com`), `--rules <file>`,
`--lbs <n>` (load balancer threads, default 2), `--fps <n>` (FP threads
per LB, default 2), `--verbose`.

### Simple packet dumper (human-readable, single-threaded)

```bash
java -cp target/classes com.dpi.packetanalyzer.SimplePacketDumper capture.pcap [max_packets]
```

## Architecture

```
PCAP Reader -> hash(5-tuple) % num_lbs -> Load Balancers
            -> hash(5-tuple) % fps_per_lb -> Fast Path Processors
            (connection tracking, SNI/Host/DNS extraction, classification,
             rule matching, block/forward decision)
            -> Output Queue -> Output Writer -> filtered.pcap
```

## Package layout

| Package        | Purpose                                                        |
|----------------|-----------------------------------------------------------------|
| `pcap`         | PCAP file reading (global header, per-packet header, byte order)|
| `parser`       | Ethernet/IPv4/TCP/UDP field extraction                          |
| `types`        | FiveTuple, Connection, PacketJob, AppType, stats                |
| `sni`          | TLS SNI, HTTP Host, DNS query, QUIC SNI extraction              |
| `rules`        | Thread-safe IP/App/Domain/Port blocking rules + persistence     |
| `tracker`      | Per-thread connection tracker + global aggregation              |
| `pipeline`     | ThreadSafeQueue, LoadBalancer(s), FastPathProcessor(s)           |
| `engine`       | DPIEngine — wires everything together                           |

## Notes on the port

- All C++ raw pointers/structs became small Java classes/records.
- `uint32_t`/`uint16_t` network fields are widened into `int`/`long` since
  Java has no unsigned integer types; bit-level layout is preserved so
  hashing and formatting still match.
- The C++ `ThreadSafeQueue<T>` (condition-variable based, with a shutdown
  that wakes every blocked thread) is reimplemented with
  `ReentrantLock`/`Condition` rather than `java.util.concurrent.BlockingQueue`,
  since `BlockingQueue` has no equivalent "wake everyone on shutdown" primitive.
- Verified against the repo's own `test_dpi.pcap`: correctly classifies
  15 different applications via SNI, and blocking rules (IP/app/domain)
  all produce identical drop behavior to the original design.
