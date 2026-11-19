# PacketScope 🔍

> **High-Performance, Browser-Based Network Forensics Workbench in Rust & WebAssembly**

[![CI](https://github.com/lokeshpuma/packetscope.rust/actions/workflows/ci.yml/badge.svg)](https://github.com/lokeshpuma/packetscope.rust/actions/workflows/ci.yml)
[![Deploy to GitHub Pages](https://github.com/lokeshpuma/packetscope.rust/actions/workflows/deploy-pages.yml/badge.svg)](https://github.com/lokeshpuma/packetscope.rust/actions/workflows/deploy-pages.yml)
[![License: MIT / Apache-2.0](https://img.shields.io/badge/license-MIT%20%2F%20Apache--2.0-blue.svg)](LICENSE)

**Live Web Application**: [https://lokeshpuma.github.io/packetscope.rust/](https://lokeshpuma.github.io/packetscope.rust/)

PacketScope is a client-side network traffic analysis and forensic workbench built entirely in safe Rust and WebAssembly with Yew. It enables security analysts, incident responders, network engineers, and students to inspect, dissect, filter, and detect anomalies in PCAP and PCAPNG captures directly inside any modern web browser—**with 100% local processing, zero server uploads, and complete privacy**.

---

## ⚡ Key Highlights

- **🔒 100% Local-First & Confidential**: Original capture files never leave your device. All parsing, dissection, aggregation, and heuristic rule evaluation run exclusively inside in-browser WebAssembly memory.
- **📦 No Native Dependencies**: Pure Rust parser implementation; does not require `libpcap`, C build chains, or backend services. Works completely offline on air-gapped forensic workstations.
- **🔬 Deep Protocol Dissection**: Decodes Ethernet II, 802.1Q VLAN, ARP, IPv4, IPv6 (with extension header chains), TCP (flags & options), UDP, ICMPv4, ICMPv6, DNS (with compression pointer safety), HTTP/1.x, and TLS records.
- **📊 10 Forensic Workspaces**:
  1. **Overview**: Executive dashboard with traffic totals, top talkers, protocol distribution, and rate metrics.
  2. **Packets**: Paginated packet table with Wireshark-style query filtering, autocomplete, interactive hex viewer, and protocol layer tree.
  3. **Conversations (Flows)**: Bidirectional 5-tuple flow aggregation, directional byte/packet splits, and TCP handshake/state tracking.
  4. **Hosts**: Host inventory, MAC correlation, volume sent/received, DNS associations, and destination port lists.
  5. **Protocols**: Layer breakdown and port utilization mapped to standard services.
  6. **DNS Analytics**: Query type distributions, response codes, NXDomain ratio alerts, and domain search.
  7. **Findings**: Explainable heuristic anomaly detection with rule evidence, thresholds, and investigation guidance.
  8. **Timeline & Topology**: PPS/BPS traffic rate charts and an SVG host communication graph.
  9. **Reports & Exports**: Formatted executive report, JSON export, and spreadsheet-formula-sanitized CSV exports.
  10. **Settings**: Theme switcher (Dark Cyber / Clean Light), configurable heuristic thresholds, and memory cache controls.
- **🚀 Instant Demo Mode**: One-click deterministic capture generator producing valid synthetic traffic (ARP, DNS, HTTP, ICMP, NTP, and burst anomalies) to test all features immediately without needing a local PCAP file.

---

## 💻 How to Use on Your Own System

### Prerequisites

You need the standard Rust toolchain (1.80+) and Trunk (the WebAssembly web application bundler for Rust):

```bash
# 1. Install Rust via rustup (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 2. Add the wasm32 WebAssembly target
rustup target add wasm32-unknown-unknown

# 3. Install Trunk
cargo install --locked trunk
```

### 1. Clone the Repository

```bash
git clone https://github.com/lokeshpuma/packetscope.rust.git
cd packetscope.rust
```

### 2. Run the Development Server

Start the local development server with automatic rebuilds and live reloading:

```bash
trunk serve
```

Once started, open your web browser at:
👉 **`http://127.0.0.1:8080`**

### 3. Build for Production

To create an optimized, standalone static release build:

```bash
trunk build --release --public-url /
```

The compiled release artifacts will be output to the `dist/` folder:
- `index.html` — Entry point
- `packetscope-web-*.js` — WebAssembly JavaScript loader
- `packetscope-web-*_bg.wasm` — Compiled and optimized (wasm-opt) WebAssembly binary (~1 MB)
- `style-*.css` — Cybersecurity dark and light theme styles
- `favicon.svg` & `logo.svg` — Visual assets

You can serve the contents of `dist/` with any static web server (such as Python's `python3 -m http.server -d dist 8080`, Nginx, Apache, Caddy, Cloudflare Pages, or GitHub Pages).

### 4. Run the Test Suites

PacketScope includes comprehensive automated test suites covering parser robustness, filter evaluation, flow reconstruction, and CSV sanitization:

```bash
# Run all workspace unit and integration tests
cargo test --workspace

# Run code formatting check
cargo fmt --check

# Run strict Clippy linter
cargo clippy --workspace --all-targets -- -D warnings

# Verify WebAssembly target compilation
cargo check -p packetscope-web --target wasm32-unknown-unknown
```

---

## 🔎 Feature Walkthrough

### 1. Packet Explorer & Hex Dissection
- **Interactive Table**: Paginated browsing of all captured frames with frame number, relative timestamp, source/destination endpoints, protocol, length, and summary information.
- **Protocol Layer Tree**: Expandable nested protocol layers (Frame → Ethernet II → IPv4/IPv6 → TCP/UDP/ICMP → Application Layer).
- **Hex Viewer**: Real-time synchronized byte viewer showing hexadecimal offset, raw hex bytes, and printable ASCII text with selection highlights.

### 2. Display Filter Engine
PacketScope includes an in-browser query engine with autocomplete suggestions:

```
# Filter by source IP
ip.src == 192.168.1.10

# Filter by destination port
tcp.port == 443

# Filter by protocol
protocol == "DNS"

# Combine expressions with logical operators
ip.src == 192.168.1.10 and tcp.port == 80

# Filter by DNS queried domain
dns.qname == "example.com"

# Filter by frame length
frame.len > 1000
```

### 3. Bidirectional Flow Reconstruction
- Groups individual packets into canonical 5-tuples: `(IP A, Port A) ↔ (IP B, Port B) [Protocol]`.
- Calculates forward and reverse traffic volume (bytes and packet count).
- Tracks TCP handshake states (`SYN`, `SYN-ACK`, `ACK`, `RST`, `FIN`) to detect aborted connections or incomplete handshakes.

### 4. Explainable Heuristic Anomaly Detection
PacketScope flags statistical anomalies with transparent evidence and investigation steps:
- **Rule 1: High Traffic Burst** — Detects sudden traffic surges exceeding a configurable multiplier above the baseline PPS.
- **Rule 2: High Destination Fan-Out** — Flags hosts connecting to an abnormally large number of unique destinations in a short window (reconnaissance / scanning).
- **Rule 3: Repeated TCP Connection Attempts** — Detects repeated unanswered SYNs without completed handshakes.
- **Rule 4: High TCP Reset Ratio** — Flags flows where RST packet counts exceed normal operational ratios.
- **Rule 5: DNS Error Spike** — Detects unusual volumes of NXDOMAIN or ServFail responses (DGA or typo squatting).
- **Rule 6: Unusual Port Concentration** — Identifies abnormal volumes of traffic focused on non-standard ports.

### 5. Sanitized Reports & Data Export
- **CSV Exports**: Packets, Flows, Hosts, and Findings can be exported as CSV. All cells beginning with `=`, `+`, `-`, or `@` are automatically escaped with `'` to prevent spreadsheet formula injection.
- **JSON Export**: Complete structured analysis results in JSON format.
- **Printable HTML Report**: Clean executive summary formatted for printing or PDF generation.

---

## 📁 Repository Structure

```
packetscope.rust/
├── .github/
│   └── workflows/
│       ├── ci.yml                 # Continuous integration workflow
│       └── deploy-pages.yml       # GitHub Pages deployment workflow
├── Cargo.toml                     # Workspace configuration
├── Trunk.toml                     # Trunk bundler settings
├── rust-toolchain.toml            # Rust stable toolchain definition
├── index.html                     # HTML application shell
├── public/
│   ├── style.css                  # Dark and Light cybersecurity design system
│   ├── favicon.svg                # Application icon
│   └── logo.svg                   # PacketScope logo
├── fixtures/
│   ├── valid/                     # Sample valid PCAP & PCAPNG captures
│   ├── malformed/                 # Truncated and corrupt capture test files
│   └── expected-results/          # Deterministic test reference snapshots
├── crates/
│   ├── packetscope-core/          # Pure Rust core analysis library
│   │   ├── src/
│   │   │   ├── capture.rs         # Parsing pipeline & reader
│   │   │   ├── demo.rs            # Deterministic demo PCAP generator
│   │   │   ├── export.rs          # Sanitized CSV, JSON, and HTML report generator
│   │   │   ├── filters/           # Query lexer, recursive parser, AST evaluator
│   │   │   ├── findings/          # 6 Explainable anomaly detection rules
│   │   │   ├── flow.rs            # 5-tuple flow aggregation & TCP handshake state
│   │   │   ├── host.rs            # Host inventory & peer correlation
│   │   │   ├── packet.rs          # Packet records & protocol layer models
│   │   │   ├── protocols/         # Protocol decoders (Eth, ARP, IP, TCP, UDP, ICMP, DNS)
│   │   │   ├── statistics.rs      # Protocol distribution & port mapping
│   │   │   └── timeline.rs        # Time bucketing & rate metrics
│   │   └── tests/                 # Unit & integration test suites
│   └── packetscope-web/           # Yew 0.21 WebAssembly frontend
│       └── src/
│           ├── app.rs             # Application state, router & layout
│           ├── components/        # Hex viewer, layer tree, SVG charts
│           ├── pages/             # All 10 forensic views + import screen
│           ├── routes.rs          # Hash-based navigation
│           └── state.rs           # Global state models & theme handling
└── docs/                          # Detailed technical documentation
    ├── architecture.md            # Architecture & topology
    ├── capture-formats.md         # PCAP and PCAPNG specifications
    ├── deployment.md              # Deployment guide
    ├── privacy-and-security.md    # Local-first security & formula injection protection
    ├── supported-protocols.md     # Protocol decoder specifications
    ├── testing.md                 # Test harness instructions
    └── troubleshooting.md         # Common questions and solutions
```

---

## 🛡️ Privacy & Security Commitments

1. **Air-Gapped Operation**: Once loaded, PacketScope does not send any network requests or analytics telemetry.
2. **Memory Safety**: Written entirely in safe Rust with bounds checking on every byte slice to eliminate buffer overflows.
3. **No Parser Panics**: Malformed, truncated, or corrupted frames are captured as error layers without crashing the analysis session.
4. **Formula Injection Sanitization**: All CSV cell exports are strictly sanitized against spreadsheet execution vulnerabilities.

---

## 📚 Technical Documentation

- [Architecture Overview](docs/architecture.md)
- [Supported Protocols](docs/supported-protocols.md)
- [Capture Formats & Specifications](docs/capture-formats.md)
- [Privacy & Security Model](docs/privacy-and-security.md)
- [Testing & Quality Assurance](docs/testing.md)
- [Deployment Guide](docs/deployment.md)
- [Troubleshooting Guide](docs/troubleshooting.md)

---

## 📄 License

PacketScope is dual-licensed under either:
- **MIT License** ([LICENSE](LICENSE))
- **Apache License, Version 2.0** ([LICENSE](LICENSE))

at your option.
