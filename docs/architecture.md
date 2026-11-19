# PacketScope Architecture

PacketScope is organized as a Cargo workspace with a clear separation of concerns between core packet processing logic and the WebAssembly presentation layer.

## System Topology

```
┌─────────────────────────────────────────────────────────────┐
│                       Browser Window                        │
│                                                             │
│  ┌─────────────────────────┐   ┌─────────────────────────┐  │
│  │   Drag & Drop / Demo    │   │  Yew 0.21 UI Framework  │  │
│  └───────────┬─────────────┘   └────────────▲────────────┘  │
│              │ In-Memory ArrayBuffer        │ Reactive State│
│              ▼                              │ Updates       │
│  ┌──────────────────────────────────────────┴────────────┐  │
│  │              crates/packetscope-web                   │  │
│  │  - Page Routers & Navigation (Hash-based)             │  │
│  │  - Hex Viewer Component (Offset, Hex, ASCII)          │  │
│  │  - Layer Tree Component (Protocols & Fields)          │  │
│  │  - SVG Visualizations (Timeline & Communication Graph)│  │
│  │  - Data Export Triggers (Blob & Object URLs)          │  │
│  └──────────────────────────┬────────────────────────────┘  │
│                             │ Safe Function Calls           │
│                             ▼                               │
│  ┌───────────────────────────────────────────────────────┐  │
│  │             crates/packetscope-core                   │  │
│  │  - Format Detector (Magic Bytes: PCAP & PCAPNG)       │  │
│  │  - Protocol Dissection Engine (L2, L3, L4, L7)        │  │
│  │  - Flow Assembler & TCP Handshake State Tracker       │  │
│  │  - Host Inventory & DNS Correlator                    │  │
│  │  - Timeline & Statistics Calculators                  │  │
│  │  - Explainable Heuristic Rule Evaluator               │  │
│  │  - Query Lexer, Parser & Expression Evaluator         │  │
│  │  - Exporters (Sanitized CSV, JSON, Printable HTML)    │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Core Engine (`packetscope-core`)

The `packetscope-core` crate is a pure Rust library that does not depend on web platform APIs, browser globals, or operating system capture libraries (`libpcap`). This design enables:
1. Native compilation for command-line analysis or server-side workflows.
2. WebAssembly compilation for client-side execution inside modern browsers.
3. Fast headless unit testing across sample capture fixtures.

### Parsing Pipeline
1. **Header Validation**: `detect_format` inspects magic numbers (`0xa1b2c3d4`, `0xd4c3b2a1`, `0x4d3c2b1a`, `0x1a2b3c4d`, `0x0a0d0d0a`).
2. **Block Iteration**: `pcap_parser::create_reader` streams packet records without reading entire files into unbounded buffers.
3. **Layer Decoding**: `dissect_packet` decodes link, network, transport, and application layers, extracting structured fields for display and query evaluation.
4. **Flow Assembly**: Packets are grouped by canonical 5-tuples (`min(ip1, ip2)`, `max(ip1, ip2)`), aggregating forward and reverse counters, duration, and TCP control flags.
5. **Timeline Aggregation**: Traffic volume is binned into 1-second resolution intervals for PPS, BPS, and protocol composition metrics.
6. **Heuristic Evaluation**: Explainable rules evaluate packet and flow counters against configurable anomaly thresholds.

## Web Frontend (`packetscope-web`)

The `packetscope-web` crate uses Yew 0.21 with client-side rendering (CSR):
- **Local-First Privacy**: File data loaded via `<input type="file">` or Drag-and-Drop is parsed entirely in memory inside the WebAssembly linear memory space. No network requests are made.
- **Hash-Based Routing**: All views (`#overview`, `#packets`, `#conversations`, `#hosts`, `#protocols`, `#dns`, `#findings`, `#timeline`, `#reports`, `#settings`) use URL fragment hashes, guaranteeing correct loading on static hosting providers like GitHub Pages without server-side rewrite rules.
