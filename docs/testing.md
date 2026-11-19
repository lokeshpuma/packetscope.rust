# Testing Guide

PacketScope includes a comprehensive test suite across unit, integration, and parser regression tests.

## Running Tests Locally

### 1. Workspace Test Suite
Run all unit and integration tests across all workspace crates:
```bash
cargo test --workspace
```

### 2. Core Library Tests
Run unit tests for protocol parsing, filter parsing, flow aggregation, and CSV injection sanitization:
```bash
cargo test -p packetscope-core
```

### 3. WebAssembly Compilation Check
Verify that the web interface and WASM bindings compile cleanly:
```bash
cargo check -p packetscope-web --target wasm32-unknown-unknown
```

### 4. Code Formatting & Linter
Run standard Rust format checks and strict Clippy audits:
```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
```

## Test Fixtures & Regression Suites

Test fixtures are stored under `fixtures/`:
- `fixtures/valid/sample.pcap`: Valid classic PCAP capture with ARP, DNS, HTTP, ICMP, and NTP.
- `fixtures/valid/sample.pcapng`: Valid PCAPNG file with Section Header and Enhanced Packet Blocks.
- `fixtures/malformed/corrupted_header.pcap`: Capture with invalid magic bytes to verify error reporting.
- `fixtures/malformed/truncated_packet.pcap`: Capture with snaplen truncation to verify parser safety.
- `fixtures/expected-results/demo_summary.json`: Reference JSON values for demo mode verification.

To regenerate fixtures deterministically, execute:
```bash
cargo test -p packetscope-core --test generate_fixtures
```
