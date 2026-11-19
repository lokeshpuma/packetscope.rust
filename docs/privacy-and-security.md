# Privacy and Security Model

PacketScope was designed from the ground up for strict confidentiality and data protection in sensitive network incident investigations.

## Local-First Execution Boundary

1. **Zero External Data Transmission**:
   - Packet capture files (`.pcap`, `.pcapng`, `.cap`) are loaded directly into browser memory using the HTML5 File API (`FileReader` / `ArrayBuffer`).
   - The analysis pipeline runs inside WebAssembly in the user's browser thread.
   - No packets, IP addresses, payloads, DNS queries, or summary statistics are transmitted to external servers or telemetry endpoints.

2. **Network Isolation**:
   - The application functions normally in offline environments and air-gapped forensic laptops.
   - After initial asset loading, network disconnects do not impair packet parsing, filtering, or report generation.

## Export Sanitization & Formula Injection Defense

CSV exports of security data carry risks when opened in spreadsheet software (Excel, LibreOffice, Google Sheets). Malicious actors can embed payload cells beginning with `=CMD|' /C ...` or similar formulas.

PacketScope enforces automatic formula injection sanitization on every CSV cell export:
- Any cell whose leading character is `=`, `+`, `-`, `@`, `\t`, or `\r` is automatically prefixed with a single quotation mark (`'`).
- Spreadsheet applications display the value as plain text rather than executing it as an active macro or equation.

## Safe Memory Execution

- Written in safe Rust with `#![forbid(unsafe_code)]` across the dissection parser.
- Boundary checks on all byte slices prevent buffer overflow vulnerabilities common in native C parsing tools.
- Out-of-memory guards and chunked parser streaming prevent browser tab crashes on large captures.
