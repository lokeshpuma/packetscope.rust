# Capture Formats

PacketScope parses both legacy PCAP and modern PCAPNG capture formats without native C-library bindings.

## Supported Formats

| Format | Magic Bytes (Hex) | Endianness | Timestamp Precision |
| :--- | :--- | :--- | :--- |
| **Classic PCAP (Microseconds)** | `a1 b2 c3 d4` | Big-Endian (Network) | Microseconds (10⁻⁶ s) |
| **Classic PCAP (Microseconds)** | `d4 c3 b2 a1` | Little-Endian | Microseconds (10⁻⁶ s) |
| **Classic PCAP (Nanoseconds)** | `a1 b2 3c 4d` | Big-Endian (Network) | Nanoseconds (10⁻⁹ s) |
| **Classic PCAP (Nanoseconds)** | `4d 3c b2 a1` | Little-Endian | Nanoseconds (10⁻⁹ s) |
| **PCAP Next Generation (PCAPNG)** | `0a 0d 0d 0a` | Big or Little Endian | Configured per Interface Description Block |

## Format Detection Strategy

When a file is loaded, PacketScope reads the first 4 bytes to identify the container type:
- If `0x0a0d0d0a` is detected, it enters PCAPNG mode. The engine processes Section Header Blocks (SHB), Interface Description Blocks (IDB), Enhanced Packet Blocks (EPB), and Simple Packet Blocks (SPB).
- If one of the classic PCAP magic words is matched, the engine determines byte endianness and sets timestamp precision accordingly.
- If magic bytes do not match any recognized header, the parser returns `CaptureError::InvalidHeader` with an explanation and actionable suggestions.

## Safe Handling of Truncated and Malformed Packets

In real-world forensic workflows, captures may be captured with snaplen limits or suffer transmission corruption:
- **Snaplen Truncation**: When `captured_length < original_length`, the packet is flagged as `truncated = true`. Dissectors safely slice available bytes without panicking.
- **Malformed Protocol Headers**: If a header indicates an invalid length field or exceeds block bounds, the parser registers a `ProtocolLayer::Malformed` entry and continues processing subsequent packets.
- **DNS Loop Prevention**: A pointer jump counter tracks label compression offsets, preventing infinite recursion on circular compression loops.
