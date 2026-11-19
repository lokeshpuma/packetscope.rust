# Supported Protocols

PacketScope includes pure Rust protocol decoders capable of parsing standard network headers and extracting structured fields for inspection and query filtering.

## Link Layer
- **Ethernet II**: Destination MAC, Source MAC, EtherType (IPv4, IPv6, ARP, 802.1Q).
- **IEEE 802.1Q VLAN**: Priority Code Point (PCP), Drop Eligible Indicator (DEI), VLAN ID (VID), and encapsulated EtherType.
- **Linux Cooked Capture (SLL)**: Link layer encapsulation support.

## Network Layer
- **IPv4**: Version, Internet Header Length (IHL), Type of Service / DSCP / ECN, Total Length, Identification, Flags (DF, MF), Fragment Offset, Time to Live (TTL), Protocol number, Header Checksum, Source IP, Destination IP.
- **IPv6**: Version, Traffic Class, Flow Label, Payload Length, Next Header, Hop Limit, Source IPv6, Destination IPv6, and Extension Header chain traversal (Hop-by-Hop, Routing, Fragment, ESP, AH, Destination Options).
- **ARP**: Hardware Type, Protocol Type, Hardware Size, Protocol Size, Opcode (Request, Reply), Sender MAC, Sender IP, Target MAC, Target IP.

## Transport Layer
- **TCP**: Source Port, Destination Port, Sequence Number, Acknowledgment Number, Data Offset, Control Flags (FIN, SYN, RST, PSH, ACK, URG, ECE, CWR), Window Size, Checksum, Urgent Pointer, and Options (MSS, Window Scale, SACK Permitted, Timestamps, NOP, End of Options).
- **UDP**: Source Port, Destination Port, Length, Checksum, and Payload extraction.
- **ICMPv4**: Type, Code, Checksum, Identifier, Sequence Number, and Human-readable Type/Code descriptions (Echo Reply, Destination Unreachable, Echo Request, Time Exceeded).
- **ICMPv6**: Type, Code, Checksum, Message category (Echo Request, Echo Reply, Neighbor Solicitation, Neighbor Advertisement, Packet Too Big).

## Application Layer
- **DNS**:
  - Transaction ID, Flags (QR, Opcode, AA, TC, RD, RA, RCODE).
  - Query count, Answer count, Authority count, Additional count.
  - Question dissection: Query Name (with loop-safe compression pointer resolution), Query Type (A, AAAA, CNAME, MX, NS, PTR, SOA, TXT, SRV, ANY), Query Class.
  - Resource Record dissection: Answer Name, Type, Class, TTL, Data Length, and Decoded IP or Hostname targets.
- **HTTP/1.x**:
  - Request line parsing (GET, POST, PUT, DELETE, HEAD, OPTIONS).
  - Response status line parsing (HTTP/1.1 200 OK, 404 Not Found, etc.).
  - Payload preview extraction.
- **TLS (SSL)**:
  - Record Layer Header (ContentType 0x16 Handshake, 0x17 Application Data, 0x15 Alert).
  - Protocol Version decoding (TLS 1.0, 1.1, 1.2, 1.3).
  - Handshake type detection (Client Hello, Server Hello, Certificate, Server Key Exchange).
