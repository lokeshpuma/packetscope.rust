use pcap_parser::*;

#[test]
fn test_pcap_parser_basic_pcap() {
    let mut data = Vec::new();
    data.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    data.extend_from_slice(&2u16.to_le_bytes());
    data.extend_from_slice(&4u16.to_le_bytes());
    data.extend_from_slice(&0i32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&65535u32.to_le_bytes());
    data.extend_from_slice(&1u32.to_le_bytes());

    data.extend_from_slice(&1700000000u32.to_le_bytes());
    data.extend_from_slice(&500000u32.to_le_bytes());
    data.extend_from_slice(&14u32.to_le_bytes());
    data.extend_from_slice(&14u32.to_le_bytes());
    data.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    data.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    data.extend_from_slice(&[0x08, 0x06]);

    let (rem, header) = parse_pcap_header(&data).expect("Failed to parse pcap header");
    assert_eq!(header.version_major, 2);
    assert_eq!(header.version_minor, 4);
    assert_eq!(header.network, Linktype(1));

    let (rem2, packet) = parse_pcap_frame(rem).expect("Failed to parse packet");
    assert_eq!(packet.caplen, 14);
    assert_eq!(packet.origlen, 14);
    assert_eq!(packet.data.len(), 14);
    assert!(rem2.is_empty());
}

#[test]
fn test_pcapng_parser_basic() {
    let mut data = Vec::new();
    // SHB: type 0x0A0D0D0A, len 28, BOM 0x1A2B3C4D, v1.0, section_len -1, len 28
    data.extend_from_slice(&0x0A0D0D0Au32.to_le_bytes());
    data.extend_from_slice(&28u32.to_le_bytes());
    data.extend_from_slice(&0x1A2B3C4Du32.to_le_bytes());
    data.extend_from_slice(&1u16.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    data.extend_from_slice(&(-1i64).to_le_bytes());
    data.extend_from_slice(&28u32.to_le_bytes());

    // IDB: type 0x00000001, len 20, linktype 1 (Ethernet), reserved 0, snaplen 65535, len 20
    data.extend_from_slice(&0x00000001u32.to_le_bytes());
    data.extend_from_slice(&20u32.to_le_bytes());
    data.extend_from_slice(&1u16.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    data.extend_from_slice(&65535u32.to_le_bytes());
    data.extend_from_slice(&20u32.to_le_bytes());

    let (rem, capture) = parse_pcapng(&data).expect("Failed to parse pcapng");
    assert_eq!(capture.sections.len(), 1);
    assert_eq!(capture.sections[0].iter_interfaces().count(), 1);
    assert!(rem.is_empty());
}
