use pcap_parser::*;
use std::io::Cursor;

#[test]
fn test_create_reader_pcap() {
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

    let mut reader = create_reader(65536, Cursor::new(&data)).expect("create_reader failed");
    let mut packet_count = 0;
    loop {
        match reader.next() {
            Ok((offset, block)) => {
                if let PcapBlockOwned::Legacy(packet) = block {
                    packet_count += 1;
                    assert_eq!(packet.caplen, 14);
                }
                reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                if reader.refill().is_err() {
                    break;
                }
            }
            Err(e) => panic!("Reader error: {:?}", e),
        }
    }
    assert_eq!(packet_count, 1);
}

#[test]
fn test_create_reader_pcapng() {
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

    // EPB: type 0x00000006, block len 48, if_id 0, ts_high 0, ts_low 1000, caplen 14, origlen 14, 14 bytes data + 2 bytes pad, block len 48
    data.extend_from_slice(&0x00000006u32.to_le_bytes());
    data.extend_from_slice(&48u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&1000u32.to_le_bytes());
    data.extend_from_slice(&14u32.to_le_bytes());
    data.extend_from_slice(&14u32.to_le_bytes());
    data.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    data.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    data.extend_from_slice(&[0x08, 0x06]);
    data.extend_from_slice(&[0x00, 0x00]); // padding to 32 bits
    data.extend_from_slice(&48u32.to_le_bytes());

    let mut reader = create_reader(65536, Cursor::new(&data)).expect("create_reader failed");
    let mut epb_count = 0;
    loop {
        match reader.next() {
            Ok((offset, block)) => {
                if let PcapBlockOwned::NG(pcapng::Block::EnhancedPacket(epb)) = block {
                    epb_count += 1;
                    assert_eq!(epb.caplen, 14);
                }
                reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                if reader.refill().is_err() {
                    break;
                }
            }
            Err(e) => panic!("Reader error: {:?}", e),
        }
    }
    assert_eq!(epb_count, 1);
}
