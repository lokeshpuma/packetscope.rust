use crate::packet::{LayerField, ProtocolLayer};

#[derive(Debug, Clone)]
pub struct Ipv4Header<'a> {
    pub source_ip: String,
    pub destination_ip: String,
    pub protocol: u8,
    pub protocol_name: &'static str,
    pub ttl: u8,
    pub total_length: u16,
    pub header_length: usize,
    pub identification: u16,
    pub flags_df: bool,
    pub flags_mf: bool,
    pub fragment_offset: u16,
    pub payload: &'a [u8],
}

pub fn parse_ipv4(data: &[u8]) -> Result<(Ipv4Header<'_>, ProtocolLayer), String> {
    if data.len() < 20 {
        return Err(format!(
            "IPv4 packet too short: {} bytes (minimum 20)",
            data.len()
        ));
    }

    let version = (data[0] >> 4) & 0x0F;
    if version != 4 {
        return Err(format!("Invalid IPv4 version: {}", version));
    }

    let ihl = (data[0] & 0x0F) as usize;
    let header_len = ihl * 4;
    if ihl < 5 {
        return Err(format!("Invalid IPv4 IHL: {} (< 5)", ihl));
    }
    if data.len() < header_len {
        return Err(format!(
            "IPv4 packet truncated: {} bytes available, header requires {}",
            data.len(),
            header_len
        ));
    }

    let total_len = u16::from_be_bytes([data[2], data[3]]);
    let identification = u16::from_be_bytes([data[4], data[5]]);
    let flags_and_frag = u16::from_be_bytes([data[6], data[7]]);
    let flags_df = (flags_and_frag & 0x4000) != 0;
    let flags_mf = (flags_and_frag & 0x2000) != 0;
    let fragment_offset = (flags_and_frag & 0x1FFF) * 8;
    let ttl = data[8];
    let protocol = data[9];
    let checksum = u16::from_be_bytes([data[10], data[11]]);

    let src_ip = format!("{}.{}.{}.{}", data[12], data[13], data[14], data[15]);
    let dst_ip = format!("{}.{}.{}.{}", data[16], data[17], data[18], data[19]);

    let proto_name = match protocol {
        1 => "ICMP",
        6 => "TCP",
        17 => "UDP",
        2 => "IGMP",
        89 => "OSPF",
        _ => "Unknown",
    };

    let payload_end = if (total_len as usize) > header_len && (total_len as usize) <= data.len() {
        total_len as usize
    } else {
        data.len()
    };

    let payload = &data[header_len..payload_end];

    let fields = vec![
        LayerField::new("Version", "4"),
        LayerField::new("Header Length", format!("{} bytes ({})", header_len, ihl)),
        LayerField::new("Total Length", total_len.to_string()),
        LayerField::with_hex(
            "Identification",
            format!("{}", identification),
            format!("0x{:04x}", identification),
        ),
        LayerField::new(
            "Don't Fragment (DF)",
            if flags_df { "Set" } else { "Not set" },
        ),
        LayerField::new(
            "More Fragments (MF)",
            if flags_mf { "Set" } else { "Not set" },
        ),
        LayerField::new("Fragment Offset", fragment_offset.to_string()),
        LayerField::new("Time to Live (TTL)", ttl.to_string()),
        LayerField::new("Protocol", format!("{} ({})", proto_name, protocol)),
        LayerField::with_hex(
            "Header Checksum",
            format!("0x{:04x}", checksum),
            format!("0x{:04x}", checksum),
        ),
        LayerField::new("Source IP Address", &src_ip),
        LayerField::new("Destination IP Address", &dst_ip),
    ];

    let layer = ProtocolLayer {
        name: "Internet Protocol Version 4".to_string(),
        description: format!("Src: {}, Dst: {}", src_ip, dst_ip),
        fields,
    };

    Ok((
        Ipv4Header {
            source_ip: src_ip,
            destination_ip: dst_ip,
            protocol,
            protocol_name: proto_name,
            ttl,
            total_length: total_len,
            header_length: header_len,
            identification,
            flags_df,
            flags_mf,
            fragment_offset,
            payload,
        },
        layer,
    ))
}
