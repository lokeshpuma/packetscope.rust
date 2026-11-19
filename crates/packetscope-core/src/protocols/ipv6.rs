use crate::packet::{LayerField, ProtocolLayer};

#[derive(Debug, Clone)]
pub struct Ipv6Header<'a> {
    pub source_ip: String,
    pub destination_ip: String,
    pub next_header: u8,
    pub protocol_name: &'static str,
    pub hop_limit: u8,
    pub payload_length: u16,
    pub flow_label: u32,
    pub payload: &'a [u8],
}

pub fn format_ipv6(bytes: &[u8]) -> String {
    if bytes.len() >= 16 {
        let segments: Vec<u16> = (0..8)
            .map(|i| u16::from_be_bytes([bytes[i * 2], bytes[i * 2 + 1]]))
            .collect();
        format!(
            "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
            segments[0],
            segments[1],
            segments[2],
            segments[3],
            segments[4],
            segments[5],
            segments[6],
            segments[7]
        )
    } else {
        "::".to_string()
    }
}

pub fn parse_ipv6(data: &[u8]) -> Result<(Ipv6Header<'_>, ProtocolLayer), String> {
    if data.len() < 40 {
        return Err(format!(
            "IPv6 packet too short: {} bytes (minimum 40)",
            data.len()
        ));
    }

    let version = (data[0] >> 4) & 0x0F;
    if version != 6 {
        return Err(format!("Invalid IPv6 version: {}", version));
    }

    let traffic_class = ((data[0] & 0x0F) << 4) | ((data[1] >> 4) & 0x0F);
    let flow_label = (((data[1] & 0x0F) as u32) << 16) | ((data[2] as u32) << 8) | (data[3] as u32);
    let payload_len = u16::from_be_bytes([data[4], data[5]]);
    let mut next_header = data[6];
    let hop_limit = data[7];

    let src_ip = format_ipv6(&data[8..24]);
    let dst_ip = format_ipv6(&data[24..40]);

    // Parse extension headers safely
    let mut offset = 40;
    let mut extension_depth = 0;
    while extension_depth < 8 && offset < data.len() {
        match next_header {
            0 | 43 | 60 => {
                // Hop-by-Hop, Routing, Destination Options: 1 byte next header, 1 byte length in 8-byte units
                if offset + 2 > data.len() {
                    break;
                }
                let ext_next = data[offset];
                let ext_len = ((data[offset + 1] as usize) + 1) * 8;
                if offset + ext_len > data.len() {
                    break;
                }
                next_header = ext_next;
                offset += ext_len;
                extension_depth += 1;
            }
            44 => {
                // Fragment: 8 bytes fixed
                if offset + 8 > data.len() {
                    break;
                }
                next_header = data[offset];
                offset += 8;
                extension_depth += 1;
            }
            _ => break,
        }
    }

    let proto_name = match next_header {
        6 => "TCP",
        17 => "UDP",
        58 => "ICMPv6",
        _ => "Unknown",
    };

    let payload = if offset <= data.len() {
        &data[offset..]
    } else {
        &[]
    };

    let fields = vec![
        LayerField::new("Version", "6"),
        LayerField::new("Traffic Class", format!("0x{:02x}", traffic_class)),
        LayerField::new("Flow Label", format!("0x{:05x}", flow_label)),
        LayerField::new("Payload Length", format!("{} bytes", payload_len)),
        LayerField::new("Next Header", format!("{} ({})", proto_name, next_header)),
        LayerField::new("Hop Limit", hop_limit.to_string()),
        LayerField::new("Source IP Address", &src_ip),
        LayerField::new("Destination IP Address", &dst_ip),
    ];

    let layer = ProtocolLayer {
        name: "Internet Protocol Version 6".to_string(),
        description: format!("Src: {}, Dst: {}", src_ip, dst_ip),
        fields,
    };

    Ok((
        Ipv6Header {
            source_ip: src_ip,
            destination_ip: dst_ip,
            next_header,
            protocol_name: proto_name,
            hop_limit,
            payload_length: payload_len,
            flow_label,
            payload,
        },
        layer,
    ))
}
