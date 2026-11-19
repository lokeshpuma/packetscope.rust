use crate::packet::{LayerField, ProtocolLayer, TcpFlagsSummary};

#[derive(Debug, Clone)]
pub struct TcpSegment<'a> {
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence_number: u32,
    pub ack_number: u32,
    pub header_length: usize,
    pub flags: TcpFlagsSummary,
    pub raw_flags: u16,
    pub window_size: u16,
    pub payload: &'a [u8],
    pub info: String,
}

pub fn parse_tcp(data: &[u8]) -> Result<(TcpSegment<'_>, ProtocolLayer), String> {
    if data.len() < 20 {
        return Err(format!(
            "TCP segment too short: {} bytes (minimum 20)",
            data.len()
        ));
    }

    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let seq_num = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let ack_num = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

    let data_offset_byte = data[12];
    let data_offset = ((data_offset_byte >> 4) as usize) * 4;
    if data_offset < 20 {
        return Err(format!("Invalid TCP data offset: {} (< 20)", data_offset));
    }
    if data.len() < data_offset {
        return Err(format!(
            "TCP segment truncated: {} bytes available, header requires {}",
            data.len(),
            data_offset
        ));
    }

    let flags_byte = data[13];
    let raw_flags = (((data_offset_byte & 0x01) as u16) << 8) | (flags_byte as u16);
    let flags = TcpFlagsSummary::from_bits(raw_flags);

    let window_size = u16::from_be_bytes([data[14], data[15]]);
    let checksum = u16::from_be_bytes([data[16], data[17]]);
    let urgent_pointer = u16::from_be_bytes([data[18], data[19]]);

    let payload = &data[data_offset..];

    let mut flag_tags = Vec::new();
    if flags.syn {
        flag_tags.push("SYN");
    }
    if flags.ack {
        flag_tags.push("ACK");
    }
    if flags.fin {
        flag_tags.push("FIN");
    }
    if flags.rst {
        flag_tags.push("RST");
    }
    if flags.psh {
        flag_tags.push("PSH");
    }
    if flags.urg {
        flag_tags.push("URG");
    }
    let flag_str = if flag_tags.is_empty() {
        "".to_string()
    } else {
        format!("[{}] ", flag_tags.join(", "))
    };

    let info = format!(
        "{} → {} {}Seq={} Ack={} Win={} Len={}",
        src_port,
        dst_port,
        flag_str,
        seq_num,
        ack_num,
        window_size,
        payload.len()
    );

    let mut fields = vec![
        LayerField::new("Source Port", src_port.to_string()),
        LayerField::new("Destination Port", dst_port.to_string()),
        LayerField::new("Sequence Number", seq_num.to_string()),
        LayerField::new("Acknowledgment Number", ack_num.to_string()),
        LayerField::new("Header Length", format!("{} bytes", data_offset)),
        LayerField::with_hex(
            "Flags",
            flags.to_display_string(),
            format!("0x{:03x}", raw_flags),
        ),
        LayerField::new("Window Size", window_size.to_string()),
        LayerField::with_hex(
            "Checksum",
            format!("0x{:04x}", checksum),
            format!("0x{:04x}", checksum),
        ),
        LayerField::new("Urgent Pointer", urgent_pointer.to_string()),
        LayerField::new("Payload Length", format!("{} bytes", payload.len())),
    ];

    // Parse common options if present
    if data_offset > 20 {
        let options_bytes = &data[20..data_offset];
        let mut opt_idx = 0;
        while opt_idx < options_bytes.len() {
            let opt_type = options_bytes[opt_idx];
            if opt_type == 0 {
                // End of Option List
                break;
            } else if opt_type == 1 {
                // No Operation (NOP)
                opt_idx += 1;
            } else if opt_idx + 1 < options_bytes.len() {
                let opt_len = options_bytes[opt_idx + 1] as usize;
                if opt_len < 2 || opt_idx + opt_len > options_bytes.len() {
                    break;
                }
                match opt_type {
                    2 if opt_len == 4 => {
                        let mss = u16::from_be_bytes([
                            options_bytes[opt_idx + 2],
                            options_bytes[opt_idx + 3],
                        ]);
                        fields.push(LayerField::new(
                            "TCP Option - MSS",
                            format!("{} bytes", mss),
                        ));
                    }
                    3 if opt_len == 3 => {
                        let shift = options_bytes[opt_idx + 2];
                        fields.push(LayerField::new(
                            "TCP Option - Window Scale",
                            format!("{} (multiply by {})", shift, 1 << shift),
                        ));
                    }
                    4 if opt_len == 2 => {
                        fields.push(LayerField::new("TCP Option - SACK Permitted", "Yes"));
                    }
                    8 if opt_len == 10 => {
                        let val = u32::from_be_bytes([
                            options_bytes[opt_idx + 2],
                            options_bytes[opt_idx + 3],
                            options_bytes[opt_idx + 4],
                            options_bytes[opt_idx + 5],
                        ]);
                        fields.push(LayerField::new(
                            "TCP Option - Timestamp Value",
                            val.to_string(),
                        ));
                    }
                    _ => {}
                }
                opt_idx += opt_len;
            } else {
                break;
            }
        }
    }

    let layer = ProtocolLayer {
        name: "Transmission Control Protocol".to_string(),
        description: info.clone(),
        fields,
    };

    Ok((
        TcpSegment {
            source_port: src_port,
            destination_port: dst_port,
            sequence_number: seq_num,
            ack_number: ack_num,
            header_length: data_offset,
            flags,
            raw_flags,
            window_size,
            payload,
            info,
        },
        layer,
    ))
}
