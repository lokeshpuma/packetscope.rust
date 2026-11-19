use crate::packet::{LayerField, ProtocolLayer};

#[derive(Debug, Clone)]
pub struct IcmpMessage<'a> {
    pub message_type: u8,
    pub code: u8,
    pub checksum: u16,
    pub type_description: &'static str,
    pub identifier: Option<u16>,
    pub sequence_number: Option<u16>,
    pub payload: &'a [u8],
    pub info: String,
}

pub fn parse_icmp(data: &[u8], is_v6: bool) -> Result<(IcmpMessage<'_>, ProtocolLayer), String> {
    if data.len() < 4 {
        return Err(format!(
            "ICMP packet too short: {} bytes (minimum 4)",
            data.len()
        ));
    }

    let msg_type = data[0];
    let code = data[1];
    let checksum = u16::from_be_bytes([data[2], data[3]]);

    let mut identifier = None;
    let mut sequence_number = None;

    let (type_desc, info) = if !is_v6 {
        match msg_type {
            0 => {
                if data.len() >= 8 {
                    identifier = Some(u16::from_be_bytes([data[4], data[5]]));
                    sequence_number = Some(u16::from_be_bytes([data[6], data[7]]));
                }
                (
                    "Echo (ping) Reply",
                    format!(
                        "Echo (ping) reply id={:?} seq={:?}",
                        identifier.unwrap_or(0),
                        sequence_number.unwrap_or(0)
                    ),
                )
            }
            3 => {
                let reason = match code {
                    0 => "Net Unreachable",
                    1 => "Host Unreachable",
                    2 => "Protocol Unreachable",
                    3 => "Port Unreachable",
                    _ => "Destination Unreachable",
                };
                (
                    "Destination Unreachable",
                    format!("Destination unreachable ({})", reason),
                )
            }
            8 => {
                if data.len() >= 8 {
                    identifier = Some(u16::from_be_bytes([data[4], data[5]]));
                    sequence_number = Some(u16::from_be_bytes([data[6], data[7]]));
                }
                (
                    "Echo (ping) Request",
                    format!(
                        "Echo (ping) request id={:?} seq={:?}",
                        identifier.unwrap_or(0),
                        sequence_number.unwrap_or(0)
                    ),
                )
            }
            11 => ("Time Exceeded", "Time-to-live exceeded".to_string()),
            _ => (
                "ICMP Message",
                format!("Type: {}, Code: {}", msg_type, code),
            ),
        }
    } else {
        match msg_type {
            128 => {
                if data.len() >= 8 {
                    identifier = Some(u16::from_be_bytes([data[4], data[5]]));
                    sequence_number = Some(u16::from_be_bytes([data[6], data[7]]));
                }
                (
                    "Echo Request",
                    format!(
                        "Echo request id={:?} seq={:?}",
                        identifier.unwrap_or(0),
                        sequence_number.unwrap_or(0)
                    ),
                )
            }
            129 => {
                if data.len() >= 8 {
                    identifier = Some(u16::from_be_bytes([data[4], data[5]]));
                    sequence_number = Some(u16::from_be_bytes([data[6], data[7]]));
                }
                (
                    "Echo Reply",
                    format!(
                        "Echo reply id={:?} seq={:?}",
                        identifier.unwrap_or(0),
                        sequence_number.unwrap_or(0)
                    ),
                )
            }
            135 => ("Neighbor Solicitation", "Neighbor Solicitation".to_string()),
            136 => (
                "Neighbor Advertisement",
                "Neighbor Advertisement".to_string(),
            ),
            _ => (
                "ICMPv6 Message",
                format!("Type: {}, Code: {}", msg_type, code),
            ),
        }
    };

    let payload = if data.len() >= 8 {
        &data[8..]
    } else {
        &data[4..]
    };

    let mut fields = vec![
        LayerField::new("Type", format!("{} ({})", type_desc, msg_type)),
        LayerField::new("Code", code.to_string()),
        LayerField::with_hex(
            "Checksum",
            format!("0x{:04x}", checksum),
            format!("0x{:04x}", checksum),
        ),
    ];

    if let Some(id) = identifier {
        fields.push(LayerField::new("Identifier", id.to_string()));
    }
    if let Some(seq) = sequence_number {
        fields.push(LayerField::new("Sequence Number", seq.to_string()));
    }

    let layer_name = if is_v6 {
        "Internet Control Message Protocol v6"
    } else {
        "Internet Control Message Protocol"
    };

    let layer = ProtocolLayer {
        name: layer_name.to_string(),
        description: info.clone(),
        fields,
    };

    Ok((
        IcmpMessage {
            message_type: msg_type,
            code,
            checksum,
            type_description: type_desc,
            identifier,
            sequence_number,
            payload,
            info,
        },
        layer,
    ))
}
