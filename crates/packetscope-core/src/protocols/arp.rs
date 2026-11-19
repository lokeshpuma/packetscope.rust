use super::ethernet::format_mac;
use crate::packet::{LayerField, ProtocolLayer};

#[derive(Debug, Clone)]
pub struct ArpPacket {
    pub opcode: u16,
    pub sender_mac: String,
    pub sender_ip: String,
    pub target_mac: String,
    pub target_ip: String,
    pub info: String,
}

pub fn parse_arp(data: &[u8]) -> Result<(ArpPacket, ProtocolLayer), String> {
    if data.len() < 28 {
        return Err(format!(
            "ARP packet too short: {} bytes (minimum 28)",
            data.len()
        ));
    }

    let hw_type = u16::from_be_bytes([data[0], data[1]]);
    let proto_type = u16::from_be_bytes([data[2], data[3]]);
    let hw_len = data[4];
    let proto_len = data[5];
    let opcode = u16::from_be_bytes([data[6], data[7]]);

    if hw_len != 6 || proto_len != 4 {
        return Err(format!(
            "Unsupported ARP hardware/protocol address length: {}/{}",
            hw_len, proto_len
        ));
    }

    let sender_mac = format_mac(&data[8..14]);
    let sender_ip = format!("{}.{}.{}.{}", data[14], data[15], data[16], data[17]);
    let target_mac = format_mac(&data[18..24]);
    let target_ip = format!("{}.{}.{}.{}", data[24], data[25], data[26], data[27]);

    let (op_desc, info) = match opcode {
        1 => (
            "Request (1)",
            format!("Who has {}? Tell {}", target_ip, sender_ip),
        ),
        2 => ("Reply (2)", format!("{} is at {}", sender_ip, sender_mac)),
        other => ("Unknown", format!("ARP opcode {}", other)),
    };

    let fields = vec![
        LayerField::new(
            "Hardware Type",
            if hw_type == 1 {
                "Ethernet (1)"
            } else {
                "Unknown"
            },
        ),
        LayerField::new(
            "Protocol Type",
            if proto_type == 0x0800 {
                "IPv4 (0x0800)"
            } else {
                "Unknown"
            },
        ),
        LayerField::new("Hardware Size", hw_len.to_string()),
        LayerField::new("Protocol Size", proto_len.to_string()),
        LayerField::new("Opcode", op_desc),
        LayerField::new("Sender MAC Address", &sender_mac),
        LayerField::new("Sender IP Address", &sender_ip),
        LayerField::new("Target MAC Address", &target_mac),
        LayerField::new("Target IP Address", &target_ip),
    ];

    let layer = ProtocolLayer {
        name: "Address Resolution Protocol".to_string(),
        description: info.clone(),
        fields,
    };

    Ok((
        ArpPacket {
            opcode,
            sender_mac,
            sender_ip,
            target_mac,
            target_ip,
            info,
        },
        layer,
    ))
}
