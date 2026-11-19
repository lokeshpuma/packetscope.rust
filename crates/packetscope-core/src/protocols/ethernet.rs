use crate::packet::{LayerField, ProtocolLayer};

#[derive(Debug, Clone)]
pub struct EthernetFrame<'a> {
    pub source_mac: String,
    pub destination_mac: String,
    pub ether_type: u16,
    pub vlan_id: Option<u16>,
    pub payload: &'a [u8],
}

pub fn format_mac(bytes: &[u8]) -> String {
    if bytes.len() >= 6 {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
        )
    } else {
        "00:00:00:00:00:00".to_string()
    }
}

pub fn parse_ethernet(data: &[u8]) -> Result<(EthernetFrame<'_>, ProtocolLayer), String> {
    if data.len() < 14 {
        return Err(format!(
            "Ethernet frame too short: {} bytes (minimum 14)",
            data.len()
        ));
    }

    let dst_mac = format_mac(&data[0..6]);
    let src_mac = format_mac(&data[6..12]);
    let mut ether_type = u16::from_be_bytes([data[12], data[13]]);
    let mut offset = 14;
    let mut vlan_id = None;

    // Check for 802.1Q VLAN Tag (0x8100)
    if (ether_type == 0x8100 || ether_type == 0x88a8) && data.len() >= offset + 4 {
        let tci = u16::from_be_bytes([data[offset], data[offset + 1]]);
        vlan_id = Some(tci & 0x0FFF);
        ether_type = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        offset += 4;
    }

    let payload = &data[offset..];

    let mut fields = vec![
        LayerField::with_hex("Destination MAC", &dst_mac, format!("{:02x?}", &data[0..6])),
        LayerField::with_hex("Source MAC", &src_mac, format!("{:02x?}", &data[6..12])),
    ];

    if let Some(vlan) = vlan_id {
        fields.push(LayerField::new("802.1Q VLAN ID", vlan.to_string()));
    }

    let ether_type_desc = match ether_type {
        0x0800 => "IPv4 (0x0800)",
        0x86dd => "IPv6 (0x86dd)",
        0x0806 => "ARP (0x0806)",
        0x8100 => "VLAN (0x8100)",
        _other => "Unknown",
    };

    fields.push(LayerField::with_hex(
        "EtherType",
        ether_type_desc,
        format!("0x{:04x}", ether_type),
    ));

    let layer = ProtocolLayer {
        name: "Ethernet II".to_string(),
        description: format!("Src: {}, Dst: {}", src_mac, dst_mac),
        fields,
    };

    Ok((
        EthernetFrame {
            source_mac: src_mac,
            destination_mac: dst_mac,
            ether_type,
            vlan_id,
            payload,
        },
        layer,
    ))
}
