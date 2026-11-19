use crate::packet::{LayerField, ProtocolLayer};

#[derive(Debug, Clone)]
pub struct UdpDatagram<'a> {
    pub source_port: u16,
    pub destination_port: u16,
    pub length: u16,
    pub checksum: u16,
    pub payload: &'a [u8],
    pub info: String,
}

pub fn parse_udp(data: &[u8]) -> Result<(UdpDatagram<'_>, ProtocolLayer), String> {
    if data.len() < 8 {
        return Err(format!(
            "UDP datagram too short: {} bytes (minimum 8)",
            data.len()
        ));
    }

    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let length = u16::from_be_bytes([data[4], data[5]]);
    let checksum = u16::from_be_bytes([data[6], data[7]]);

    let payload_len = if (length as usize) >= 8 && (length as usize) <= data.len() {
        (length as usize) - 8
    } else if data.len() >= 8 {
        data.len() - 8
    } else {
        0
    };

    let payload = if data.len() >= 8 + payload_len {
        &data[8..8 + payload_len]
    } else {
        &data[8..]
    };

    let info = format!("{} → {} Len={}", src_port, dst_port, payload.len());

    let fields = vec![
        LayerField::new("Source Port", src_port.to_string()),
        LayerField::new("Destination Port", dst_port.to_string()),
        LayerField::new("Length", format!("{} bytes", length)),
        LayerField::with_hex(
            "Checksum",
            format!("0x{:04x}", checksum),
            format!("0x{:04x}", checksum),
        ),
        LayerField::new("Payload Length", format!("{} bytes", payload.len())),
    ];

    let layer = ProtocolLayer {
        name: "User Datagram Protocol".to_string(),
        description: info.clone(),
        fields,
    };

    Ok((
        UdpDatagram {
            source_port: src_port,
            destination_port: dst_port,
            length,
            checksum,
            payload,
            info,
        },
        layer,
    ))
}
