use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TcpFlagsSummary {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub psh: bool,
    pub urg: bool,
    pub ece: bool,
    pub cwr: bool,
}

impl TcpFlagsSummary {
    pub fn from_bits(bits: u16) -> Self {
        Self {
            fin: (bits & 0x01) != 0,
            syn: (bits & 0x02) != 0,
            rst: (bits & 0x04) != 0,
            psh: (bits & 0x08) != 0,
            ack: (bits & 0x10) != 0,
            urg: (bits & 0x20) != 0,
            ece: (bits & 0x40) != 0,
            cwr: (bits & 0x80) != 0,
        }
    }

    pub fn to_display_string(&self) -> String {
        let mut flags = Vec::new();
        if self.syn {
            flags.push("SYN");
        }
        if self.ack {
            flags.push("ACK");
        }
        if self.fin {
            flags.push("FIN");
        }
        if self.rst {
            flags.push("RST");
        }
        if self.psh {
            flags.push("PSH");
        }
        if self.urg {
            flags.push("URG");
        }
        if self.ece {
            flags.push("ECE");
        }
        if self.cwr {
            flags.push("CWR");
        }
        if flags.is_empty() {
            "None".to_string()
        } else {
            flags.join(", ")
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayerField {
    pub name: String,
    pub value: String,
    pub hex_value: Option<String>,
}

impl LayerField {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            hex_value: None,
        }
    }

    pub fn with_hex(
        name: impl Into<String>,
        value: impl Into<String>,
        hex: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            hex_value: Some(hex.into()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolLayer {
    pub name: String,
    pub description: String,
    pub fields: Vec<LayerField>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PacketRecord {
    pub index: u64,
    pub timestamp_ns: Option<u128>,
    pub timestamp_iso: String,
    pub captured_length: u32,
    pub original_length: u32,

    pub link_type: u16,
    pub source_mac: Option<String>,
    pub destination_mac: Option<String>,
    pub vlan_id: Option<u16>,

    pub source_ip: Option<String>,
    pub destination_ip: Option<String>,

    pub network_protocol: String,
    pub transport_protocol: Option<String>,
    pub application_protocol: Option<String>,

    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,

    pub tcp_flags: Option<TcpFlagsSummary>,
    pub tcp_seq: Option<u32>,
    pub tcp_ack: Option<u32>,

    pub payload_length: u32,
    pub interface_id: Option<u32>,

    pub truncated: bool,
    pub parse_warnings: Vec<String>,
    pub info: String,

    pub layers: Vec<ProtocolLayer>,
    pub raw_bytes: Vec<u8>,
}

impl PacketRecord {
    pub fn primary_source(&self) -> String {
        if let Some(ref ip) = self.source_ip {
            ip.clone()
        } else if let Some(ref mac) = self.source_mac {
            mac.clone()
        } else {
            "Unknown".to_string()
        }
    }

    pub fn primary_destination(&self) -> String {
        if let Some(ref ip) = self.destination_ip {
            ip.clone()
        } else if let Some(ref mac) = self.destination_mac {
            mac.clone()
        } else {
            "Unknown".to_string()
        }
    }

    pub fn protocol_display(&self) -> String {
        if let Some(ref app) = self.application_protocol {
            app.clone()
        } else if let Some(ref trans) = self.transport_protocol {
            trans.clone()
        } else {
            self.network_protocol.clone()
        }
    }
}
