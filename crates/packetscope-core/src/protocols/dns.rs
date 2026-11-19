use crate::packet::{LayerField, ProtocolLayer};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: u16,
    pub qtype_name: String,
    pub qclass: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsAnswer {
    pub name: String,
    pub rtype: u16,
    pub rtype_name: String,
    pub ttl: u32,
    pub data: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DnsRecord {
    pub packet_index: u64,
    pub timestamp_ns: Option<u128>,
    pub timestamp_iso: String,
    pub source_ip: String,
    pub destination_ip: String,
    pub transaction_id: u16,
    pub is_response: bool,
    pub opcode: u8,
    pub rcode: u8,
    pub rcode_name: String,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsAnswer>,
    pub primary_query: String,
    pub primary_query_type: String,
    pub latency_ms: Option<f64>,
}

pub fn type_to_name(t: u16) -> &'static str {
    match t {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        255 => "ANY",
        _ => "OTHER",
    }
}

pub fn rcode_to_name(code: u8) -> &'static str {
    match code {
        0 => "NoError",
        1 => "FormErr",
        2 => "ServFail",
        3 => "NXDomain",
        4 => "NotImp",
        5 => "Refused",
        _ => "UnknownError",
    }
}

pub fn parse_domain_name(data: &[u8], mut offset: usize) -> Result<(String, usize), String> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut next_offset = offset;
    let mut jump_count = 0;
    const MAX_JUMPS: usize = 30;

    loop {
        if offset >= data.len() {
            return Err("DNS name pointer out of bounds".to_string());
        }

        let len = data[offset] as usize;
        if len == 0 {
            if !jumped {
                next_offset = offset + 1;
            }
            break;
        }

        if (len & 0xC0) == 0xC0 {
            // Compression pointer
            if offset + 1 >= data.len() {
                return Err("DNS compression pointer truncated".to_string());
            }
            let ptr = ((len & 0x3F) << 8) | (data[offset + 1] as usize);
            if !jumped {
                next_offset = offset + 2;
                jumped = true;
            }
            jump_count += 1;
            if jump_count > MAX_JUMPS {
                return Err("DNS compression loop detected".to_string());
            }
            offset = ptr;
        } else {
            // Label literal
            offset += 1;
            if offset + len > data.len() {
                return Err("DNS label extends beyond packet".to_string());
            }
            let label_str = String::from_utf8_lossy(&data[offset..offset + len]).into_owned();
            labels.push(label_str);
            offset += len;
            if !jumped {
                next_offset = offset;
            }
        }
    }

    let name = if labels.is_empty() {
        ".".to_string()
    } else {
        labels.join(".")
    };

    Ok((name, next_offset))
}

pub fn parse_dns(
    data: &[u8],
    packet_index: u64,
    timestamp_ns: Option<u128>,
    timestamp_iso: &str,
    src_ip: &str,
    dst_ip: &str,
) -> Result<(DnsRecord, ProtocolLayer), String> {
    if data.len() < 12 {
        return Err(format!(
            "DNS packet too short: {} bytes (minimum 12)",
            data.len()
        ));
    }

    let tx_id = u16::from_be_bytes([data[0], data[1]]);
    let flags = u16::from_be_bytes([data[2], data[3]]);
    let qd_count = u16::from_be_bytes([data[4], data[5]]) as usize;
    let an_count = u16::from_be_bytes([data[6], data[7]]) as usize;
    let _ns_count = u16::from_be_bytes([data[8], data[9]]) as usize;
    let _ar_count = u16::from_be_bytes([data[10], data[11]]) as usize;

    let is_response = (flags & 0x8000) != 0;
    let opcode = ((flags >> 11) & 0x0F) as u8;
    let rcode = (flags & 0x000F) as u8;
    let rcode_name = rcode_to_name(rcode).to_string();

    let mut questions = Vec::new();
    let mut offset = 12;

    for _ in 0..qd_count.min(50) {
        if offset >= data.len() {
            break;
        }
        if let Ok((name, new_offset)) = parse_domain_name(data, offset) {
            offset = new_offset;
            if offset + 4 <= data.len() {
                let qtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
                let qclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
                offset += 4;
                questions.push(DnsQuestion {
                    name,
                    qtype,
                    qtype_name: type_to_name(qtype).to_string(),
                    qclass,
                });
            }
        } else {
            break;
        }
    }

    let mut answers = Vec::new();
    if is_response {
        for _ in 0..an_count.min(50) {
            if offset >= data.len() {
                break;
            }
            if let Ok((name, new_offset)) = parse_domain_name(data, offset) {
                offset = new_offset;
                if offset + 10 <= data.len() {
                    let rtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
                    let _rclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
                    let ttl = u32::from_be_bytes([
                        data[offset + 4],
                        data[offset + 5],
                        data[offset + 6],
                        data[offset + 7],
                    ]);
                    let rdlen = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;
                    offset += 10;

                    let mut rdata_str = String::new();
                    if offset + rdlen <= data.len() {
                        let rdata = &data[offset..offset + rdlen];
                        if rtype == 1 && rdlen == 4 {
                            rdata_str =
                                format!("{}.{}.{}.{}", rdata[0], rdata[1], rdata[2], rdata[3]);
                        } else if rtype == 28 && rdlen == 16 {
                            rdata_str = super::ipv6::format_ipv6(rdata);
                        } else if rtype == 5 || rtype == 12 || rtype == 2 {
                            if let Ok((target_name, _)) = parse_domain_name(data, offset) {
                                rdata_str = target_name;
                            }
                        } else {
                            rdata_str = format!("{} bytes data", rdlen);
                        }
                        offset += rdlen;
                    }

                    answers.push(DnsAnswer {
                        name,
                        rtype,
                        rtype_name: type_to_name(rtype).to_string(),
                        ttl,
                        data: rdata_str,
                    });
                }
            } else {
                break;
            }
        }
    }

    let primary_query = questions
        .first()
        .map(|q| q.name.clone())
        .unwrap_or_else(|| "<no query>".to_string());
    let primary_query_type = questions
        .first()
        .map(|q| q.qtype_name.clone())
        .unwrap_or_else(|| "ANY".to_string());

    let info = if is_response {
        if rcode == 0 {
            let ans_preview = answers
                .iter()
                .map(|a| a.data.as_str())
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join(", ");
            format!(
                "Standard query response 0x{:04x} {} {}",
                tx_id, primary_query, ans_preview
            )
        } else {
            format!(
                "Standard query response 0x{:04x} {} Error: {}",
                tx_id, primary_query, rcode_name
            )
        }
    } else {
        format!(
            "Standard query 0x{:04x} {} {}",
            tx_id, primary_query_type, primary_query
        )
    };

    let mut fields = vec![
        LayerField::with_hex(
            "Transaction ID",
            format!("0x{:04x}", tx_id),
            format!("0x{:04x}", tx_id),
        ),
        LayerField::new(
            "Type",
            if is_response {
                "Response (1)"
            } else {
                "Query (0)"
            },
        ),
        LayerField::new("Opcode", opcode.to_string()),
        LayerField::new("Response Code", format!("{} ({})", rcode_name, rcode)),
        LayerField::new("Questions Count", qd_count.to_string()),
        LayerField::new("Answers Count", an_count.to_string()),
    ];

    for q in &questions {
        fields.push(LayerField::new(
            "Query",
            format!("{} ({})", q.name, q.qtype_name),
        ));
    }
    for a in &answers {
        fields.push(LayerField::new(
            "Answer",
            format!("{} -> {} (TTL={})", a.name, a.data, a.ttl),
        ));
    }

    let layer = ProtocolLayer {
        name: "Domain Name System".to_string(),
        description: info.clone(),
        fields,
    };

    Ok((
        DnsRecord {
            packet_index,
            timestamp_ns,
            timestamp_iso: timestamp_iso.to_string(),
            source_ip: src_ip.to_string(),
            destination_ip: dst_ip.to_string(),
            transaction_id: tx_id,
            is_response,
            opcode,
            rcode,
            rcode_name,
            questions,
            answers,
            primary_query,
            primary_query_type,
            latency_ms: None,
        },
        layer,
    ))
}
