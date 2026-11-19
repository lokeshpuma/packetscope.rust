use crate::packet::PacketRecord;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProtocolStat {
    pub name: String,
    pub packet_count: u64,
    pub byte_count: u64,
    pub percentage_packets: f64,
    pub percentage_bytes: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PortStat {
    pub port: u16,
    pub service_label: String,
    pub packet_count: u64,
    pub byte_count: u64,
    pub as_source_count: u64,
    pub as_destination_count: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CaptureSummary {
    pub filename: String,
    pub file_size_bytes: u64,
    pub format_name: String,
    pub packet_count: u64,
    pub total_bytes: u64,
    pub start_time_iso: String,
    pub end_time_iso: String,
    pub duration_seconds: f64,
    pub link_type_name: String,
    pub interface_count: usize,
    pub timestamp_precision: String,
    pub malformed_packet_count: u64,
    pub truncated_packet_count: u64,
    pub unsupported_packet_count: u64,
    pub host_count: usize,
    pub flow_count: usize,
    pub dns_query_count: usize,
}

pub fn common_port_service(port: u16) -> &'static str {
    match port {
        20 | 21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        67 | 68 => "DHCP",
        80 => "HTTP",
        110 => "POP3",
        123 => "NTP",
        143 => "IMAP",
        161 | 162 => "SNMP",
        389 => "LDAP",
        443 => "HTTPS",
        445 => "SMB",
        514 => "Syslog",
        636 => "LDAPS",
        993 => "IMAPS",
        995 => "POP3S",
        1433 => "MSSQL",
        1521 => "Oracle",
        3306 => "MySQL",
        3389 => "RDP",
        5432 => "PostgreSQL",
        6379 => "Redis",
        8080 => "HTTP-Proxy",
        8443 => "HTTPS-Alt",
        9092 => "Kafka",
        _ => "Unknown",
    }
}

pub struct StatisticsCalculator {
    proto_packets: HashMap<String, u64>,
    proto_bytes: HashMap<String, u64>,
    port_stats: HashMap<u16, (u64, u64, u64, u64)>, // (packets, bytes, as_src, as_dst)
    total_packets: u64,
    total_bytes: u64,
    truncated_count: u64,
}

impl StatisticsCalculator {
    pub fn new() -> Self {
        Self {
            proto_packets: HashMap::new(),
            proto_bytes: HashMap::new(),
            port_stats: HashMap::new(),
            total_packets: 0,
            total_bytes: 0,
            truncated_count: 0,
        }
    }

    pub fn process_packet(&mut self, pkt: &PacketRecord) {
        self.total_packets += 1;
        let bytes = pkt.captured_length as u64;
        self.total_bytes += bytes;

        if pkt.truncated {
            self.truncated_count += 1;
        }

        let proto = pkt.protocol_display();
        *self.proto_packets.entry(proto.clone()).or_insert(0) += 1;
        *self.proto_bytes.entry(proto).or_insert(0) += bytes;

        if let Some(sp) = pkt.source_port {
            let entry = self.port_stats.entry(sp).or_insert((0, 0, 0, 0));
            entry.0 += 1;
            entry.1 += bytes;
            entry.2 += 1;
        }

        if let Some(dp) = pkt.destination_port {
            let entry = self.port_stats.entry(dp).or_insert((0, 0, 0, 0));
            entry.0 += 1;
            entry.1 += bytes;
            entry.3 += 1;
        }
    }

    pub fn finalize_protocols(&self) -> Vec<ProtocolStat> {
        let mut list: Vec<ProtocolStat> = self
            .proto_packets
            .iter()
            .map(|(name, &count)| {
                let bytes = *self.proto_bytes.get(name).unwrap_or(&0);
                let pct_pkts = if self.total_packets > 0 {
                    (count as f64 / self.total_packets as f64) * 100.0
                } else {
                    0.0
                };
                let pct_bytes = if self.total_bytes > 0 {
                    (bytes as f64 / self.total_bytes as f64) * 100.0
                } else {
                    0.0
                };
                ProtocolStat {
                    name: name.clone(),
                    packet_count: count,
                    byte_count: bytes,
                    percentage_packets: pct_pkts,
                    percentage_bytes: pct_bytes,
                }
            })
            .collect();

        list.sort_by_key(|a| std::cmp::Reverse(a.byte_count));
        list
    }

    pub fn finalize_ports(&self) -> Vec<PortStat> {
        let mut list: Vec<PortStat> = self
            .port_stats
            .iter()
            .map(|(&port, &(pkts, bytes, src, dst))| PortStat {
                port,
                service_label: common_port_service(port).to_string(),
                packet_count: pkts,
                byte_count: bytes,
                as_source_count: src,
                as_destination_count: dst,
            })
            .collect();

        list.sort_by_key(|a| std::cmp::Reverse(a.packet_count));
        list
    }

    pub fn truncated_count(&self) -> u64 {
        self.truncated_count
    }
}

impl Default for StatisticsCalculator {
    fn default() -> Self {
        Self::new()
    }
}
