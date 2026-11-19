use crate::packet::PacketRecord;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FlowKey {
    pub protocol: String,
    pub endpoint_a: String,
    pub port_a: u16,
    pub endpoint_b: String,
    pub port_b: u16,
}

impl FlowKey {
    pub fn new(
        protocol: &str,
        src_ip: &str,
        src_port: u16,
        dst_ip: &str,
        dst_port: u16,
    ) -> (Self, bool) {
        let ep_src = (src_ip, src_port);
        let ep_dst = (dst_ip, dst_port);

        if ep_src <= ep_dst {
            (
                FlowKey {
                    protocol: protocol.to_string(),
                    endpoint_a: src_ip.to_string(),
                    port_a: src_port,
                    endpoint_b: dst_ip.to_string(),
                    port_b: dst_port,
                },
                true, // forward direction
            )
        } else {
            (
                FlowKey {
                    protocol: protocol.to_string(),
                    endpoint_a: dst_ip.to_string(),
                    port_a: dst_port,
                    endpoint_b: src_ip.to_string(),
                    port_b: src_port,
                },
                false, // reverse direction
            )
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetworkFlow {
    pub id: String,
    pub protocol: String,
    pub endpoint_a: String,
    pub port_a: u16,
    pub endpoint_b: String,
    pub port_b: u16,

    pub start_time_ns: u128,
    pub end_time_ns: u128,
    pub start_time_iso: String,
    pub end_time_iso: String,
    pub duration_seconds: f64,

    pub packet_count: u64,
    pub total_bytes: u64,
    pub forward_packets: u64,
    pub reverse_packets: u64,
    pub forward_bytes: u64,
    pub reverse_bytes: u64,

    pub first_packet_index: u64,
    pub last_packet_index: u64,

    pub syn_count: u32,
    pub syn_ack_count: u32,
    pub ack_count: u32,
    pub rst_count: u32,
    pub fin_count: u32,
    pub handshake_summary: String,

    pub dns_names: Vec<String>,
}

#[derive(Default)]
pub struct FlowAggregator {
    flows: HashMap<FlowKey, NetworkFlow>,
}

impl FlowAggregator {
    pub fn new() -> Self {
        Self {
            flows: HashMap::new(),
        }
    }

    pub fn process_packet(&mut self, pkt: &PacketRecord) {
        let (src_ip, dst_ip) = match (&pkt.source_ip, &pkt.destination_ip) {
            (Some(s), Some(d)) => (s.as_str(), d.as_str()),
            _ => return,
        };

        let protocol = pkt
            .transport_protocol
            .as_deref()
            .unwrap_or(&pkt.network_protocol);
        let src_port = pkt.source_port.unwrap_or(0);
        let dst_port = pkt.destination_port.unwrap_or(0);

        let (key, is_forward) = FlowKey::new(protocol, src_ip, src_port, dst_ip, dst_port);
        let ts_ns = pkt.timestamp_ns.unwrap_or(0);
        let bytes = pkt.captured_length as u64;

        let flow = self.flows.entry(key.clone()).or_insert_with(|| {
            let id = format!(
                "{}_{}_{}_{}_{}",
                key.protocol.to_lowercase(),
                key.endpoint_a.replace(['.', ':'], "-"),
                key.port_a,
                key.endpoint_b.replace(['.', ':'], "-"),
                key.port_b
            );

            NetworkFlow {
                id,
                protocol: key.protocol.clone(),
                endpoint_a: key.endpoint_a.clone(),
                port_a: key.port_a,
                endpoint_b: key.endpoint_b.clone(),
                port_b: key.port_b,
                start_time_ns: ts_ns,
                end_time_ns: ts_ns,
                start_time_iso: pkt.timestamp_iso.clone(),
                end_time_iso: pkt.timestamp_iso.clone(),
                duration_seconds: 0.0,
                packet_count: 0,
                total_bytes: 0,
                forward_packets: 0,
                reverse_packets: 0,
                forward_bytes: 0,
                reverse_bytes: 0,
                first_packet_index: pkt.index,
                last_packet_index: pkt.index,
                syn_count: 0,
                syn_ack_count: 0,
                ack_count: 0,
                rst_count: 0,
                fin_count: 0,
                handshake_summary: String::new(),
                dns_names: Vec::new(),
            }
        });

        flow.packet_count += 1;
        flow.total_bytes += bytes;
        flow.last_packet_index = pkt.index;

        if is_forward {
            flow.forward_packets += 1;
            flow.forward_bytes += bytes;
        } else {
            flow.reverse_packets += 1;
            flow.reverse_bytes += bytes;
        }

        if ts_ns < flow.start_time_ns || flow.start_time_ns == 0 {
            flow.start_time_ns = ts_ns;
            flow.start_time_iso = pkt.timestamp_iso.clone();
        }
        if ts_ns > flow.end_time_ns {
            flow.end_time_ns = ts_ns;
            flow.end_time_iso = pkt.timestamp_iso.clone();
        }

        if flow.end_time_ns >= flow.start_time_ns {
            flow.duration_seconds =
                (flow.end_time_ns - flow.start_time_ns) as f64 / 1_000_000_000.0;
        }

        // Track TCP flags
        if let Some(flags) = pkt.tcp_flags {
            if flags.syn && !flags.ack {
                flow.syn_count += 1;
            } else if flags.syn && flags.ack {
                flow.syn_ack_count += 1;
            } else if flags.ack {
                flow.ack_count += 1;
            }
            if flags.rst {
                flow.rst_count += 1;
            }
            if flags.fin {
                flow.fin_count += 1;
            }
        }
    }

    pub fn finalize(self) -> Vec<NetworkFlow> {
        let mut result: Vec<NetworkFlow> = self.flows.into_values().collect();

        for flow in &mut result {
            if flow.protocol == "TCP" {
                if flow.syn_count > 0 && flow.syn_ack_count > 0 && flow.ack_count > 0 {
                    flow.handshake_summary = "Completed (SYN → SYN-ACK → ACK)".to_string();
                } else if flow.rst_count > 0 {
                    flow.handshake_summary = "Reset (RST observed)".to_string();
                } else if flow.syn_count > 0 && flow.syn_ack_count == 0 {
                    flow.handshake_summary = "Unanswered SYN (No response observed)".to_string();
                } else {
                    flow.handshake_summary =
                        "Handshake not fully observed in this capture.".to_string();
                }
            } else {
                flow.handshake_summary = "N/A (Connectionless)".to_string();
            }
        }

        // Sort by total bytes descending
        result.sort_by_key(|a| std::cmp::Reverse(a.total_bytes));
        result
    }
}
