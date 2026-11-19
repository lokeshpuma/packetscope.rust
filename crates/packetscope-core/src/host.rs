use crate::packet::PacketRecord;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HostRecord {
    pub ip: String,
    pub mac: Option<String>,
    pub address_family: String,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub total_bytes: u64,
    pub unique_peers: Vec<String>,
    pub peer_count: usize,
    pub observed_protocols: Vec<String>,
    pub source_ports: Vec<u16>,
    pub destination_ports: Vec<u16>,
    pub associated_dns_names: Vec<String>,
    pub first_seen_iso: String,
    pub last_seen_iso: String,
    pub first_seen_ns: u128,
    pub last_seen_ns: u128,
}

struct HostAccumulator {
    ip: String,
    mac: Option<String>,
    address_family: String,
    packets_sent: u64,
    packets_received: u64,
    bytes_sent: u64,
    bytes_received: u64,
    peers: HashSet<String>,
    protocols: HashSet<String>,
    source_ports: HashSet<u16>,
    destination_ports: HashSet<u16>,
    dns_names: HashSet<String>,
    first_seen_iso: String,
    last_seen_iso: String,
    first_seen_ns: u128,
    last_seen_ns: u128,
}

#[derive(Default)]
pub struct HostAggregator {
    hosts: HashMap<String, HostAccumulator>,
}

impl HostAggregator {
    pub fn new() -> Self {
        Self {
            hosts: HashMap::new(),
        }
    }

    pub fn process_packet(&mut self, pkt: &PacketRecord) {
        let ts_ns = pkt.timestamp_ns.unwrap_or(0);
        let bytes = pkt.captured_length as u64;
        let proto = pkt.protocol_display();

        // Process Source Host
        if let Some(ref src_ip) = pkt.source_ip {
            let is_v6 = src_ip.contains(':');
            let family = if is_v6 { "IPv6" } else { "IPv4" };

            let host = self
                .hosts
                .entry(src_ip.clone())
                .or_insert_with(|| HostAccumulator {
                    ip: src_ip.clone(),
                    mac: pkt.source_mac.clone(),
                    address_family: family.to_string(),
                    packets_sent: 0,
                    packets_received: 0,
                    bytes_sent: 0,
                    bytes_received: 0,
                    peers: HashSet::new(),
                    protocols: HashSet::new(),
                    source_ports: HashSet::new(),
                    destination_ports: HashSet::new(),
                    dns_names: HashSet::new(),
                    first_seen_iso: pkt.timestamp_iso.clone(),
                    last_seen_iso: pkt.timestamp_iso.clone(),
                    first_seen_ns: ts_ns,
                    last_seen_ns: ts_ns,
                });

            host.packets_sent += 1;
            host.bytes_sent += bytes;
            if host.mac.is_none() && pkt.source_mac.is_some() {
                host.mac = pkt.source_mac.clone();
            }
            if let Some(ref dst_ip) = pkt.destination_ip {
                host.peers.insert(dst_ip.clone());
            }
            host.protocols.insert(proto.clone());
            if let Some(sp) = pkt.source_port {
                host.source_ports.insert(sp);
            }
            if ts_ns < host.first_seen_ns || host.first_seen_ns == 0 {
                host.first_seen_ns = ts_ns;
                host.first_seen_iso = pkt.timestamp_iso.clone();
            }
            if ts_ns > host.last_seen_ns {
                host.last_seen_ns = ts_ns;
                host.last_seen_iso = pkt.timestamp_iso.clone();
            }
        }

        // Process Destination Host
        if let Some(ref dst_ip) = pkt.destination_ip {
            let is_v6 = dst_ip.contains(':');
            let family = if is_v6 { "IPv6" } else { "IPv4" };

            let host = self
                .hosts
                .entry(dst_ip.clone())
                .or_insert_with(|| HostAccumulator {
                    ip: dst_ip.clone(),
                    mac: pkt.destination_mac.clone(),
                    address_family: family.to_string(),
                    packets_sent: 0,
                    packets_received: 0,
                    bytes_sent: 0,
                    bytes_received: 0,
                    peers: HashSet::new(),
                    protocols: HashSet::new(),
                    source_ports: HashSet::new(),
                    destination_ports: HashSet::new(),
                    dns_names: HashSet::new(),
                    first_seen_iso: pkt.timestamp_iso.clone(),
                    last_seen_iso: pkt.timestamp_iso.clone(),
                    first_seen_ns: ts_ns,
                    last_seen_ns: ts_ns,
                });

            host.packets_received += 1;
            host.bytes_received += bytes;
            if host.mac.is_none() && pkt.destination_mac.is_some() {
                host.mac = pkt.destination_mac.clone();
            }
            if let Some(ref src_ip) = pkt.source_ip {
                host.peers.insert(src_ip.clone());
            }
            host.protocols.insert(proto.clone());
            if let Some(dp) = pkt.destination_port {
                host.destination_ports.insert(dp);
            }
            if ts_ns < host.first_seen_ns || host.first_seen_ns == 0 {
                host.first_seen_ns = ts_ns;
                host.first_seen_iso = pkt.timestamp_iso.clone();
            }
            if ts_ns > host.last_seen_ns {
                host.last_seen_ns = ts_ns;
                host.last_seen_iso = pkt.timestamp_iso.clone();
            }
        }
    }

    pub fn add_dns_association(&mut self, ip: &str, domain: &str) {
        if let Some(host) = self.hosts.get_mut(ip) {
            host.dns_names.insert(domain.to_string());
        }
    }

    pub fn finalize(self) -> Vec<HostRecord> {
        let mut list: Vec<HostRecord> = self
            .hosts
            .into_values()
            .map(|acc| {
                let total_bytes = acc.bytes_sent + acc.bytes_received;
                let mut unique_peers: Vec<String> = acc.peers.into_iter().collect();
                unique_peers.sort();
                let peer_count = unique_peers.len();

                let mut observed_protocols: Vec<String> = acc.protocols.into_iter().collect();
                observed_protocols.sort();

                let mut source_ports: Vec<u16> = acc.source_ports.into_iter().collect();
                source_ports.sort();

                let mut destination_ports: Vec<u16> = acc.destination_ports.into_iter().collect();
                destination_ports.sort();

                let mut associated_dns_names: Vec<String> = acc.dns_names.into_iter().collect();
                associated_dns_names.sort();

                HostRecord {
                    ip: acc.ip,
                    mac: acc.mac,
                    address_family: acc.address_family,
                    packets_sent: acc.packets_sent,
                    packets_received: acc.packets_received,
                    bytes_sent: acc.bytes_sent,
                    bytes_received: acc.bytes_received,
                    total_bytes,
                    unique_peers,
                    peer_count,
                    observed_protocols,
                    source_ports,
                    destination_ports,
                    associated_dns_names,
                    first_seen_iso: acc.first_seen_iso,
                    last_seen_iso: acc.last_seen_iso,
                    first_seen_ns: acc.first_seen_ns,
                    last_seen_ns: acc.last_seen_ns,
                }
            })
            .collect();

        // Sort by total bytes descending
        list.sort_by_key(|a| std::cmp::Reverse(a.total_bytes));
        list
    }
}
