use super::model::{Finding, FindingSeverity, ReviewStatus};
use crate::flow::NetworkFlow;
use crate::host::HostRecord;
use crate::packet::PacketRecord;
use crate::protocols::dns::DnsRecord;
use crate::timeline::TimelineAnalysis;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuleConfig {
    pub burst_baseline_multiplier: f64,
    pub fanout_threshold: usize,
    pub repeated_syn_threshold: u32,
    pub rst_ratio_threshold: f64,
    pub dns_error_ratio_threshold: f64,
    pub unusual_port_traffic_share: f64,
}

impl Default for RuleConfig {
    fn default() -> Self {
        Self {
            burst_baseline_multiplier: 3.0,
            fanout_threshold: 8,
            repeated_syn_threshold: 4,
            rst_ratio_threshold: 0.15,
            dns_error_ratio_threshold: 0.20,
            unusual_port_traffic_share: 0.35,
        }
    }
}

pub fn evaluate_findings(
    packets: &[PacketRecord],
    flows: &[NetworkFlow],
    hosts: &[HostRecord],
    dns_records: &[DnsRecord],
    timeline: &TimelineAnalysis,
    config: &RuleConfig,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut id_counter = 1;

    // Rule 1: High Traffic Burst
    if timeline.buckets.len() >= 3 {
        let total_packets: u32 = timeline.buckets.iter().map(|b| b.packet_count).sum();
        let avg_pps = (total_packets as f64)
            / (timeline.buckets.len() as f64 * timeline.bucket_resolution_seconds);

        for bucket in &timeline.buckets {
            if avg_pps > 1.0
                && (bucket.packets_per_second >= avg_pps * config.burst_baseline_multiplier)
            {
                findings.push(Finding {
                    id: format!("FIND-{:04}", id_counter),
                    title: "High Traffic Burst Detected".to_string(),
                    severity: FindingSeverity::Medium,
                    category: "Traffic Anomalies".to_string(),
                    affected_host: None,
                    first_seen_iso: bucket.timestamp_iso.clone(),
                    last_seen_iso: bucket.timestamp_iso.clone(),
                    status: ReviewStatus::New,
                    rule_name: "Rule 1: High Traffic Burst".to_string(),
                    configured_threshold: format!(">= {:.1}x baseline ({:.1} pps)", config.burst_baseline_multiplier, avg_pps * config.burst_baseline_multiplier),
                    observed_value: format!("{:.1} pps ({} packets in {:.1}s bucket)", bucket.packets_per_second, bucket.packet_count, timeline.bucket_resolution_seconds),
                    what_happened: format!("Traffic volume surged to {:.1} packets/sec, which significantly exceeds the baseline rate of {:.1} packets/sec.", bucket.packets_per_second, avg_pps),
                    why_flagged: "Sudden sharp surges in packet rate can indicate bulk transfers, scanning activity, or network load spikes.".to_string(),
                    affected_conversations: Vec::new(),
                    related_packets: Vec::new(),
                    investigation_steps: vec![
                        "Review packets captured during this time window.".to_string(),
                        "Check which protocol and host pairs contributed the majority of the burst traffic.".to_string(),
                        "Verify whether this traffic corresponds to expected application data transfer.".to_string(),
                    ],
                    notes: String::new(),
                });
                id_counter += 1;
                break; // One burst finding is sufficient to highlight the peak
            }
        }
    }

    // Rule 2: High Destination Fan-Out
    for host in hosts {
        if host.peer_count >= config.fanout_threshold {
            findings.push(Finding {
                id: format!("FIND-{:04}", id_counter),
                title: format!("High Destination Fan-Out from {}", host.ip),
                severity: FindingSeverity::High,
                category: "Host Behaviour".to_string(),
                affected_host: Some(host.ip.clone()),
                first_seen_iso: host.first_seen_iso.clone(),
                last_seen_iso: host.last_seen_iso.clone(),
                status: ReviewStatus::New,
                rule_name: "Rule 2: High Destination Fan-Out".to_string(),
                configured_threshold: format!(">= {} unique destinations", config.fanout_threshold),
                observed_value: format!("{} unique peers", host.peer_count),
                what_happened: format!("Host {} communicated with {} distinct IP destinations across the capture.", host.ip, host.peer_count),
                why_flagged: "A single host communicating with many destinations in a short window is characteristic of port scanning, host discovery, or service enumeration.".to_string(),
                affected_conversations: host.unique_peers.iter().take(5).map(|p| format!("{} ↔ {}", host.ip, p)).collect(),
                related_packets: Vec::new(),
                investigation_steps: vec![
                    "Inspect the destination ports accessed across these peers.".to_string(),
                    "Check if the attempts received valid responses or remained unanswered.".to_string(),
                    "Determine if this device functions as a legitimate gateway, proxy, or monitoring scanner.".to_string(),
                ],
                notes: String::new(),
            });
            id_counter += 1;
        }
    }

    // Rule 3: Repeated TCP Connection Attempts
    for flow in flows {
        if flow.protocol == "TCP"
            && flow.syn_count >= config.repeated_syn_threshold
            && flow.syn_ack_count == 0
        {
            findings.push(Finding {
                id: format!("FIND-{:04}", id_counter),
                title: format!("Repeated Unanswered SYN Attempts to {}:{}", flow.endpoint_b, flow.port_b),
                severity: FindingSeverity::Medium,
                category: "Connection Health".to_string(),
                affected_host: Some(flow.endpoint_a.clone()),
                first_seen_iso: flow.start_time_iso.clone(),
                last_seen_iso: flow.end_time_iso.clone(),
                status: ReviewStatus::New,
                rule_name: "Rule 3: Repeated TCP Connection Attempts".to_string(),
                configured_threshold: format!(">= {} SYN packets without SYN-ACK", config.repeated_syn_threshold),
                observed_value: format!("{} SYN attempts, 0 SYN-ACK received", flow.syn_count),
                what_happened: format!("Host {} sent {} SYN packets to {}:{} with no observed handshake completion.", flow.endpoint_a, flow.syn_count, flow.endpoint_b, flow.port_b),
                why_flagged: "Repeated connection attempts without response suggest service unavailability, firewall dropping, or SYN probe scanning.".to_string(),
                affected_conversations: vec![flow.id.clone()],
                related_packets: vec![flow.first_packet_index, flow.last_packet_index],
                investigation_steps: vec![
                    "Verify if target service was offline or firewall was filtering port.".to_string(),
                    "Check for ICMP 'Host / Port Unreachable' responses from intervening routers.".to_string(),
                    "Confirm if this host was testing connectivity or scanning.".to_string(),
                ],
                notes: String::new(),
            });
            id_counter += 1;
        }
    }

    // Rule 4: High TCP Reset Ratio
    let tcp_packets = packets
        .iter()
        .filter(|p| p.transport_protocol.as_deref() == Some("TCP"))
        .count();
    let rst_packets = packets
        .iter()
        .filter(|p| p.tcp_flags.map(|f| f.rst).unwrap_or(false))
        .count();
    if tcp_packets >= 10 {
        let rst_ratio = rst_packets as f64 / tcp_packets as f64;
        if rst_ratio >= config.rst_ratio_threshold {
            findings.push(Finding {
                id: format!("FIND-{:04}", id_counter),
                title: "High TCP Reset (RST) Ratio".to_string(),
                severity: FindingSeverity::Medium,
                category: "Connection Health".to_string(),
                affected_host: None,
                first_seen_iso: packets.first().map(|p| p.timestamp_iso.clone()).unwrap_or_default(),
                last_seen_iso: packets.last().map(|p| p.timestamp_iso.clone()).unwrap_or_default(),
                status: ReviewStatus::New,
                rule_name: "Rule 4: High TCP Reset Ratio".to_string(),
                configured_threshold: format!(">= {:.0}% RST packets", config.rst_ratio_threshold * 100.0),
                observed_value: format!("{:.1}% ({} RST out of {} TCP packets)", rst_ratio * 100.0, rst_packets, tcp_packets),
                what_happened: format!("An unusually high proportion ({:.1}%) of observed TCP traffic consists of connection resets (RST).", rst_ratio * 100.0),
                why_flagged: "Frequent connection aborts or rejected connections typically indicate port refusal, closed services, or network middlebox teardown.".to_string(),
                affected_conversations: flows.iter().filter(|f| f.rst_count > 0).take(3).map(|f| f.id.clone()).collect(),
                related_packets: Vec::new(),
                investigation_steps: vec![
                    "Review which destinations are returning RST packets.".to_string(),
                    "Check whether ports contacted are actively listening.".to_string(),
                    "Examine middlebox or firewall policies that actively reject unauthorized connections.".to_string(),
                ],
                notes: String::new(),
            });
            id_counter += 1;
        }
    }

    // Rule 5: DNS Error Spike
    if !dns_records.is_empty() {
        let total_dns = dns_records.len();
        let error_dns = dns_records
            .iter()
            .filter(|d| d.is_response && d.rcode != 0)
            .count();
        if total_dns >= 5 {
            let error_ratio = error_dns as f64 / total_dns as f64;
            if error_ratio >= config.dns_error_ratio_threshold {
                findings.push(Finding {
                    id: format!("FIND-{:04}", id_counter),
                    title: "Elevated DNS Error / NXDOMAIN Rate".to_string(),
                    severity: FindingSeverity::Low,
                    category: "DNS Analytics".to_string(),
                    affected_host: None,
                    first_seen_iso: dns_records.first().map(|d| d.timestamp_iso.clone()).unwrap_or_default(),
                    last_seen_iso: dns_records.last().map(|d| d.timestamp_iso.clone()).unwrap_or_default(),
                    status: ReviewStatus::New,
                    rule_name: "Rule 5: DNS Error Spike".to_string(),
                    configured_threshold: format!(">= {:.0}% DNS errors", config.dns_error_ratio_threshold * 100.0),
                    observed_value: format!("{:.1}% ({} errors out of {} DNS messages)", error_ratio * 100.0, error_dns, total_dns),
                    what_happened: "Multiple DNS queries resulted in non-zero response codes (NXDomain / ServFail / FormErr).".to_string(),
                    why_flagged: "High rates of NXDOMAIN responses can occur from typo squatting, domain generation algorithms (DGA), or misconfigured service endpoints.".to_string(),
                    affected_conversations: Vec::new(),
                    related_packets: dns_records.iter().filter(|d| d.is_response && d.rcode != 0).take(5).map(|d| d.packet_index).collect(),
                    investigation_steps: vec![
                        "Inspect the queried domain names that returned NXDomain.".to_string(),
                        "Identify the requesting source hosts.".to_string(),
                        "Check for patterns or automated querying in DNS timeline.".to_string(),
                    ],
                    notes: String::new(),
                });
                id_counter += 1;
            }
        }
    }

    // Rule 6: Unusual Port Concentration
    for host in hosts {
        if host.total_bytes > 5000 {
            for &port in &host.destination_ports {
                // Ignore standard ports 80, 443, 53, 22
                if port != 80 && port != 443 && port != 53 && port != 22 && port > 1024 {
                    // Check if this port represents a major share of host flows
                    let port_flows: Vec<&NetworkFlow> = flows
                        .iter()
                        .filter(|f| {
                            (f.endpoint_a == host.ip || f.endpoint_b == host.ip)
                                && (f.port_a == port || f.port_b == port)
                        })
                        .collect();
                    let port_bytes: u64 = port_flows.iter().map(|f| f.total_bytes).sum();
                    let share = port_bytes as f64 / host.total_bytes as f64;

                    if share >= config.unusual_port_traffic_share {
                        findings.push(Finding {
                            id: format!("FIND-{:04}", id_counter),
                            title: format!("High Traffic Concentration on Non-Standard Port {}", port),
                            severity: FindingSeverity::Low,
                            category: "Port Usage".to_string(),
                            affected_host: Some(host.ip.clone()),
                            first_seen_iso: host.first_seen_iso.clone(),
                            last_seen_iso: host.last_seen_iso.clone(),
                            status: ReviewStatus::New,
                            rule_name: "Rule 6: Unusual Port Concentration".to_string(),
                            configured_threshold: format!(">= {:.0}% host traffic", config.unusual_port_traffic_share * 100.0),
                            observed_value: format!("{:.1}% ({:.1} KB on port {})", share * 100.0, port_bytes as f64 / 1024.0, port),
                            what_happened: format!("Host {} directed {:.1}% of its observed byte volume to non-standard port {}.", host.ip, share * 100.0, port),
                            why_flagged: "Heavy utilization of custom, high, or non-standard ports warrants review to identify custom services or unmanaged data transfers.".to_string(),
                            affected_conversations: port_flows.iter().take(3).map(|f| f.id.clone()).collect(),
                            related_packets: Vec::new(),
                            investigation_steps: vec![
                                "Verify what service or custom application listens on this port.".to_string(),
                                "Review the payload or protocol headers for this traffic.".to_string(),
                                "Confirm whether this communication aligns with organizational policy.".to_string(),
                            ],
                            notes: String::new(),
                        });
                        id_counter += 1;
                        break;
                    }
                }
            }
        }
    }

    findings
}
