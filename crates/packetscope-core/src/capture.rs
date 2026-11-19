use chrono::DateTime;
use pcap_parser::*;
use serde::{Deserialize, Serialize};
use std::io::Cursor;

use crate::errors::CaptureError;
use crate::export::AnalysisReport;
use crate::findings::{evaluate_findings, Finding, RuleConfig};
use crate::flow::{FlowAggregator, NetworkFlow};
use crate::format::{detect_format, CaptureFormat};
use crate::host::{HostAggregator, HostRecord};
use crate::packet::PacketRecord;
use crate::protocols::dissect_packet;
use crate::protocols::dns::DnsRecord;
use crate::statistics::{CaptureSummary, PortStat, ProtocolStat, StatisticsCalculator};
use crate::timeline::{TimelineAggregator, TimelineAnalysis};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CaptureResult {
    pub summary: CaptureSummary,
    pub packets: Vec<PacketRecord>,
    pub flows: Vec<NetworkFlow>,
    pub hosts: Vec<HostRecord>,
    pub protocols: Vec<ProtocolStat>,
    pub ports: Vec<PortStat>,
    pub dns_records: Vec<DnsRecord>,
    pub timeline: TimelineAnalysis,
    pub findings: Vec<Finding>,
    pub limitations: Vec<String>,
    pub warnings: Vec<String>,
}

impl CaptureResult {
    pub fn to_analysis_report(&self) -> AnalysisReport {
        AnalysisReport {
            summary: self.summary.clone(),
            protocols: self.protocols.clone(),
            top_hosts: self.hosts.iter().take(10).cloned().collect(),
            top_flows: self.flows.iter().take(10).cloned().collect(),
            findings: self.findings.clone(),
            limitations: self.limitations.clone(),
        }
    }
}

pub fn format_timestamp(ns: u128) -> String {
    let secs = (ns / 1_000_000_000) as i64;
    let subsec_nanos = (ns % 1_000_000_000) as u32;
    if let Some(dt) = DateTime::from_timestamp(secs, subsec_nanos) {
        dt.to_rfc3339()
    } else {
        format!("{}.{:09}s", secs, subsec_nanos)
    }
}

pub fn analyze_capture<F>(
    data: &[u8],
    filename: &str,
    rule_config: Option<RuleConfig>,
    mut progress_callback: F,
) -> Result<CaptureResult, CaptureError>
where
    F: FnMut(f64, &str) -> bool, // returns false if cancelled
{
    if !progress_callback(0.05, "Validating capture header...") {
        return Err(CaptureError::ParseError(
            "Analysis cancelled by user".to_string(),
        ));
    }

    let format = detect_format(data);
    if !format.is_supported() {
        return Err(CaptureError::UnsupportedFormat(
            "File header does not match known PCAP or PCAPNG magic numbers".to_string(),
        ));
    }

    let mut reader = create_reader(65536, Cursor::new(data))
        .map_err(|e| CaptureError::InvalidHeader(format!("{:?}", e)))?;

    if !progress_callback(0.15, "Parsing packet records...") {
        return Err(CaptureError::ParseError(
            "Analysis cancelled by user".to_string(),
        ));
    }

    let mut packets: Vec<PacketRecord> = Vec::new();
    let mut dns_records: Vec<DnsRecord> = Vec::new();
    let mut flow_aggregator = FlowAggregator::new();
    let mut host_aggregator = HostAggregator::new();
    let mut stats_calculator = StatisticsCalculator::new();
    let mut timeline_aggregator = TimelineAggregator::new(1.0); // 1-second buckets
    let mut warnings: Vec<String> = Vec::new();

    let mut legacy_linktype = 1u16; // default Ethernet
    let mut interfaces: Vec<(u16, u64)> = Vec::new(); // (linktype, ts_resolution in Hz or ns multiplier)
    let mut packet_index: u64 = 0;
    let mut malformed_packet_count: u64 = 0;
    let mut start_ts_ns: Option<u128> = None;
    let mut end_ts_ns: Option<u128> = None;

    let total_bytes_len = data.len() as f64;
    let mut consumed_bytes: usize = 0;

    loop {
        match reader.next() {
            Ok((offset, block)) => {
                consumed_bytes += offset;
                if packet_index > 0 && packet_index.is_multiple_of(250) {
                    let pct = 0.15 + (consumed_bytes as f64 / total_bytes_len) * 0.45;
                    if !progress_callback(
                        pct.min(0.60),
                        &format!("Parsed {} packets...", packet_index),
                    ) {
                        return Err(CaptureError::ParseError(
                            "Analysis cancelled by user".to_string(),
                        ));
                    }
                }

                match block {
                    PcapBlockOwned::LegacyHeader(hdr) => {
                        legacy_linktype = hdr.network.0 as u16;
                    }
                    PcapBlockOwned::Legacy(packet) => {
                        packet_index += 1;
                        let ts_ns = (packet.ts_sec as u128) * 1_000_000_000
                            + (packet.ts_usec as u128) * 1000;
                        if start_ts_ns.is_none() || Some(ts_ns) < start_ts_ns {
                            start_ts_ns = Some(ts_ns);
                        }
                        if end_ts_ns.is_none() || Some(ts_ns) > end_ts_ns {
                            end_ts_ns = Some(ts_ns);
                        }

                        let ts_iso = format_timestamp(ts_ns);
                        let res = dissect_packet(
                            packet_index,
                            Some(ts_ns),
                            &ts_iso,
                            legacy_linktype,
                            packet.data,
                            packet.origlen,
                            None,
                        );

                        if !res.packet.parse_warnings.is_empty() {
                            malformed_packet_count += 1;
                        }

                        flow_aggregator.process_packet(&res.packet);
                        host_aggregator.process_packet(&res.packet);
                        stats_calculator.process_packet(&res.packet);
                        timeline_aggregator.process_packet(&res.packet);

                        if let Some(dns) = res.dns_record {
                            dns_records.push(dns);
                        }
                        packets.push(res.packet);
                    }
                    PcapBlockOwned::NG(pcapng_block) => match pcapng_block {
                        pcapng::Block::InterfaceDescription(idb) => {
                            let linktype = idb.linktype.0 as u16;
                            // Option 9 is if_tsresol: 6 means 10^-6 (microseconds), 9 means 10^-9 (nanoseconds)
                            let mut resol = 1000u64; // default microseconds -> multiply by 1000 to get ns
                            for opt in &idb.options {
                                if opt.code.0 == 9 && !opt.value.is_empty() {
                                    let exp = opt.value[0];
                                    if exp & 0x80 == 0 {
                                        // Power of 10
                                        if exp == 9 {
                                            resol = 1;
                                        } else if exp == 6 {
                                            resol = 1000;
                                        } else if exp == 3 {
                                            resol = 1_000_000;
                                        }
                                    }
                                }
                            }
                            interfaces.push((linktype, resol));
                        }
                        pcapng::Block::EnhancedPacket(epb) => {
                            packet_index += 1;
                            let if_id = epb.if_id as usize;
                            let (linktype, resol) = if if_id < interfaces.len() {
                                interfaces[if_id]
                            } else {
                                (1, 1000)
                            };

                            let raw_ts = ((epb.ts_high as u64) << 32) | (epb.ts_low as u64);
                            let ts_ns = (raw_ts as u128) * (resol as u128);

                            if start_ts_ns.is_none() || Some(ts_ns) < start_ts_ns {
                                start_ts_ns = Some(ts_ns);
                            }
                            if end_ts_ns.is_none() || Some(ts_ns) > end_ts_ns {
                                end_ts_ns = Some(ts_ns);
                            }

                            let ts_iso = format_timestamp(ts_ns);
                            let res = dissect_packet(
                                packet_index,
                                Some(ts_ns),
                                &ts_iso,
                                linktype,
                                epb.data,
                                epb.origlen,
                                Some(epb.if_id),
                            );

                            if !res.packet.parse_warnings.is_empty() {
                                malformed_packet_count += 1;
                            }

                            flow_aggregator.process_packet(&res.packet);
                            host_aggregator.process_packet(&res.packet);
                            stats_calculator.process_packet(&res.packet);
                            timeline_aggregator.process_packet(&res.packet);

                            if let Some(dns) = res.dns_record {
                                dns_records.push(dns);
                            }
                            packets.push(res.packet);
                        }
                        pcapng::Block::SimplePacket(spb) => {
                            packet_index += 1;
                            let linktype = interfaces.first().map(|i| i.0).unwrap_or(1);
                            let ts_iso = "Unknown".to_string();

                            let res = dissect_packet(
                                packet_index,
                                None,
                                &ts_iso,
                                linktype,
                                spb.data,
                                spb.origlen,
                                None,
                            );

                            flow_aggregator.process_packet(&res.packet);
                            host_aggregator.process_packet(&res.packet);
                            stats_calculator.process_packet(&res.packet);
                            packets.push(res.packet);
                        }
                        _ => {}
                    },
                }

                reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                if reader.refill().is_err() {
                    break;
                }
            }
            Err(e) => {
                warnings.push(format!("Reader warning: {:?}", e));
                break;
            }
        }
    }

    if packets.is_empty() {
        return Err(CaptureError::EmptyCapture);
    }

    if !progress_callback(0.65, "Aggregating flows and hosts...") {
        return Err(CaptureError::ParseError(
            "Analysis cancelled by user".to_string(),
        ));
    }

    // Correlate DNS answers with hosts
    for dns in &dns_records {
        for ans in &dns.answers {
            if ans.rtype == 1 || ans.rtype == 28 {
                host_aggregator.add_dns_association(&ans.data, &dns.primary_query);
            }
        }
    }

    let flows = flow_aggregator.finalize();
    let hosts = host_aggregator.finalize();
    let protocols = stats_calculator.finalize_protocols();
    let ports = stats_calculator.finalize_ports();

    if !progress_callback(0.80, "Calculating traffic timelines and charts...") {
        return Err(CaptureError::ParseError(
            "Analysis cancelled by user".to_string(),
        ));
    }

    let timeline = timeline_aggregator.finalize();

    if !progress_callback(0.90, "Evaluating heuristic finding rules...") {
        return Err(CaptureError::ParseError(
            "Analysis cancelled by user".to_string(),
        ));
    }

    let cfg = rule_config.unwrap_or_default();
    let findings = evaluate_findings(&packets, &flows, &hosts, &dns_records, &timeline, &cfg);

    let start_iso = start_ts_ns
        .map(format_timestamp)
        .unwrap_or_else(|| "N/A".to_string());
    let end_iso = end_ts_ns
        .map(format_timestamp)
        .unwrap_or_else(|| "N/A".to_string());
    let duration_sec = match (start_ts_ns, end_ts_ns) {
        (Some(s), Some(e)) if e >= s => (e - s) as f64 / 1_000_000_000.0,
        _ => 0.0,
    };

    let total_bytes: u64 = packets.iter().map(|p| p.captured_length as u64).sum();

    let summary = CaptureSummary {
        filename: filename.to_string(),
        file_size_bytes: data.len() as u64,
        format_name: format.name().to_string(),
        packet_count: packets.len() as u64,
        total_bytes,
        start_time_iso: start_iso,
        end_time_iso: end_iso,
        duration_seconds: duration_sec,
        link_type_name: if legacy_linktype == 1 {
            "Ethernet (1)".to_string()
        } else {
            format!("LINKTYPE_{}", legacy_linktype)
        },
        interface_count: if interfaces.is_empty() {
            1
        } else {
            interfaces.len()
        },
        timestamp_precision: match format {
            CaptureFormat::Pcap { precision, .. } => format!("{:?}", precision),
            _ => "Nanosecond (Interface Scaled)".to_string(),
        },
        malformed_packet_count,
        truncated_packet_count: stats_calculator.truncated_count(),
        unsupported_packet_count: 0,
        host_count: hosts.len(),
        flow_count: flows.len(),
        dns_query_count: dns_records.len(),
    };

    let limitations = vec![
        "Encrypted application payloads (TLS, SSH, HTTPS) are inspected for protocol metadata only; payload plaintext is neither decrypted nor inspected.".to_string(),
        "Heuristic findings represent potentially unusual statistical patterns and should not be treated as confirmed security compromises.".to_string(),
        "Incomplete observed TCP handshakes may simply reflect partial packet capture duration rather than connection failure.".to_string(),
        "Analyses are executed entirely client-side inside the local WebAssembly runtime; capture data is never transmitted to remote servers.".to_string(),
    ];

    let _ = progress_callback(1.0, "Analysis complete.");

    Ok(CaptureResult {
        summary,
        packets,
        flows,
        hosts,
        protocols,
        ports,
        dns_records,
        timeline,
        findings,
        limitations,
        warnings,
    })
}
