use crate::findings::Finding;
use crate::flow::NetworkFlow;
use crate::host::HostRecord;
use crate::packet::PacketRecord;
use crate::statistics::{CaptureSummary, ProtocolStat};
use serde::{Deserialize, Serialize};

pub fn sanitize_csv_cell(val: &str) -> String {
    let trimmed = val.trim();
    // Formula injection check: =, +, -, @, tab, carriage return
    let needs_prefix = trimmed.starts_with('=')
        || trimmed.starts_with('+')
        || trimmed.starts_with('-')
        || trimmed.starts_with('@')
        || trimmed.starts_with('\t')
        || trimmed.starts_with('\r');

    let sanitized = if needs_prefix {
        format!("'{}", trimmed)
    } else {
        trimmed.to_string()
    };

    if sanitized.contains(',')
        || sanitized.contains('"')
        || sanitized.contains('\n')
        || sanitized.contains('\r')
    {
        format!("\"{}\"", sanitized.replace('"', "\"\""))
    } else {
        sanitized
    }
}

pub fn export_packets_csv(packets: &[PacketRecord]) -> String {
    let mut out = String::from(
        "No,Time,Source,Destination,Protocol,SourcePort,DestinationPort,Length,TCPFlags,Info\n",
    );
    for p in packets {
        let line = format!(
            "{},{},{},{},{},{},{},{},{},{}\n",
            p.index,
            sanitize_csv_cell(&p.timestamp_iso),
            sanitize_csv_cell(&p.primary_source()),
            sanitize_csv_cell(&p.primary_destination()),
            sanitize_csv_cell(&p.protocol_display()),
            p.source_port.map(|v| v.to_string()).unwrap_or_default(),
            p.destination_port
                .map(|v| v.to_string())
                .unwrap_or_default(),
            p.captured_length,
            sanitize_csv_cell(
                &p.tcp_flags
                    .map(|f| f.to_display_string())
                    .unwrap_or_default()
            ),
            sanitize_csv_cell(&p.info)
        );
        out.push_str(&line);
    }
    out
}

pub fn export_flows_csv(flows: &[NetworkFlow]) -> String {
    let mut out = String::from("FlowID,Protocol,EndpointA,PortA,EndpointB,PortB,StartTime,EndTime,DurationSec,PacketCount,TotalBytes,ForwardPackets,ReversePackets,HandshakeSummary\n");
    for f in flows {
        let line = format!(
            "{},{},{},{},{},{},{},{},{:.4},{},{},{},{},{}\n",
            sanitize_csv_cell(&f.id),
            sanitize_csv_cell(&f.protocol),
            sanitize_csv_cell(&f.endpoint_a),
            f.port_a,
            sanitize_csv_cell(&f.endpoint_b),
            f.port_b,
            sanitize_csv_cell(&f.start_time_iso),
            sanitize_csv_cell(&f.end_time_iso),
            f.duration_seconds,
            f.packet_count,
            f.total_bytes,
            f.forward_packets,
            f.reverse_packets,
            sanitize_csv_cell(&f.handshake_summary)
        );
        out.push_str(&line);
    }
    out
}

pub fn export_hosts_csv(hosts: &[HostRecord]) -> String {
    let mut out = String::from("IP,MAC,AddressFamily,PacketsSent,PacketsReceived,BytesSent,BytesReceived,TotalBytes,UniquePeersCount,FirstSeen,LastSeen\n");
    for h in hosts {
        let line = format!(
            "{},{},{},{},{},{},{},{},{},{},{}\n",
            sanitize_csv_cell(&h.ip),
            sanitize_csv_cell(h.mac.as_deref().unwrap_or("")),
            sanitize_csv_cell(&h.address_family),
            h.packets_sent,
            h.packets_received,
            h.bytes_sent,
            h.bytes_received,
            h.total_bytes,
            h.peer_count,
            sanitize_csv_cell(&h.first_seen_iso),
            sanitize_csv_cell(&h.last_seen_iso)
        );
        out.push_str(&line);
    }
    out
}

pub fn export_findings_csv(findings: &[Finding]) -> String {
    let mut out = String::from("FindingID,Title,Severity,Category,Host,Status,RuleName,Threshold,ObservedValue,WhatHappened\n");
    for f in findings {
        let line = format!(
            "{},{},{},{},{},{},{},{},{},{}\n",
            sanitize_csv_cell(&f.id),
            sanitize_csv_cell(&f.title),
            sanitize_csv_cell(f.severity.as_str()),
            sanitize_csv_cell(&f.category),
            sanitize_csv_cell(f.affected_host.as_deref().unwrap_or("")),
            sanitize_csv_cell(f.status.as_str()),
            sanitize_csv_cell(&f.rule_name),
            sanitize_csv_cell(&f.configured_threshold),
            sanitize_csv_cell(&f.observed_value),
            sanitize_csv_cell(&f.what_happened)
        );
        out.push_str(&line);
    }
    out
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisReport {
    pub summary: CaptureSummary,
    pub protocols: Vec<ProtocolStat>,
    pub top_hosts: Vec<HostRecord>,
    pub top_flows: Vec<NetworkFlow>,
    pub findings: Vec<Finding>,
    pub limitations: Vec<String>,
}

pub fn export_analysis_json(report: &AnalysisReport) -> Result<String, String> {
    serde_json::to_string_pretty(report).map_err(|e| e.to_string())
}

pub fn export_html_report(report: &AnalysisReport) -> String {
    let mut html = String::new();
    html.push_str(r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>PacketScope Analysis Report</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 24px; }
.container { max-width: 1000px; margin: 0 auto; background: #1e293b; border-radius: 8px; padding: 32px; border: 1px solid #334155; }
h1, h2, h3 { color: #38bdf8; margin-top: 24px; }
h1 { margin-top: 0; border-bottom: 2px solid #334155; padding-bottom: 12px; }
table { width: 100%; border-collapse: collapse; margin-top: 12px; margin-bottom: 24px; font-size: 14px; }
th, td { border: 1px solid #334155; padding: 10px 14px; text-align: left; }
th { background: #0f172a; color: #94a3b8; font-weight: 600; }
tr:nth-child(even) { background: #1e293b; }
tr:nth-child(odd) { background: #182234; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; }
.badge-High { background: #ef4444; color: #fff; }
.badge-Medium { background: #f59e0b; color: #000; }
.badge-Low { background: #3b82f6; color: #fff; }
.badge-Info { background: #10b981; color: #fff; }
.footer { font-size: 12px; color: #64748b; margin-top: 32px; border-top: 1px solid #334155; padding-top: 16px; }
</style>
</head>
<body>
<div class="container">
<h1>PacketScope Analysis Report</h1>
<p><strong>Capture:</strong> "#);
    html.push_str(&html_escape(&report.summary.filename));
    html.push_str(" | <strong>Format:</strong> ");
    html.push_str(&html_escape(&report.summary.format_name));
    html.push_str(" | <strong>Analyzed Locally:</strong> Privacy Preserved</p>");

    html.push_str("<h2>1. Executive Summary</h2><table>");
    html.push_str(&format!("<tr><th>Total Packets</th><td>{}</td><th>Total Volume</th><td>{:.2} MB ({} bytes)</td></tr>", report.summary.packet_count, report.summary.total_bytes as f64 / 1_048_576.0, report.summary.total_bytes));
    html.push_str(&format!(
        "<tr><th>Duration</th><td>{:.2} seconds</td><th>Link Layer</th><td>{}</td></tr>",
        report.summary.duration_seconds,
        html_escape(&report.summary.link_type_name)
    ));
    html.push_str(&format!(
        "<tr><th>Start Time</th><td>{}</td><th>End Time</th><td>{}</td></tr>",
        html_escape(&report.summary.start_time_iso),
        html_escape(&report.summary.end_time_iso)
    ));
    html.push_str(&format!(
        "<tr><th>Unique Hosts</th><td>{}</td><th>Unique Flows</th><td>{}</td></tr>",
        report.summary.host_count, report.summary.flow_count
    ));
    html.push_str(&format!(
        "<tr><th>Malformed Packets</th><td>{}</td><th>Truncated Packets</th><td>{}</td></tr>",
        report.summary.malformed_packet_count, report.summary.truncated_packet_count
    ));
    html.push_str("</table>");

    html.push_str("<h2>2. Protocol Distribution</h2><table><tr><th>Protocol</th><th>Packets</th><th>Packet %</th><th>Bytes</th><th>Byte %</th></tr>");
    for proto in &report.protocols {
        html.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{:.1}%</td><td>{}</td><td>{:.1}%</td></tr>",
            html_escape(&proto.name),
            proto.packet_count,
            proto.percentage_packets,
            proto.byte_count,
            proto.percentage_bytes
        ));
    }
    html.push_str("</table>");

    html.push_str("<h2>3. Heuristic Findings & Anomalies</h2>");
    if report.findings.is_empty() {
        html.push_str("<p>No anomalous patterns detected matching configured heuristics.</p>");
    } else {
        html.push_str("<table><tr><th>ID</th><th>Severity</th><th>Title</th><th>Observed Value</th><th>Threshold</th></tr>");
        for f in &report.findings {
            html.push_str(&format!(
                "<tr><td>{}</td><td><span class=\"badge badge-{}\">{}</span></td><td><strong>{}</strong><br><small>{}</small></td><td>{}</td><td>{}</td></tr>",
                html_escape(&f.id), f.severity.as_str(), f.severity.as_str(),
                html_escape(&f.title), html_escape(&f.what_happened),
                html_escape(&f.observed_value), html_escape(&f.configured_threshold)
            ));
        }
        html.push_str("</table>");
    }

    html.push_str("<h2>4. Analysis Limitations</h2><ul>");
    for lim in &report.limitations {
        html.push_str(&format!("<li>{}</li>", html_escape(lim)));
    }
    html.push_str("</ul>");

    html.push_str("<div class=\"footer\"><p>Generated by PacketScope Browser-Based Network Forensics Workbench. Notice: Packet capture data processed entirely client-side. No capture bytes transmitted to external services.</p></div>");
    html.push_str("</div></body></html>");

    html
}

fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
