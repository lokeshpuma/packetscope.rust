use packetscope_core::*;

#[test]
fn test_demo_analysis_complete() {
    let result = load_demo_analysis().expect("Demo analysis failed");

    // Summary checks
    assert!(
        result.summary.packet_count >= 20,
        "Expected >= 20 packets, found {}",
        result.summary.packet_count
    );
    assert!(result.summary.total_bytes > 1000);
    assert_eq!(result.summary.format_name, "PCAP");
    assert!(result.summary.duration_seconds > 0.0);
    assert!(result.summary.host_count >= 4);
    assert!(result.summary.flow_count >= 5);

    // Protocol checks
    let proto_names: Vec<&str> = result.protocols.iter().map(|p| p.name.as_str()).collect();
    assert!(
        proto_names.contains(&"ARP"),
        "Missing ARP in {:?}",
        proto_names
    );
    assert!(
        proto_names.contains(&"TCP"),
        "Missing TCP in {:?}",
        proto_names
    );
    assert!(
        proto_names.contains(&"UDP"),
        "Missing UDP in {:?}",
        proto_names
    );
    assert!(
        proto_names.contains(&"DNS"),
        "Missing DNS in {:?}",
        proto_names
    );
    assert!(
        proto_names.contains(&"HTTP"),
        "Missing HTTP in {:?}",
        proto_names
    );

    // DNS checks
    assert!(!result.dns_records.is_empty(), "Expected DNS records");
    let has_nxdomain = result
        .dns_records
        .iter()
        .any(|d| d.rcode_name == "NXDomain");
    assert!(has_nxdomain, "Expected at least one NXDOMAIN record");

    // Host checks
    let host_ips: Vec<&str> = result.hosts.iter().map(|h| h.ip.as_str()).collect();
    assert!(host_ips.contains(&"192.168.1.10"), "Client host missing");
    assert!(host_ips.contains(&"8.8.8.8"), "DNS host missing");

    // Flow checks
    assert!(!result.flows.is_empty(), "Expected flows");
    let has_http_flow = result
        .flows
        .iter()
        .any(|f| f.port_b == 80 || f.port_a == 80);
    assert!(has_http_flow, "Expected HTTP flow on port 80");

    // Findings checks (Rule heuristics)
    assert!(
        !result.findings.is_empty(),
        "Expected heuristic findings to trigger"
    );
    let rule_names: Vec<&str> = result
        .findings
        .iter()
        .map(|f| f.rule_name.as_str())
        .collect();
    println!("Triggered findings: {:?}", rule_names);

    // Timeline checks
    assert!(!result.timeline.buckets.is_empty());
    assert!(result.timeline.max_pps > 0.0);

    // Export tests
    let csv_pkts = export_packets_csv(&result.packets);
    assert!(csv_pkts.contains("No,Time,Source,Destination,Protocol"));
    assert!(csv_pkts.lines().count() > 10);

    let csv_flows = export_flows_csv(&result.flows);
    assert!(csv_flows.contains("FlowID,Protocol,EndpointA"));

    let csv_hosts = export_hosts_csv(&result.hosts);
    assert!(csv_hosts.contains("IP,MAC,AddressFamily"));

    let csv_findings = export_findings_csv(&result.findings);
    assert!(csv_findings.contains("FindingID,Title,Severity"));

    let json_report =
        export_analysis_json(&result.to_analysis_report()).expect("JSON report export failed");
    assert!(json_report.contains("\"packet_count\":"));

    let html_report = export_html_report(&result.to_analysis_report());
    assert!(html_report.contains("<!DOCTYPE html>"));
    assert!(html_report.contains("PacketScope Analysis Report"));
}

#[test]
fn test_filter_evaluation() {
    let result = load_demo_analysis().expect("Demo analysis failed");

    // Test 1: ip.src
    let filter1 = parse_filter("ip.src == 192.168.1.10").expect("Parse filter 1");
    let matched1: Vec<_> = result
        .packets
        .iter()
        .filter(|p| filter1.evaluate(p))
        .collect();
    assert!(!matched1.is_empty());
    assert!(matched1
        .iter()
        .all(|p| p.source_ip.as_deref() == Some("192.168.1.10")));

    // Test 2: tcp.port
    let filter2 = parse_filter("tcp.port == 80").expect("Parse filter 2");
    let matched2: Vec<_> = result
        .packets
        .iter()
        .filter(|p| filter2.evaluate(p))
        .collect();
    assert!(!matched2.is_empty());
    assert!(matched2
        .iter()
        .all(|p| p.source_port == Some(80) || p.destination_port == Some(80)));

    // Test 3: protocol
    let filter3 = parse_filter("protocol == \"DNS\"").expect("Parse filter 3");
    let matched3: Vec<_> = result
        .packets
        .iter()
        .filter(|p| filter3.evaluate(p))
        .collect();
    assert!(!matched3.is_empty());

    // Test 4: logical and & or
    let filter4 =
        parse_filter("ip.src == 192.168.1.10 and tcp.flags.syn == true").expect("Parse filter 4");
    let matched4: Vec<_> = result
        .packets
        .iter()
        .filter(|p| filter4.evaluate(p))
        .collect();
    assert!(!matched4.is_empty());

    // Test 5: frame.len comparison
    let filter5 = parse_filter("frame.len > 50").expect("Parse filter 5");
    let matched5: Vec<_> = result
        .packets
        .iter()
        .filter(|p| filter5.evaluate(p))
        .collect();
    assert!(!matched5.is_empty());
    assert!(matched5.iter().all(|p| p.captured_length > 50));

    // Test 6: invalid syntax should fail safely
    assert!(parse_filter("invalid.field == 123").is_err());
    assert!(parse_filter("ip.src = 123").is_err());
    assert!(parse_filter("(ip.src == 10.0.0.1").is_err());
}

#[test]
fn test_csv_formula_injection_prevention() {
    let dangerous_str = "=SUM(A1:A10)";
    let sanitized = sanitize_csv_cell(dangerous_str);
    assert_eq!(sanitized, "'=SUM(A1:A10)");

    let dangerous_cmd = "+cmd|' /C calc'!A0";
    let sanitized2 = sanitize_csv_cell(dangerous_cmd);
    assert_eq!(sanitized2, "'+cmd|' /C calc'!A0");
}

#[test]
fn test_malformed_pcap_robustness() {
    // Empty data
    assert!(analyze_capture(&[], "empty.pcap", None, |_, _| true).is_err());

    // Truncated header
    let truncated_hdr = [0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x04];
    assert!(analyze_capture(&truncated_hdr, "trunc.pcap", None, |_, _| true).is_err());

    // Garbage data
    let garbage = vec![0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
    assert!(analyze_capture(&garbage, "garbage.pcap", None, |_, _| true).is_err());
}
