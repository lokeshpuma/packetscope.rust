pub mod arp;
pub mod dns;
pub mod ethernet;
pub mod icmp;
pub mod ipv4;
pub mod ipv6;
pub mod tcp;
pub mod udp;

use crate::packet::{LayerField, PacketRecord, ProtocolLayer};
use arp::parse_arp;
use dns::parse_dns;
use ethernet::parse_ethernet;
use icmp::parse_icmp;
use ipv4::parse_ipv4;
use ipv6::parse_ipv6;
use tcp::parse_tcp;
use udp::parse_udp;

pub struct DissectResult {
    pub packet: PacketRecord,
    pub dns_record: Option<dns::DnsRecord>,
}

pub fn dissect_packet(
    index: u64,
    timestamp_ns: Option<u128>,
    timestamp_iso: &str,
    link_type: u16,
    data: &[u8],
    orig_len: u32,
    interface_id: Option<u32>,
) -> DissectResult {
    let captured_length = data.len() as u32;
    let truncated = captured_length < orig_len;

    let mut layers = Vec::new();
    let mut warnings = Vec::new();

    // Frame Layer
    let frame_layer = ProtocolLayer {
        name: "Frame".to_string(),
        description: format!(
            "Frame {}: {} bytes captured on wire, {} bytes total",
            index, captured_length, orig_len
        ),
        fields: vec![
            LayerField::new("Frame Number", index.to_string()),
            LayerField::new(
                "Frame Length",
                format!("{} bytes ({} bits)", captured_length, captured_length * 8),
            ),
            LayerField::new("Capture Length", format!("{} bytes", captured_length)),
            LayerField::new("Original Length", format!("{} bytes", orig_len)),
            LayerField::new("Arrival Time", timestamp_iso),
            LayerField::new("Link Layer Type", format!("LINKTYPE_{}", link_type)),
        ],
    };
    layers.push(frame_layer);

    let mut src_mac = None;
    let mut dst_mac = None;
    let mut vlan_id = None;
    let mut src_ip = None;
    let mut dst_ip = None;
    let mut net_proto = "Unknown".to_string();
    let mut trans_proto = None;
    let mut app_proto = None;
    let mut src_port = None;
    let mut dst_port = None;
    let mut tcp_flags = None;
    let mut tcp_seq = None;
    let mut tcp_ack = None;
    let mut payload_len = 0u32;
    let mut info = format!("Frame {} ({} bytes)", index, captured_length);
    let mut dns_res = None;

    let mut curr_data = data;
    let mut next_ethertype = 0u16;

    // Link Layer dissection
    match link_type {
        1 => {
            // LINKTYPE_ETHERNET
            match parse_ethernet(curr_data) {
                Ok((eth, layer)) => {
                    src_mac = Some(eth.source_mac);
                    dst_mac = Some(eth.destination_mac);
                    vlan_id = eth.vlan_id;
                    next_ethertype = eth.ether_type;
                    curr_data = eth.payload;
                    layers.push(layer);
                }
                Err(err) => {
                    warnings.push(format!("Ethernet: {}", err));
                }
            }
        }
        12 | 101 | 228 => {
            // Raw IPv4
            next_ethertype = 0x0800;
        }
        229 => {
            // Raw IPv6
            next_ethertype = 0x86dd;
        }
        other => {
            warnings.push(format!("Unsupported link type: {}", other));
        }
    }

    // Network Layer dissection
    let mut ip_proto = 0u8;
    let mut is_ipv6 = false;

    match next_ethertype {
        0x0806 => {
            // ARP
            net_proto = "ARP".to_string();
            match parse_arp(curr_data) {
                Ok((arp_pkt, layer)) => {
                    src_ip = Some(arp_pkt.sender_ip);
                    dst_ip = Some(arp_pkt.target_ip);
                    info = arp_pkt.info;
                    layers.push(layer);
                }
                Err(err) => {
                    warnings.push(format!("ARP: {}", err));
                }
            }
        }
        0x0800 => {
            // IPv4
            net_proto = "IPv4".to_string();
            match parse_ipv4(curr_data) {
                Ok((ip, layer)) => {
                    info = format!("IPv4: {} → {}", ip.source_ip, ip.destination_ip);
                    src_ip = Some(ip.source_ip);
                    dst_ip = Some(ip.destination_ip);
                    ip_proto = ip.protocol;
                    curr_data = ip.payload;
                    layers.push(layer);
                }
                Err(err) => {
                    warnings.push(format!("IPv4: {}", err));
                }
            }
        }
        0x86dd => {
            // IPv6
            net_proto = "IPv6".to_string();
            is_ipv6 = true;
            match parse_ipv6(curr_data) {
                Ok((ip6, layer)) => {
                    info = format!("IPv6: {} → {}", ip6.source_ip, ip6.destination_ip);
                    src_ip = Some(ip6.source_ip);
                    dst_ip = Some(ip6.destination_ip);
                    ip_proto = ip6.next_header;
                    curr_data = ip6.payload;
                    layers.push(layer);
                }
                Err(err) => {
                    warnings.push(format!("IPv6: {}", err));
                }
            }
        }
        _ => {}
    }

    // Transport Layer dissection
    match ip_proto {
        6 => {
            // TCP
            trans_proto = Some("TCP".to_string());
            match parse_tcp(curr_data) {
                Ok((tcp_seg, layer)) => {
                    src_port = Some(tcp_seg.source_port);
                    dst_port = Some(tcp_seg.destination_port);
                    tcp_flags = Some(tcp_seg.flags);
                    tcp_seq = Some(tcp_seg.sequence_number);
                    tcp_ack = Some(tcp_seg.ack_number);
                    payload_len = tcp_seg.payload.len() as u32;
                    info = tcp_seg.info;
                    curr_data = tcp_seg.payload;
                    layers.push(layer);
                }
                Err(err) => {
                    warnings.push(format!("TCP: {}", err));
                }
            }
        }
        17 => {
            // UDP
            trans_proto = Some("UDP".to_string());
            match parse_udp(curr_data) {
                Ok((udp_dgram, layer)) => {
                    src_port = Some(udp_dgram.source_port);
                    dst_port = Some(udp_dgram.destination_port);
                    payload_len = udp_dgram.payload.len() as u32;
                    info = udp_dgram.info;
                    curr_data = udp_dgram.payload;
                    layers.push(layer);
                }
                Err(err) => {
                    warnings.push(format!("UDP: {}", err));
                }
            }
        }
        1 | 58 => {
            // ICMP / ICMPv6
            let icmp_name = if is_ipv6 { "ICMPv6" } else { "ICMP" };
            trans_proto = Some(icmp_name.to_string());
            match parse_icmp(curr_data, is_ipv6) {
                Ok((icmp_pkt, layer)) => {
                    info = icmp_pkt.info;
                    payload_len = icmp_pkt.payload.len() as u32;
                    curr_data = icmp_pkt.payload;
                    layers.push(layer);
                }
                Err(err) => {
                    warnings.push(format!("ICMP: {}", err));
                }
            }
        }
        _ => {}
    }

    // Application Layer dissection
    let sport = src_port.unwrap_or(0);
    let dport = dst_port.unwrap_or(0);

    // DNS (Port 53)
    if (sport == 53 || dport == 53) && !curr_data.is_empty() {
        let sip = src_ip.as_deref().unwrap_or("0.0.0.0");
        let dip = dst_ip.as_deref().unwrap_or("0.0.0.0");
        let dns_slice = if trans_proto.as_deref() == Some("TCP") && curr_data.len() > 2 {
            // DNS over TCP has 2-byte prefix length
            &curr_data[2..]
        } else {
            curr_data
        };

        if let Ok((dns_rec, layer)) =
            parse_dns(dns_slice, index, timestamp_ns, timestamp_iso, sip, dip)
        {
            app_proto = Some("DNS".to_string());
            info = layer.description.clone();
            layers.push(layer);
            dns_res = Some(dns_rec);
        }
    }
    // HTTP detection (Port 80, 8080 or header heuristic)
    else if (sport == 80 || dport == 80 || sport == 8080 || dport == 8080)
        && !curr_data.is_empty()
    {
        let preview = String::from_utf8_lossy(&curr_data[..curr_data.len().min(128)]);
        if preview.starts_with("GET ")
            || preview.starts_with("POST ")
            || preview.starts_with("HTTP/1.")
            || preview.starts_with("PUT ")
            || preview.starts_with("HEAD ")
        {
            app_proto = Some("HTTP".to_string());
            let first_line = preview.lines().next().unwrap_or("HTTP Traffic");
            info = first_line.to_string();
            layers.push(ProtocolLayer {
                name: "Hypertext Transfer Protocol".to_string(),
                description: first_line.to_string(),
                fields: vec![
                    LayerField::new("Summary", first_line),
                    LayerField::new("Payload Length", format!("{} bytes", curr_data.len())),
                ],
            });
        }
    }
    // TLS detection (Port 443, 8443 or ContentType 0x16 Handshake)
    else if (sport == 443 || dport == 443 || sport == 8443 || dport == 8443)
        && curr_data.len() >= 5
        && curr_data[0] == 0x16
        && curr_data[1] == 0x03
    {
        app_proto = Some("TLS".to_string());
        let tls_ver = match (curr_data[1], curr_data[2]) {
            (3, 1) => "TLS 1.0",
            (3, 2) => "TLS 1.1",
            (3, 3) => "TLS 1.2",
            (3, 4) => "TLS 1.3",
            _ => "TLS Record",
        };
        let handshake_type = if curr_data.len() >= 6 {
            match curr_data[5] {
                1 => "Client Hello",
                2 => "Server Hello",
                11 => "Certificate",
                12 => "Server Key Exchange",
                14 => "Server Hello Done",
                16 => "Client Key Exchange",
                _ => "Handshake Record",
            }
        } else {
            "Handshake Record"
        };
        info = format!("{}: {}", tls_ver, handshake_type);
        layers.push(ProtocolLayer {
            name: "Transport Layer Security".to_string(),
            description: info.clone(),
            fields: vec![
                LayerField::new("Version", tls_ver),
                LayerField::new("Handshake Type", handshake_type),
                LayerField::new("Payload Length", format!("{} bytes", curr_data.len())),
            ],
        });
    }

    // If there is leftover unparsed application payload, add a generic Data layer
    if app_proto.is_none() && payload_len > 0 && !curr_data.is_empty() {
        layers.push(ProtocolLayer {
            name: "Data".to_string(),
            description: format!("{} bytes application payload", curr_data.len()),
            fields: vec![LayerField::new(
                "Length",
                format!("{} bytes", curr_data.len()),
            )],
        });
    }

    let record = PacketRecord {
        index,
        timestamp_ns,
        timestamp_iso: timestamp_iso.to_string(),
        captured_length,
        original_length: orig_len,
        link_type,
        source_mac: src_mac,
        destination_mac: dst_mac,
        vlan_id,
        source_ip: src_ip,
        destination_ip: dst_ip,
        network_protocol: net_proto,
        transport_protocol: trans_proto,
        application_protocol: app_proto,
        source_port: src_port,
        destination_port: dst_port,
        tcp_flags,
        tcp_seq,
        tcp_ack,
        payload_length: payload_len,
        interface_id,
        truncated,
        parse_warnings: warnings,
        info,
        layers,
        raw_bytes: data.to_vec(),
    };

    DissectResult {
        packet: record,
        dns_record: dns_res,
    }
}
