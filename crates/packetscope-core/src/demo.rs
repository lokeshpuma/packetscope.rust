use crate::capture::{analyze_capture, CaptureResult};
use crate::errors::CaptureError;

/// Generates a valid, deterministic PCAP byte stream containing realistic
/// network traffic for PacketScope's Demo Mode.
pub fn generate_demo_pcap() -> Vec<u8> {
    let mut data = Vec::new();

    // Global PCAP Header (24 bytes): Magic 0xa1b2c3d4 (LE), v2.4, tz 0, sig 0, snaplen 65535, linktype 1 (Ethernet)
    data.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    data.extend_from_slice(&2u16.to_le_bytes());
    data.extend_from_slice(&4u16.to_le_bytes());
    data.extend_from_slice(&0i32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&65535u32.to_le_bytes());
    data.extend_from_slice(&1u32.to_le_bytes());

    let base_time: u32 = 1700000000;

    let append_packet = |buf: &mut Vec<u8>, sec_offset: u32, usec: u32, pkt_bytes: &[u8]| {
        let caplen = pkt_bytes.len() as u32;
        buf.extend_from_slice(&(base_time + sec_offset).to_le_bytes());
        buf.extend_from_slice(&usec.to_le_bytes());
        buf.extend_from_slice(&caplen.to_le_bytes());
        buf.extend_from_slice(&caplen.to_le_bytes());
        buf.extend_from_slice(pkt_bytes);
    };

    // Helper: Build Ethernet header (14 bytes)
    let make_eth = |src: [u8; 6], dst: [u8; 6], ethertype: u16| -> Vec<u8> {
        let mut eth = Vec::with_capacity(14);
        eth.extend_from_slice(&dst);
        eth.extend_from_slice(&src);
        eth.extend_from_slice(&ethertype.to_be_bytes());
        eth
    };

    // Helper: Build IPv4 header (20 bytes)
    let make_ipv4 = |src: [u8; 4], dst: [u8; 4], proto: u8, payload_len: u16| -> Vec<u8> {
        let mut ip = Vec::with_capacity(20);
        ip.push(0x45); // Version 4, IHL 5
        ip.push(0x00); // DSCP
        ip.extend_from_slice(&(20 + payload_len).to_be_bytes());
        ip.extend_from_slice(&0x1234u16.to_be_bytes()); // ID
        ip.extend_from_slice(&0x4000u16.to_be_bytes()); // DF
        ip.push(64); // TTL
        ip.push(proto);
        ip.extend_from_slice(&0x0000u16.to_be_bytes()); // Checksum
        ip.extend_from_slice(&src);
        ip.extend_from_slice(&dst);
        ip
    };

    // Helper: Build TCP header (20 bytes)
    let make_tcp =
        |sport: u16, dport: u16, seq: u32, ack: u32, flags: u8, payload: &[u8]| -> Vec<u8> {
            let mut tcp = Vec::with_capacity(20 + payload.len());
            tcp.extend_from_slice(&sport.to_be_bytes());
            tcp.extend_from_slice(&dport.to_be_bytes());
            tcp.extend_from_slice(&seq.to_be_bytes());
            tcp.extend_from_slice(&ack.to_be_bytes());
            tcp.push(0x50); // Data offset 5 (20 bytes)
            tcp.push(flags);
            tcp.extend_from_slice(&65535u16.to_be_bytes()); // Window
            tcp.extend_from_slice(&0x0000u16.to_be_bytes()); // Checksum
            tcp.extend_from_slice(&0x0000u16.to_be_bytes()); // Urgent
            tcp.extend_from_slice(payload);
            tcp
        };

    // Helper: Build UDP header (8 bytes)
    let make_udp = |sport: u16, dport: u16, payload: &[u8]| -> Vec<u8> {
        let mut udp = Vec::with_capacity(8 + payload.len());
        udp.extend_from_slice(&sport.to_be_bytes());
        udp.extend_from_slice(&dport.to_be_bytes());
        let len = (8 + payload.len()) as u16;
        udp.extend_from_slice(&len.to_be_bytes());
        udp.extend_from_slice(&0x0000u16.to_be_bytes()); // Checksum
        udp.extend_from_slice(payload);
        udp
    };

    let mac_client = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    let mac_router = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    let ip_client = [192, 168, 1, 10];
    let ip_router = [192, 168, 1, 1];
    let ip_dns = [8, 8, 8, 8];
    let ip_web = [93, 184, 216, 34]; // example.com
    let ip_scanner = [192, 168, 1, 100];

    // 1. ARP Request: Who has 192.168.1.1? Tell 192.168.1.10
    {
        let mut pkt = make_eth(mac_client, [0xff; 6], 0x0806);
        pkt.extend_from_slice(&1u16.to_be_bytes()); // HW Ethernet
        pkt.extend_from_slice(&0x0800u16.to_be_bytes()); // Proto IPv4
        pkt.push(6);
        pkt.push(4);
        pkt.extend_from_slice(&1u16.to_be_bytes()); // Op Request
        pkt.extend_from_slice(&mac_client);
        pkt.extend_from_slice(&ip_client);
        pkt.extend_from_slice(&[0x00; 6]);
        pkt.extend_from_slice(&ip_router);
        append_packet(&mut data, 0, 100000, &pkt);
    }

    // 2. ARP Reply: 192.168.1.1 is at mac_router
    {
        let mut pkt = make_eth(mac_router, mac_client, 0x0806);
        pkt.extend_from_slice(&1u16.to_be_bytes());
        pkt.extend_from_slice(&0x0800u16.to_be_bytes());
        pkt.push(6);
        pkt.push(4);
        pkt.extend_from_slice(&2u16.to_be_bytes()); // Op Reply
        pkt.extend_from_slice(&mac_router);
        pkt.extend_from_slice(&ip_router);
        pkt.extend_from_slice(&mac_client);
        pkt.extend_from_slice(&ip_client);
        append_packet(&mut data, 0, 110000, &pkt);
    }

    // 3. DNS Query: example.com (A)
    {
        let mut dns_payload = Vec::new();
        dns_payload.extend_from_slice(&0x1a2bu16.to_be_bytes()); // TX ID
        dns_payload.extend_from_slice(&0x0100u16.to_be_bytes()); // Standard query, RD
        dns_payload.extend_from_slice(&1u16.to_be_bytes()); // 1 question
        dns_payload.extend_from_slice(&0u16.to_be_bytes()); // 0 answers
        dns_payload.extend_from_slice(&0u16.to_be_bytes());
        dns_payload.extend_from_slice(&0u16.to_be_bytes());
        // "example.com"
        dns_payload.push(7);
        dns_payload.extend_from_slice(b"example");
        dns_payload.push(3);
        dns_payload.extend_from_slice(b"com");
        dns_payload.push(0);
        dns_payload.extend_from_slice(&1u16.to_be_bytes()); // Type A
        dns_payload.extend_from_slice(&1u16.to_be_bytes()); // Class IN

        let udp = make_udp(54321, 53, &dns_payload);
        let ip = make_ipv4(ip_client, ip_dns, 17, udp.len() as u16);
        let mut pkt = make_eth(mac_client, mac_router, 0x0800);
        pkt.extend_from_slice(&ip);
        pkt.extend_from_slice(&udp);
        append_packet(&mut data, 1, 10000, &pkt);
    }

    // 4. DNS Response: example.com -> 93.184.216.34
    {
        let mut dns_payload = Vec::new();
        dns_payload.extend_from_slice(&0x1a2bu16.to_be_bytes());
        dns_payload.extend_from_slice(&0x8180u16.to_be_bytes()); // Response, NoError
        dns_payload.extend_from_slice(&1u16.to_be_bytes()); // 1 question
        dns_payload.extend_from_slice(&1u16.to_be_bytes()); // 1 answer
        dns_payload.extend_from_slice(&0u16.to_be_bytes());
        dns_payload.extend_from_slice(&0u16.to_be_bytes());
        // Question: example.com
        dns_payload.push(7);
        dns_payload.extend_from_slice(b"example");
        dns_payload.push(3);
        dns_payload.extend_from_slice(b"com");
        dns_payload.push(0);
        dns_payload.extend_from_slice(&1u16.to_be_bytes());
        dns_payload.extend_from_slice(&1u16.to_be_bytes());
        // Answer: pointer 0xC00C, Type A (1), Class IN (1), TTL 300, Len 4, 93.184.216.34
        dns_payload.extend_from_slice(&[0xc0, 0x0c]);
        dns_payload.extend_from_slice(&1u16.to_be_bytes());
        dns_payload.extend_from_slice(&1u16.to_be_bytes());
        dns_payload.extend_from_slice(&300u32.to_be_bytes());
        dns_payload.extend_from_slice(&4u16.to_be_bytes());
        dns_payload.extend_from_slice(&ip_web);

        let udp = make_udp(53, 54321, &dns_payload);
        let ip = make_ipv4(ip_dns, ip_client, 17, udp.len() as u16);
        let mut pkt = make_eth(mac_router, mac_client, 0x0800);
        pkt.extend_from_slice(&ip);
        pkt.extend_from_slice(&udp);
        append_packet(&mut data, 1, 25000, &pkt);
    }

    // 5-7. TCP 3-Way Handshake: 192.168.1.10:49152 -> 93.184.216.34:80
    // SYN
    {
        let tcp = make_tcp(49152, 80, 1000, 0, 0x02, &[]);
        let ip = make_ipv4(ip_client, ip_web, 6, tcp.len() as u16);
        let mut pkt = make_eth(mac_client, mac_router, 0x0800);
        pkt.extend_from_slice(&ip);
        pkt.extend_from_slice(&tcp);
        append_packet(&mut data, 2, 50000, &pkt);
    }
    // SYN-ACK
    {
        let tcp = make_tcp(80, 49152, 5000, 1001, 0x12, &[]);
        let ip = make_ipv4(ip_web, ip_client, 6, tcp.len() as u16);
        let mut pkt = make_eth(mac_router, mac_client, 0x0800);
        pkt.extend_from_slice(&ip);
        pkt.extend_from_slice(&tcp);
        append_packet(&mut data, 2, 65000, &pkt);
    }
    // ACK
    {
        let tcp = make_tcp(49152, 80, 1001, 5001, 0x10, &[]);
        let ip = make_ipv4(ip_client, ip_web, 6, tcp.len() as u16);
        let mut pkt = make_eth(mac_client, mac_router, 0x0800);
        pkt.extend_from_slice(&ip);
        pkt.extend_from_slice(&tcp);
        append_packet(&mut data, 2, 70000, &pkt);
    }

    // 8. HTTP GET Request
    {
        let http_data = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: PacketScopeDemo/1.0\r\nAccept: */*\r\n\r\n";
        let tcp = make_tcp(49152, 80, 1001, 5001, 0x18, http_data); // PSH, ACK
        let ip = make_ipv4(ip_client, ip_web, 6, tcp.len() as u16);
        let mut pkt = make_eth(mac_client, mac_router, 0x0800);
        pkt.extend_from_slice(&ip);
        pkt.extend_from_slice(&tcp);
        append_packet(&mut data, 2, 75000, &pkt);
    }

    // 9. HTTP 200 OK Response
    {
        let http_resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 48\r\n\r\n<html><body><h1>PacketScope Demo</h1></body></html>";
        let tcp = make_tcp(80, 49152, 5001, 1001 + 82, 0x18, http_resp);
        let ip = make_ipv4(ip_web, ip_client, 6, tcp.len() as u16);
        let mut pkt = make_eth(mac_router, mac_client, 0x0800);
        pkt.extend_from_slice(&ip);
        pkt.extend_from_slice(&tcp);
        append_packet(&mut data, 2, 90000, &pkt);
    }

    // 10. ICMP Ping Request & Reply
    {
        let mut icmp_req = vec![8, 0, 0, 0, 0x12, 0x34, 0x00, 0x01];
        icmp_req.extend_from_slice(b"abcdefghijklmnopqrstuvwabcdefghi");
        let ip = make_ipv4(ip_client, ip_router, 1, icmp_req.len() as u16);
        let mut pkt = make_eth(mac_client, mac_router, 0x0800);
        pkt.extend_from_slice(&ip);
        pkt.extend_from_slice(&icmp_req);
        append_packet(&mut data, 3, 10000, &pkt);

        let mut icmp_rep = vec![0, 0, 0, 0, 0x12, 0x34, 0x00, 0x01];
        icmp_rep.extend_from_slice(b"abcdefghijklmnopqrstuvwabcdefghi");
        let ip_rep = make_ipv4(ip_router, ip_client, 1, icmp_rep.len() as u16);
        let mut pkt_rep = make_eth(mac_router, mac_client, 0x0800);
        pkt_rep.extend_from_slice(&ip_rep);
        pkt_rep.extend_from_slice(&icmp_rep);
        append_packet(&mut data, 3, 11000, &pkt_rep);
    }

    // 10b. Generic UDP: NTP (Port 123)
    {
        let ntp_data = [
            0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let udp = make_udp(51234, 123, &ntp_data);
        let ip = make_ipv4(ip_client, [129, 6, 15, 28], 17, udp.len() as u16);
        let mut pkt = make_eth(mac_client, mac_router, 0x0800);
        pkt.extend_from_slice(&ip);
        pkt.extend_from_slice(&udp);
        append_packet(&mut data, 3, 50000, &pkt);
    }

    // 11. DNS NXDOMAIN Query & Response (Triggers DNS error heuristic)
    for i in 0..4 {
        let domain_name = format!("nxdomain-test-{}.internal", i);
        let mut dns_q = Vec::new();
        let tx = (0x3344 + i) as u16;
        dns_q.extend_from_slice(&tx.to_be_bytes());
        dns_q.extend_from_slice(&0x0100u16.to_be_bytes());
        dns_q.extend_from_slice(&1u16.to_be_bytes());
        dns_q.extend_from_slice(&0u16.to_be_bytes());
        dns_q.extend_from_slice(&0u16.to_be_bytes());
        dns_q.extend_from_slice(&0u16.to_be_bytes());
        for part in domain_name.split('.') {
            dns_q.push(part.len() as u8);
            dns_q.extend_from_slice(part.as_bytes());
        }
        dns_q.push(0);
        dns_q.extend_from_slice(&1u16.to_be_bytes());
        dns_q.extend_from_slice(&1u16.to_be_bytes());

        let udp = make_udp(54322 + i as u16, 53, &dns_q);
        let ip = make_ipv4(ip_client, ip_dns, 17, udp.len() as u16);
        let mut pkt = make_eth(mac_client, mac_router, 0x0800);
        pkt.extend_from_slice(&ip);
        pkt.extend_from_slice(&udp);
        append_packet(&mut data, 4, 10000 + i * 2000, &pkt);

        // Response with RCODE 3 (NXDOMAIN)
        let mut dns_r = Vec::new();
        dns_r.extend_from_slice(&tx.to_be_bytes());
        dns_r.extend_from_slice(&0x8183u16.to_be_bytes()); // RCODE = 3 (NXDOMAIN)
        dns_r.extend_from_slice(&1u16.to_be_bytes());
        dns_r.extend_from_slice(&0u16.to_be_bytes());
        dns_r.extend_from_slice(&0u16.to_be_bytes());
        dns_r.extend_from_slice(&0u16.to_be_bytes());
        for part in domain_name.split('.') {
            dns_r.push(part.len() as u8);
            dns_r.extend_from_slice(part.as_bytes());
        }
        dns_r.push(0);
        dns_r.extend_from_slice(&1u16.to_be_bytes());
        dns_r.extend_from_slice(&1u16.to_be_bytes());

        let udp_r = make_udp(53, 54322 + i as u16, &dns_r);
        let ip_r = make_ipv4(ip_dns, ip_client, 17, udp_r.len() as u16);
        let mut pkt_r = make_eth(mac_router, mac_client, 0x0800);
        pkt_r.extend_from_slice(&ip_r);
        pkt_r.extend_from_slice(&udp_r);
        append_packet(&mut data, 4, 11000 + i * 2000, &pkt_r);
    }

    // 12. Repeated Unanswered SYN attempts from Scanner (Triggers Rule 3 & Fan-out)
    for port in [21, 22, 23, 25, 445, 1433, 3389, 8080, 8443, 9000] {
        let tcp = make_tcp(50000, port, 100, 0, 0x02, &[]); // SYN
        let ip = make_ipv4(ip_scanner, [192, 168, 1, 50], 6, tcp.len() as u16);
        let mut pkt = make_eth(mac_client, mac_router, 0x0800);
        pkt.extend_from_slice(&ip);
        pkt.extend_from_slice(&tcp);
        append_packet(&mut data, 5, 10000 + (port as u32) * 10, &pkt);

        // Also add RST for closed ports (Triggers Rule 4 TCP Reset Ratio)
        if port % 2 == 0 {
            let tcp_rst = make_tcp(port, 50000, 0, 101, 0x14, &[]); // RST, ACK
            let ip_rst = make_ipv4([192, 168, 1, 50], ip_scanner, 6, tcp_rst.len() as u16);
            let mut pkt_rst = make_eth(mac_router, mac_client, 0x0800);
            pkt_rst.extend_from_slice(&ip_rst);
            pkt_rst.extend_from_slice(&tcp_rst);
            append_packet(&mut data, 5, 10500 + (port as u32) * 10, &pkt_rst);
        }
    }

    // 13. Fan-out scanner sending probes to multiple IPs (Triggers Rule 2)
    for host_id in 20..32 {
        let target_ip = [192, 168, 1, host_id];
        let tcp = make_tcp(45000, 443, 200, 0, 0x02, &[]);
        let ip = make_ipv4(ip_scanner, target_ip, 6, tcp.len() as u16);
        let mut pkt = make_eth(mac_client, mac_router, 0x0800);
        pkt.extend_from_slice(&ip);
        pkt.extend_from_slice(&tcp);
        append_packet(&mut data, 6, (host_id as u32) * 1000, &pkt);
    }

    data
}

/// Loads and executes full local analysis on the demo capture dataset.
pub fn load_demo_analysis() -> Result<CaptureResult, CaptureError> {
    let demo_bytes = generate_demo_pcap();
    analyze_capture(&demo_bytes, "demo_network_traffic.pcap", None, |_, _| true)
}
