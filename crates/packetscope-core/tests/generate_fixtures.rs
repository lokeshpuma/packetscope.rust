use packetscope_core::*;
use std::fs::File;
use std::io::Write;

#[test]
fn generate_all_fixtures() {
    // 1. Valid sample.pcap
    let pcap_bytes = generate_demo_pcap();
    let mut f = File::create("../../fixtures/valid/sample.pcap").expect("create sample.pcap");
    f.write_all(&pcap_bytes).expect("write sample.pcap");

    // 2. Valid sample.pcapng
    let mut pcapng_bytes = Vec::new();
    // SHB
    pcapng_bytes.extend_from_slice(&0x0A0D0D0Au32.to_le_bytes());
    pcapng_bytes.extend_from_slice(&28u32.to_le_bytes());
    pcapng_bytes.extend_from_slice(&0x1A2B3C4Du32.to_le_bytes());
    pcapng_bytes.extend_from_slice(&1u16.to_le_bytes());
    pcapng_bytes.extend_from_slice(&0u16.to_le_bytes());
    pcapng_bytes.extend_from_slice(&(-1i64).to_le_bytes());
    pcapng_bytes.extend_from_slice(&28u32.to_le_bytes());
    // IDB
    pcapng_bytes.extend_from_slice(&0x00000001u32.to_le_bytes());
    pcapng_bytes.extend_from_slice(&20u32.to_le_bytes());
    pcapng_bytes.extend_from_slice(&1u16.to_le_bytes());
    pcapng_bytes.extend_from_slice(&0u16.to_le_bytes());
    pcapng_bytes.extend_from_slice(&65535u32.to_le_bytes());
    pcapng_bytes.extend_from_slice(&20u32.to_le_bytes());
    // EPB
    pcapng_bytes.extend_from_slice(&0x00000006u32.to_le_bytes());
    pcapng_bytes.extend_from_slice(&48u32.to_le_bytes());
    pcapng_bytes.extend_from_slice(&0u32.to_le_bytes());
    pcapng_bytes.extend_from_slice(&0u32.to_le_bytes());
    pcapng_bytes.extend_from_slice(&1000u32.to_le_bytes());
    pcapng_bytes.extend_from_slice(&14u32.to_le_bytes());
    pcapng_bytes.extend_from_slice(&14u32.to_le_bytes());
    pcapng_bytes.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    pcapng_bytes.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    pcapng_bytes.extend_from_slice(&[0x08, 0x06]);
    pcapng_bytes.extend_from_slice(&[0x00, 0x00]);
    pcapng_bytes.extend_from_slice(&48u32.to_le_bytes());

    let mut f_ng =
        File::create("../../fixtures/valid/sample.pcapng").expect("create sample.pcapng");
    f_ng.write_all(&pcapng_bytes).expect("write sample.pcapng");

    // 3. Malformed corrupted_header.pcap
    let mut f_bad = File::create("../../fixtures/malformed/corrupted_header.pcap")
        .expect("create corrupted_header.pcap");
    f_bad
        .write_all(&[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07])
        .expect("write bad");

    // 4. Malformed truncated_packet.pcap
    let mut trunc_pcap = Vec::new();
    trunc_pcap.extend_from_slice(&pcap_bytes[..40]); // truncated in the middle of first packet
    let mut f_trunc = File::create("../../fixtures/malformed/truncated_packet.pcap")
        .expect("create truncated_packet.pcap");
    f_trunc.write_all(&trunc_pcap).expect("write trunc");

    // 5. Expected result JSON summary
    let result = load_demo_analysis().expect("analysis");
    let report = result.to_analysis_report();
    let json = export_analysis_json(&report).expect("export json");
    let mut f_json = File::create("../../fixtures/expected-results/demo_summary.json")
        .expect("create demo_summary.json");
    f_json.write_all(json.as_bytes()).expect("write json");
}
