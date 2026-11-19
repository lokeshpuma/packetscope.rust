pub mod capture;
pub mod demo;
pub mod errors;
pub mod export;
pub mod filters;
pub mod findings;
pub mod flow;
pub mod format;
pub mod host;
pub mod packet;
pub mod protocols;
pub mod statistics;
pub mod timeline;

pub use capture::{analyze_capture, format_timestamp, CaptureResult};
pub use demo::{generate_demo_pcap, load_demo_analysis};
pub use errors::{CaptureError, FilterError};
pub use export::{
    export_analysis_json, export_findings_csv, export_flows_csv, export_hosts_csv,
    export_html_report, export_packets_csv, sanitize_csv_cell, AnalysisReport,
};
pub use filters::{get_filter_completions, parse_filter, CompOp, Expr, Value, FILTER_SUGGESTIONS};
pub use findings::{evaluate_findings, Finding, FindingSeverity, ReviewStatus, RuleConfig};
pub use flow::{FlowKey, NetworkFlow};
pub use format::{detect_format, CaptureFormat, Endianness, TimestampPrecision};
pub use host::HostRecord;
pub use packet::{LayerField, PacketRecord, ProtocolLayer, TcpFlagsSummary};
pub use protocols::dns::DnsRecord;
pub use statistics::{CaptureSummary, PortStat, ProtocolStat};
pub use timeline::{TimelineAnalysis, TimelineBucket};

pub fn version() -> &'static str {
    "0.1.0"
}
