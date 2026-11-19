pub mod lexer;
pub mod parser;

pub use parser::{parse_filter, CompOp, Expr, Value};

pub const FILTER_SUGGESTIONS: &[&str] = &[
    "ip.src == 192.168.1.1",
    "ip.dst == 10.0.0.1",
    "host == 192.168.1.1",
    "tcp.port == 443",
    "tcp.port == 80",
    "udp.port == 53",
    "protocol == \"TCP\"",
    "protocol == \"UDP\"",
    "protocol == \"DNS\"",
    "protocol == \"HTTP\"",
    "frame.len > 1000",
    "tcp.flags.syn == true",
    "tcp.flags.rst == true",
    "dns.qname contains \"google\"",
    "ip.src == 192.168.1.1 and tcp.flags.syn == true",
];

pub fn get_filter_completions(prefix: &str) -> Vec<String> {
    let lower = prefix.trim().to_lowercase();
    FILTER_SUGGESTIONS
        .iter()
        .filter(|s| s.to_lowercase().contains(&lower) || lower.is_empty())
        .map(|s| s.to_string())
        .collect()
}
