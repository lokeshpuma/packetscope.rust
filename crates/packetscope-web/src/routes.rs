use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AppRoute {
    Import,
    Overview,
    Packets,
    Conversations,
    Hosts,
    Protocols,
    DnsAnalytics,
    Findings,
    Timeline,
    Reports,
    Settings,
}

impl AppRoute {
    pub fn title(&self) -> &'static str {
        match self {
            AppRoute::Import => "Import Capture",
            AppRoute::Overview => "Overview",
            AppRoute::Packets => "Packet Explorer",
            AppRoute::Conversations => "Conversations & Flows",
            AppRoute::Hosts => "Host Inventory",
            AppRoute::Protocols => "Protocol Analytics",
            AppRoute::DnsAnalytics => "DNS Analytics",
            AppRoute::Findings => "Findings & Anomalies",
            AppRoute::Timeline => "Traffic Timeline",
            AppRoute::Reports => "Reports & Export",
            AppRoute::Settings => "Settings",
        }
    }
}
