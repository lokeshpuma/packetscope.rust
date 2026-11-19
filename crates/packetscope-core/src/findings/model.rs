use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FindingSeverity {
    Info,
    Low,
    Medium,
    High,
}

impl FindingSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            FindingSeverity::Info => "Info",
            FindingSeverity::Low => "Low",
            FindingSeverity::Medium => "Medium",
            FindingSeverity::High => "High",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReviewStatus {
    New,
    Reviewed,
}

impl ReviewStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            ReviewStatus::New => "New",
            ReviewStatus::Reviewed => "Reviewed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub severity: FindingSeverity,
    pub category: String,
    pub affected_host: Option<String>,
    pub first_seen_iso: String,
    pub last_seen_iso: String,
    pub status: ReviewStatus,
    pub rule_name: String,
    pub configured_threshold: String,
    pub observed_value: String,
    pub what_happened: String,
    pub why_flagged: String,
    pub affected_conversations: Vec<String>,
    pub related_packets: Vec<u64>,
    pub investigation_steps: Vec<String>,
    pub notes: String,
}
