use crate::routes::AppRoute;
use packetscope_core::{CaptureResult, RuleConfig};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Theme {
    Dark,
    Light,
}

#[derive(Debug, Clone)]
pub struct AppState {
    pub current_route: AppRoute,
    pub analysis: Option<CaptureResult>,
    pub is_demo: bool,
    pub is_analyzing: bool,
    pub analysis_progress: f64,
    pub analysis_stage: String,
    pub theme: Theme,
    pub sidebar_collapsed: bool,
    pub mobile_menu_open: bool,
    pub global_search: String,
    pub filter_expression: String,
    pub selected_packet_index: Option<u64>,
    pub selected_flow_id: Option<String>,
    pub selected_host_ip: Option<String>,
    pub selected_finding_id: Option<String>,
    pub error_message: Option<String>,
    pub rule_config: RuleConfig,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            current_route: AppRoute::Import,
            analysis: None,
            is_demo: false,
            is_analyzing: false,
            analysis_progress: 0.0,
            analysis_stage: String::new(),
            theme: Theme::Dark,
            sidebar_collapsed: false,
            mobile_menu_open: false,
            global_search: String::new(),
            filter_expression: String::new(),
            selected_packet_index: None,
            selected_flow_id: None,
            selected_host_ip: None,
            selected_finding_id: None,
            error_message: None,
            rule_config: RuleConfig::default(),
        }
    }
}
