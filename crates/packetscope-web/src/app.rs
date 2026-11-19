use gloo_timers::future::TimeoutFuture;
use packetscope_core::{analyze_capture, load_demo_analysis, ReviewStatus, RuleConfig};
use wasm_bindgen_futures::spawn_local;
use yew::prelude::*;

use crate::components::{Header, Sidebar};
use crate::pages::*;
use crate::routes::AppRoute;
use crate::state::{AppState, Theme};

#[function_component(App)]
pub fn app() -> Html {
    let state = use_state(AppState::default);

    // Sync theme with document element
    {
        let theme = state.theme;
        use_effect_with(theme, move |t| {
            if let Some(window) = web_sys::window() {
                if let Some(doc) = window.document() {
                    if let Some(root) = doc.document_element() {
                        let val = match t {
                            Theme::Dark => "dark",
                            Theme::Light => "light",
                        };
                        let _ = root.set_attribute("data-theme", val);
                    }
                }
            }
            || ()
        });
    }

    // Hash navigation listener
    {
        let state_clone = state.clone();
        use_effect_with((), move |_| {
            let update_route_from_hash = {
                let state = state_clone.clone();
                move || {
                    if let Some(window) = web_sys::window() {
                        if let Ok(hash) = window.location().hash() {
                            let clean_hash = hash.trim_start_matches('#');
                            let route = match clean_hash {
                                "overview" => AppRoute::Overview,
                                "packets" => AppRoute::Packets,
                                "conversations" | "flows" => AppRoute::Conversations,
                                "hosts" => AppRoute::Hosts,
                                "protocols" => AppRoute::Protocols,
                                "dns" => AppRoute::DnsAnalytics,
                                "findings" => AppRoute::Findings,
                                "timeline" => AppRoute::Timeline,
                                "reports" => AppRoute::Reports,
                                "settings" => AppRoute::Settings,
                                _ => AppRoute::Import,
                            };
                            let mut new_state = (*state).clone();
                            new_state.current_route = route;
                            state.set(new_state);
                        }
                    }
                }
            };

            update_route_from_hash();
            || ()
        });
    }

    // Callbacks
    let on_route_change = {
        let state = state.clone();
        Callback::from(move |route: AppRoute| {
            let hash = match route {
                AppRoute::Overview => "#overview",
                AppRoute::Packets => "#packets",
                AppRoute::Conversations => "#conversations",
                AppRoute::Hosts => "#hosts",
                AppRoute::Protocols => "#protocols",
                AppRoute::DnsAnalytics => "#dns",
                AppRoute::Findings => "#findings",
                AppRoute::Timeline => "#timeline",
                AppRoute::Reports => "#reports",
                AppRoute::Settings => "#settings",
                AppRoute::Import => "#import",
            };
            if let Some(window) = web_sys::window() {
                let _ = window.location().set_hash(hash);
            }
            let mut new_state = (*state).clone();
            new_state.current_route = route;
            new_state.mobile_menu_open = false;
            state.set(new_state);
        })
    };

    let on_theme_toggle = {
        let state = state.clone();
        Callback::from(move |_| {
            let mut new_state = (*state).clone();
            new_state.theme = match new_state.theme {
                Theme::Dark => Theme::Light,
                Theme::Light => Theme::Dark,
            };
            state.set(new_state);
        })
    };

    let on_sidebar_collapse = {
        let state = state.clone();
        Callback::from(move |_| {
            let mut new_state = (*state).clone();
            new_state.sidebar_collapsed = !new_state.sidebar_collapsed;
            state.set(new_state);
        })
    };

    let on_mobile_toggle = {
        let state = state.clone();
        Callback::from(move |_| {
            let mut new_state = (*state).clone();
            new_state.mobile_menu_open = !new_state.mobile_menu_open;
            state.set(new_state);
        })
    };

    let on_search_change = {
        let state = state.clone();
        Callback::from(move |query: String| {
            let mut new_state = (*state).clone();
            new_state.global_search = query.clone();
            if !query.is_empty() {
                // If user typed in global search, set filter and switch to packets page
                new_state.filter_expression = format!(
                    "host == \"{}\" or protocol contains \"{}\" or dns.qname contains \"{}\"",
                    query, query, query
                );
                new_state.current_route = AppRoute::Packets;
            }
            state.set(new_state);
        })
    };

    let on_filter_packets = {
        let state = state.clone();
        Callback::from(move |filter: String| {
            let mut new_state = (*state).clone();
            new_state.filter_expression = filter;
            new_state.current_route = AppRoute::Packets;
            state.set(new_state);
        })
    };

    let on_packet_select = {
        let state = state.clone();
        Callback::from(move |idx: Option<u64>| {
            let mut new_state = (*state).clone();
            new_state.selected_packet_index = idx;
            state.set(new_state);
        })
    };

    let on_flow_select = {
        let state = state.clone();
        Callback::from(move |id: Option<String>| {
            let mut new_state = (*state).clone();
            new_state.selected_flow_id = id;
            state.set(new_state);
        })
    };

    let on_host_select = {
        let state = state.clone();
        Callback::from(move |ip: Option<String>| {
            let mut new_state = (*state).clone();
            new_state.selected_host_ip = ip;
            new_state.current_route = AppRoute::Hosts;
            state.set(new_state);
        })
    };

    let on_finding_select = {
        let state = state.clone();
        Callback::from(move |id: Option<String>| {
            let mut new_state = (*state).clone();
            new_state.selected_finding_id = id;
            state.set(new_state);
        })
    };

    let on_status_toggle = {
        let state = state.clone();
        Callback::from(move |finding_id: String| {
            let mut new_state = (*state).clone();
            if let Some(ref mut analysis) = new_state.analysis {
                if let Some(f) = analysis.findings.iter_mut().find(|f| f.id == finding_id) {
                    f.status = match f.status {
                        ReviewStatus::New => ReviewStatus::Reviewed,
                        ReviewStatus::Reviewed => ReviewStatus::New,
                    };
                }
            }
            state.set(new_state);
        })
    };

    let on_note_update = {
        let state = state.clone();
        Callback::from(move |(finding_id, note): (String, String)| {
            let mut new_state = (*state).clone();
            if let Some(ref mut analysis) = new_state.analysis {
                if let Some(f) = analysis.findings.iter_mut().find(|f| f.id == finding_id) {
                    f.notes = note;
                }
            }
            state.set(new_state);
        })
    };

    let on_rule_config_update = {
        let state = state.clone();
        Callback::from(move |cfg: RuleConfig| {
            let mut new_state = (*state).clone();
            new_state.rule_config = cfg;
            state.set(new_state);
        })
    };

    let on_clear_data = {
        let state = state.clone();
        Callback::from(move |_| {
            let new_state = AppState {
                theme: state.theme,
                ..AppState::default()
            };
            state.set(new_state);
        })
    };

    // Load Demo Data
    let on_load_demo = {
        let state = state.clone();
        Callback::from(move |_| {
            let mut s = (*state).clone();
            s.is_analyzing = true;
            s.analysis_progress = 0.2;
            s.analysis_stage = "Generating demo network capture...".to_string();
            state.set(s);

            let state_c = state.clone();
            spawn_local(async move {
                TimeoutFuture::new(50).await;
                match load_demo_analysis() {
                    Ok(result) => {
                        let mut new_s = (*state_c).clone();
                        new_s.analysis = Some(result);
                        new_s.is_demo = true;
                        new_s.is_analyzing = false;
                        new_s.analysis_progress = 1.0;
                        new_s.current_route = AppRoute::Overview;
                        state_c.set(new_s);
                    }
                    Err(e) => {
                        let mut new_s = (*state_c).clone();
                        new_s.is_analyzing = false;
                        new_s.error_message = Some(e.to_string());
                        state_c.set(new_s);
                    }
                }
            });
        })
    };

    // File loaded handler
    let on_file_loaded = {
        let state = state.clone();
        Callback::from(move |(filename, bytes): (String, Vec<u8>)| {
            let mut s = (*state).clone();
            s.is_analyzing = true;
            s.analysis_progress = 0.1;
            s.analysis_stage = format!("Reading {} ({} bytes)...", filename, bytes.len());
            s.error_message = None;
            state.set(s);

            let state_c = state.clone();
            let rule_cfg = state.rule_config.clone();

            spawn_local(async move {
                TimeoutFuture::new(50).await;
                let fname = filename.clone();
                let res = analyze_capture(&bytes, &fname, Some(rule_cfg), |_, _| true);
                match res {
                    Ok(result) => {
                        let mut new_s = (*state_c).clone();
                        new_s.analysis = Some(result);
                        new_s.is_demo = false;
                        new_s.is_analyzing = false;
                        new_s.analysis_progress = 1.0;
                        new_s.current_route = AppRoute::Overview;
                        state_c.set(new_s);
                    }
                    Err(e) => {
                        let mut new_s = (*state_c).clone();
                        new_s.is_analyzing = false;
                        new_s.error_message = Some(e.to_string());
                        state_c.set(new_s);
                    }
                }
            });
        })
    };

    let capture_name = state.analysis.as_ref().map(|a| a.summary.filename.clone());
    let has_capture = state.analysis.is_some();
    let content_collapsed_class = if state.sidebar_collapsed {
        "content-area collapsed"
    } else {
        "content-area"
    };

    html! {
        <div class="app-container">
            <Header
                capture_name={capture_name}
                is_demo={state.is_demo}
                theme={state.theme}
                on_theme_toggle={on_theme_toggle.clone()}
                on_route_change={on_route_change.clone()}
                on_mobile_toggle={on_mobile_toggle}
                search_query={state.global_search.clone()}
                on_search_change={on_search_change}
            />

            <div class="main-layout">
                <Sidebar
                    current_route={state.current_route}
                    has_capture={has_capture}
                    is_collapsed={state.sidebar_collapsed}
                    is_mobile_open={state.mobile_menu_open}
                    on_route_change={on_route_change.clone()}
                    on_toggle_collapse={on_sidebar_collapse}
                />

                <main class={content_collapsed_class}>
                    {
                        match (state.current_route, state.analysis.as_ref()) {
                            (AppRoute::Import, _) | (_, None) => html! {
                                <ImportPage
                                    is_analyzing={state.is_analyzing}
                                    progress={state.analysis_progress}
                                    stage={state.analysis_stage.clone()}
                                    error_message={state.error_message.clone()}
                                    on_file_loaded={on_file_loaded}
                                    on_load_demo={on_load_demo}
                                />
                            },
                            (AppRoute::Overview, Some(analysis)) => html! {
                                <OverviewPage
                                    analysis={analysis.clone()}
                                    on_route_change={on_route_change.clone()}
                                    on_host_select={on_host_select.clone().reform(Some)}
                                />
                            },
                            (AppRoute::Packets, Some(analysis)) => html! {
                                <PacketsPage
                                    packets={analysis.packets.clone()}
                                    selected_packet_index={state.selected_packet_index}
                                    on_packet_select={on_packet_select}
                                    global_filter={state.filter_expression.clone()}
                                />
                            },
                            (AppRoute::Conversations, Some(analysis)) => html! {
                                <FlowsPage
                                    flows={analysis.flows.clone()}
                                    selected_flow_id={state.selected_flow_id.clone()}
                                    on_flow_select={on_flow_select}
                                    on_filter_packets={on_filter_packets.clone()}
                                />
                            },
                            (AppRoute::Hosts, Some(analysis)) => html! {
                                <HostsPage
                                    hosts={analysis.hosts.clone()}
                                    selected_host_ip={state.selected_host_ip.clone()}
                                    on_host_select={on_host_select}
                                    on_filter_packets={on_filter_packets.clone()}
                                />
                            },
                            (AppRoute::Protocols, Some(analysis)) => html! {
                                <ProtocolsPage
                                    protocols={analysis.protocols.clone()}
                                    ports={analysis.ports.clone()}
                                    on_filter_packets={on_filter_packets.clone()}
                                />
                            },
                            (AppRoute::DnsAnalytics, Some(analysis)) => html! {
                                <DnsPage
                                    dns_records={analysis.dns_records.clone()}
                                    on_filter_packets={on_filter_packets.clone()}
                                />
                            },
                            (AppRoute::Findings, Some(analysis)) => html! {
                                <FindingsPage
                                    findings={analysis.findings.clone()}
                                    selected_finding_id={state.selected_finding_id.clone()}
                                    on_finding_select={on_finding_select}
                                    on_status_toggle={on_status_toggle}
                                    on_note_update={on_note_update}
                                    on_filter_packets={on_filter_packets.clone()}
                                />
                            },
                            (AppRoute::Timeline, Some(analysis)) => html! {
                                <TimelinePage
                                    timeline={analysis.timeline.clone()}
                                    hosts={analysis.hosts.clone()}
                                    flows={analysis.flows.clone()}
                                    on_host_select={on_host_select.clone().reform(Some)}
                                />
                            },
                            (AppRoute::Reports, Some(analysis)) => html! {
                                <ReportsPage
                                    analysis={analysis.clone()}
                                />
                            },
                            (AppRoute::Settings, _) => html! {
                                <SettingsPage
                                    theme={state.theme}
                                    on_theme_toggle={on_theme_toggle}
                                    rule_config={state.rule_config.clone()}
                                    on_rule_config_update={on_rule_config_update}
                                    on_clear_data={on_clear_data}
                                />
                            },
                        }
                    }
                </main>
            </div>
        </div>
    }
}
