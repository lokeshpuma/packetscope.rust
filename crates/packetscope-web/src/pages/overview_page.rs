use crate::components::{HostGraph, TimelineChart};
use crate::routes::AppRoute;
use packetscope_core::CaptureResult;
use yew::prelude::*;

#[derive(Properties, PartialEq)]
pub struct OverviewPageProps {
    pub analysis: CaptureResult,
    pub on_route_change: Callback<AppRoute>,
    pub on_host_select: Callback<String>,
}

#[function_component(OverviewPage)]
pub fn overview_page(props: &OverviewPageProps) -> Html {
    let summary = &props.analysis.summary;

    let nav_to_packets = {
        let cb = props.on_route_change.clone();
        Callback::from(move |_| cb.emit(AppRoute::Packets))
    };
    let nav_to_flows = {
        let cb = props.on_route_change.clone();
        Callback::from(move |_| cb.emit(AppRoute::Conversations))
    };
    let nav_to_hosts = {
        let cb = props.on_route_change.clone();
        Callback::from(move |_| cb.emit(AppRoute::Hosts))
    };
    let nav_to_findings = {
        let cb = props.on_route_change.clone();
        Callback::from(move |_| cb.emit(AppRoute::Findings))
    };

    html! {
        <div>
            <div class="metrics-grid">
                <div class="metric-card" onclick={nav_to_packets} style="cursor: pointer;">
                    <span class="metric-title">{ "Total Packets" }</span>
                    <span class="metric-value">{ summary.packet_count }</span>
                    <span class="metric-sub">{ format!("Link: {}", summary.link_type_name) }</span>
                </div>
                <div class="metric-card">
                    <span class="metric-title">{ "Total Traffic Volume" }</span>
                    <span class="metric-value">
                        {
                            if summary.total_bytes >= 1_048_576 {
                                format!("{:.2} MB", summary.total_bytes as f64 / 1_048_576.0)
                            } else {
                                format!("{:.1} KB", summary.total_bytes as f64 / 1024.0)
                            }
                        }
                    </span>
                    <span class="metric-sub">{ format!("{} bytes", summary.total_bytes) }</span>
                </div>
                <div class="metric-card" onclick={nav_to_hosts.clone()} style="cursor: pointer;">
                    <span class="metric-title">{ "Unique Hosts" }</span>
                    <span class="metric-value">{ summary.host_count }</span>
                    <span class="metric-sub">{ "Observed endpoints" }</span>
                </div>
                <div class="metric-card" onclick={nav_to_flows} style="cursor: pointer;">
                    <span class="metric-title">{ "Conversations / Flows" }</span>
                    <span class="metric-value">{ summary.flow_count }</span>
                    <span class="metric-sub">{ "Bidirectional 5-tuples" }</span>
                </div>
                <div class="metric-card">
                    <span class="metric-title">{ "Capture Duration" }</span>
                    <span class="metric-value">{ format!("{:.2}s", summary.duration_seconds) }</span>
                    <span class="metric-sub">{ format!("Format: {}", summary.format_name) }</span>
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">{ "Network Traffic Timeline (Packets/sec)" }</h3>
                    <span style="font-size: 12px; color: var(--text-muted);">
                        { format!("Resolution: {:.1}s buckets | Peak: {:.1} pps", props.analysis.timeline.bucket_resolution_seconds, props.analysis.timeline.max_pps) }
                    </span>
                </div>
                <TimelineChart timeline={props.analysis.timeline.clone()} />
            </div>

            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(360px, 1fr)); gap: 24px; margin-bottom: 24px;">
                <div class="card" style="margin-bottom: 0;">
                    <div class="card-header">
                        <h3 class="card-title">{ "Host Communication Topology" }</h3>
                        <span style="font-size: 12px; color: var(--text-muted);">{ "Top communicating nodes" }</span>
                    </div>
                    <HostGraph
                        hosts={props.analysis.hosts.clone()}
                        flows={props.analysis.flows.clone()}
                        on_host_select={props.on_host_select.clone()}
                    />
                </div>

                <div class="card" style="margin-bottom: 0;">
                    <div class="card-header">
                        <h3 class="card-title">{ "Protocol Breakdown" }</h3>
                        <button class="btn btn-secondary btn-sm" onclick={
                            let cb = props.on_route_change.clone();
                            Callback::from(move |_| cb.emit(AppRoute::Protocols))
                        }>
                            { "View All" }
                        </button>
                    </div>
                    <div class="table-container">
                        <table class="data-table">
                            <thead>
                                <tr>
                                    <th>{ "Protocol" }</th>
                                    <th>{ "Packets" }</th>
                                    <th>{ "Volume" }</th>
                                    <th>{ "Share" }</th>
                                </tr>
                            </thead>
                            <tbody>
                                {
                                    for props.analysis.protocols.iter().take(6).map(|proto| {
                                        html! {
                                            <tr>
                                                <td><span class="badge badge-info">{ &proto.name }</span></td>
                                                <td>{ proto.packet_count }</td>
                                                <td>{ format!("{:.1} KB", proto.byte_count as f64 / 1024.0) }</td>
                                                <td>
                                                    <div style="display: flex; align-items: center; gap: 8px;">
                                                        <div style="flex: 1; height: 6px; background: var(--bg-input); border-radius: 3px; overflow: hidden; width: 60px;">
                                                            <div style={format!("height: 100%; background: var(--accent-blue); width: {:.0}%;", proto.percentage_bytes)}></div>
                                                        </div>
                                                        <span style="font-size: 11px; font-family: var(--font-mono);">{ format!("{:.1}%", proto.percentage_bytes) }</span>
                                                    </div>
                                                </td>
                                            </tr>
                                        }
                                    })
                                }
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(360px, 1fr)); gap: 24px;">
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">{ "Top Talkers (By Total Bytes)" }</h3>
                        <button class="btn btn-secondary btn-sm" onclick={nav_to_hosts}>
                            { "All Hosts" }
                        </button>
                    </div>
                    <div class="table-container">
                        <table class="data-table">
                            <thead>
                                <tr>
                                    <th>{ "IP Address" }</th>
                                    <th>{ "Packets" }</th>
                                    <th>{ "Volume" }</th>
                                    <th>{ "Peers" }</th>
                                </tr>
                            </thead>
                            <tbody>
                                {
                                    for props.analysis.hosts.iter().take(5).map(|h| {
                                        let ip = h.ip.clone();
                                        let on_click = {
                                            let cb = props.on_host_select.clone();
                                            let ip_c = ip.clone();
                                            Callback::from(move |_| cb.emit(ip_c.clone()))
                                        };
                                        html! {
                                            <tr onclick={on_click}>
                                                <td class="mono-cell" style="color: var(--accent-blue); font-weight: 600;">{ &h.ip }</td>
                                                <td>{ h.packets_sent + h.packets_received }</td>
                                                <td>{ format!("{:.1} KB", h.total_bytes as f64 / 1024.0) }</td>
                                                <td>{ h.peer_count }</td>
                                            </tr>
                                        }
                                    })
                                }
                            </tbody>
                        </table>
                    </div>
                </div>

                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">{ "Heuristic Findings & Observations" }</h3>
                        <button class="btn btn-secondary btn-sm" onclick={nav_to_findings}>
                            { "View All" }
                        </button>
                    </div>
                    {
                        if props.analysis.findings.is_empty() {
                            html! {
                                <div style="text-align: center; padding: 24px; color: var(--text-muted); font-size: 13px;">
                                    { "No suspicious or anomalous traffic patterns detected." }
                                </div>
                            }
                        } else {
                            html! {
                                <div class="table-container">
                                    <table class="data-table">
                                        <thead>
                                            <tr>
                                                <th>{ "Severity" }</th>
                                                <th>{ "Finding" }</th>
                                                <th>{ "Host" }</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {
                                                for props.analysis.findings.iter().take(4).map(|f| {
                                                    let badge_cls = match f.severity.as_str() {
                                                        "High" => "badge-high",
                                                        "Medium" => "badge-medium",
                                                        "Low" => "badge-low",
                                                        _ => "badge-info",
                                                    };
                                                    html! {
                                                        <tr>
                                                            <td><span class={classes!("badge", badge_cls)}>{ f.severity.as_str() }</span></td>
                                                            <td>
                                                                <strong style="font-size: 13px;">{ &f.title }</strong>
                                                            </td>
                                                            <td class="mono-cell">{ f.affected_host.as_deref().unwrap_or("Network") }</td>
                                                        </tr>
                                                    }
                                                })
                                            }
                                        </tbody>
                                    </table>
                                </div>
                            }
                        }
                    }
                </div>
            </div>
        </div>
    }
}
