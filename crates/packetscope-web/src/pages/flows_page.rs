use packetscope_core::NetworkFlow;
use yew::prelude::*;

#[derive(Properties, PartialEq)]
pub struct FlowsPageProps {
    pub flows: Vec<NetworkFlow>,
    pub selected_flow_id: Option<String>,
    pub on_flow_select: Callback<Option<String>>,
    pub on_filter_packets: Callback<String>,
}

#[function_component(FlowsPage)]
pub fn flows_page(props: &FlowsPageProps) -> Html {
    let search_term = use_state(String::new);
    let sort_by = use_state(|| "bytes"); // "bytes", "packets", "duration"

    let filtered_flows = use_memo(
        (props.flows.clone(), (*search_term).clone(), (*sort_by)),
        |(flows, term, sort)| {
            let mut result: Vec<NetworkFlow> = if term.is_empty() {
                flows.clone()
            } else {
                let lower = term.to_lowercase();
                flows
                    .iter()
                    .filter(|f| {
                        f.endpoint_a.contains(&lower)
                            || f.endpoint_b.contains(&lower)
                            || f.protocol.to_lowercase().contains(&lower)
                            || f.port_a.to_string().contains(&lower)
                            || f.port_b.to_string().contains(&lower)
                    })
                    .cloned()
                    .collect()
            };

            match *sort {
                "packets" => result.sort_by_key(|a| std::cmp::Reverse(a.packet_count)),
                "duration" => result.sort_by(|a, b| {
                    b.duration_seconds
                        .partial_cmp(&a.duration_seconds)
                        .unwrap_or(std::cmp::Ordering::Equal)
                }),
                _ => result.sort_by_key(|a| std::cmp::Reverse(a.total_bytes)),
            }
            result
        },
    );

    let selected_flow = props
        .selected_flow_id
        .as_ref()
        .and_then(|id| props.flows.iter().find(|f| f.id == *id).cloned());

    let on_search_input = {
        let search_term = search_term.clone();
        Callback::from(move |e: InputEvent| {
            if let Some(target) = e.target_dyn_into::<web_sys::HtmlInputElement>() {
                search_term.set(target.value());
            }
        })
    };

    let close_drawer = {
        let cb = props.on_flow_select.clone();
        Callback::from(move |_| cb.emit(None))
    };

    html! {
        <div>
            <div style="display: flex; align-items: center; justify-content: space-between; gap: 16px; margin-bottom: 20px; flex-wrap: wrap;">
                <input
                    type="text"
                    class="filter-input"
                    placeholder="Search conversations by IP or port..."
                    style="max-width: 360px;"
                    value={(*search_term).clone()}
                    oninput={on_search_input}
                />

                <div style="display: flex; align-items: center; gap: 8px;">
                    <span style="font-size: 13px; color: var(--text-muted);">{ "Sort by:" }</span>
                    <button
                        class={classes!("btn", "btn-sm", if *sort_by == "bytes" { "btn-primary" } else { "btn-secondary" })}
                        onclick={
                            let s = sort_by.clone();
                            Callback::from(move |_| s.set("bytes"))
                        }
                    >
                        { "Bytes" }
                    </button>
                    <button
                        class={classes!("btn", "btn-sm", if *sort_by == "packets" { "btn-primary" } else { "btn-secondary" })}
                        onclick={
                            let s = sort_by.clone();
                            Callback::from(move |_| s.set("packets"))
                        }
                    >
                        { "Packets" }
                    </button>
                    <button
                        class={classes!("btn", "btn-sm", if *sort_by == "duration" { "btn-primary" } else { "btn-secondary" })}
                        onclick={
                            let s = sort_by.clone();
                            Callback::from(move |_| s.set("duration"))
                        }
                    >
                        { "Duration" }
                    </button>
                </div>
            </div>

            <div class="table-container">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>{ "Protocol" }</th>
                            <th>{ "Endpoint A" }</th>
                            <th>{ "Port A" }</th>
                            <th>{ "Endpoint B" }</th>
                            <th>{ "Port B" }</th>
                            <th>{ "Packets" }</th>
                            <th>{ "Volume" }</th>
                            <th>{ "Duration" }</th>
                            <th>{ "TCP Handshake / State" }</th>
                        </tr>
                    </thead>
                    <tbody>
                        {
                            if filtered_flows.is_empty() {
                                html! {
                                    <tr>
                                        <td colspan="9" style="text-align: center; padding: 40px; color: var(--text-muted);">
                                            { "No network conversations found." }
                                        </td>
                                    </tr>
                                }
                            } else {
                                html! {
                                    {
                                        for filtered_flows.iter().map(|flow| {
                                            let is_selected = props.selected_flow_id.as_deref() == Some(&flow.id);
                                            let row_class = if is_selected { "selected" } else { "" };
                                            let id = flow.id.clone();
                                            let on_click = {
                                                let cb = props.on_flow_select.clone();
                                                let id_c = id.clone();
                                                Callback::from(move |_| cb.emit(Some(id_c.clone())))
                                            };

                                            let vol_str = if flow.total_bytes >= 1_048_576 {
                                                format!("{:.2} MB", flow.total_bytes as f64 / 1_048_576.0)
                                            } else {
                                                format!("{:.1} KB", flow.total_bytes as f64 / 1024.0)
                                            };

                                            html! {
                                                <tr class={row_class} onclick={on_click}>
                                                    <td><span class="badge badge-info">{ &flow.protocol }</span></td>
                                                    <td class="mono-cell" style="color: var(--accent-blue); font-weight: 600;">{ &flow.endpoint_a }</td>
                                                    <td class="mono-cell">{ flow.port_a }</td>
                                                    <td class="mono-cell" style="color: var(--accent-blue); font-weight: 600;">{ &flow.endpoint_b }</td>
                                                    <td class="mono-cell">{ flow.port_b }</td>
                                                    <td class="mono-cell">{ flow.packet_count }</td>
                                                    <td class="mono-cell">{ vol_str }</td>
                                                    <td class="mono-cell">{ format!("{:.2}s", flow.duration_seconds) }</td>
                                                    <td style="font-size: 12px; color: var(--text-secondary);">{ &flow.handshake_summary }</td>
                                                </tr>
                                            }
                                        })
                                    }
                                }
                            }
                        }
                    </tbody>
                </table>
            </div>

            {
                if let Some(f) = selected_flow {
                    let on_filter_click = {
                        let cb = props.on_filter_packets.clone();
                        let filter_expr = format!("(ip.src == {} and ip.dst == {}) or (ip.src == {} and ip.dst == {})", f.endpoint_a, f.endpoint_b, f.endpoint_b, f.endpoint_a);
                        Callback::from(move |_| cb.emit(filter_expr.clone()))
                    };

                    html! {
                        <div class="detail-drawer">
                            <div class="drawer-header">
                                <div>
                                    <h3 style="font-size: 18px; font-weight: 700; color: var(--text-primary);">
                                        { format!("Flow: {} ↔ {}", f.endpoint_a, f.endpoint_b) }
                                    </h3>
                                    <span style="font-size: 12px; color: var(--text-muted); font-family: var(--font-mono);">
                                        { format!("{} | Ports: {} ↔ {}", f.protocol, f.port_a, f.port_b) }
                                    </span>
                                </div>
                                <button class="btn btn-secondary btn-sm" onclick={close_drawer}>
                                    { "✕" }
                                </button>
                            </div>

                            <button class="btn btn-primary" onclick={on_filter_click}>
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"></polygon>
                                </svg>
                                <span>{ "Inspect Related Packets" }</span>
                            </button>

                            <div class="card" style="margin-bottom: 0;">
                                <h4 style="font-size: 14px; font-weight: 600; color: var(--text-primary); margin-bottom: 12px;">
                                    { "Traffic Statistics" }
                                </h4>
                                <div style="display: flex; flex-direction: column; gap: 8px; font-size: 13px;">
                                    <div style="display: flex; justify-content: space-between;">
                                        <span style="color: var(--text-muted);">{ "Total Packets:" }</span>
                                        <span class="mono-cell">{ f.packet_count }</span>
                                    </div>
                                    <div style="display: flex; justify-content: space-between;">
                                        <span style="color: var(--text-muted);">{ "Total Bytes:" }</span>
                                        <span class="mono-cell">{ f.total_bytes }</span>
                                    </div>
                                    <div style="display: flex; justify-content: space-between;">
                                        <span style="color: var(--text-muted);">{ "Duration:" }</span>
                                        <span class="mono-cell">{ format!("{:.4} seconds", f.duration_seconds) }</span>
                                    </div>
                                    <div style="display: flex; justify-content: space-between;">
                                        <span style="color: var(--text-muted);">{ "Start Time:" }</span>
                                        <span class="mono-cell" style="font-size: 11px;">{ &f.start_time_iso }</span>
                                    </div>
                                    <div style="display: flex; justify-content: space-between;">
                                        <span style="color: var(--text-muted);">{ "End Time:" }</span>
                                        <span class="mono-cell" style="font-size: 11px;">{ &f.end_time_iso }</span>
                                    </div>
                                </div>
                            </div>

                            <div class="card" style="margin-bottom: 0;">
                                <h4 style="font-size: 14px; font-weight: 600; color: var(--text-primary); margin-bottom: 12px;">
                                    { "Directional Split" }
                                </h4>
                                <div style="display: flex; flex-direction: column; gap: 10px; font-size: 13px;">
                                    <div>
                                        <div style="display: flex; justify-content: space-between; margin-bottom: 4px;">
                                            <span>{ format!("{} → {}", f.endpoint_a, f.endpoint_b) }</span>
                                            <span class="mono-cell">{ format!("{} pkts ({} B)", f.forward_packets, f.forward_bytes) }</span>
                                        </div>
                                        <div style="height: 6px; background: var(--bg-input); border-radius: 3px; overflow: hidden;">
                                            <div style={format!("height: 100%; background: #38bdf8; width: {:.0}%;", if f.total_bytes > 0 { (f.forward_bytes as f64 / f.total_bytes as f64) * 100.0 } else { 0.0 })}></div>
                                        </div>
                                    </div>
                                    <div>
                                        <div style="display: flex; justify-content: space-between; margin-bottom: 4px;">
                                            <span>{ format!("{} → {}", f.endpoint_b, f.endpoint_a) }</span>
                                            <span class="mono-cell">{ format!("{} pkts ({} B)", f.reverse_packets, f.reverse_bytes) }</span>
                                        </div>
                                        <div style="height: 6px; background: var(--bg-input); border-radius: 3px; overflow: hidden;">
                                            <div style={format!("height: 100%; background: #06b6d4; width: {:.0}%;", if f.total_bytes > 0 { (f.reverse_bytes as f64 / f.total_bytes as f64) * 100.0 } else { 0.0 })}></div>
                                        </div>
                                    </div>
                                </div>
                            </div>

                            <div class="card" style="margin-bottom: 0;">
                                <h4 style="font-size: 14px; font-weight: 600; color: var(--text-primary); margin-bottom: 12px;">
                                    { "Handshake & TCP Flag Observations" }
                                </h4>
                                <div style="display: flex; flex-direction: column; gap: 8px; font-size: 13px;">
                                    <div style="display: flex; justify-content: space-between;">
                                        <span style="color: var(--text-muted);">{ "Observation:" }</span>
                                        <span>{ &f.handshake_summary }</span>
                                    </div>
                                    <div style="display: flex; justify-content: space-between;">
                                        <span style="color: var(--text-muted);">{ "SYN Count:" }</span>
                                        <span class="mono-cell">{ f.syn_count }</span>
                                    </div>
                                    <div style="display: flex; justify-content: space-between;">
                                        <span style="color: var(--text-muted);">{ "SYN-ACK Count:" }</span>
                                        <span class="mono-cell">{ f.syn_ack_count }</span>
                                    </div>
                                    <div style="display: flex; justify-content: space-between;">
                                        <span style="color: var(--text-muted);">{ "ACK Count:" }</span>
                                        <span class="mono-cell">{ f.ack_count }</span>
                                    </div>
                                    <div style="display: flex; justify-content: space-between;">
                                        <span style="color: var(--text-muted);">{ "RST Count:" }</span>
                                        <span class="mono-cell" style="color: var(--badge-amber);">{ f.rst_count }</span>
                                    </div>
                                    <div style="display: flex; justify-content: space-between;">
                                        <span style="color: var(--text-muted);">{ "FIN Count:" }</span>
                                        <span class="mono-cell">{ f.fin_count }</span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    }
                } else {
                    html! {}
                }
            }
        </div>
    }
}
