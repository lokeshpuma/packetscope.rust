use packetscope_core::HostRecord;
use yew::prelude::*;

#[derive(Properties, PartialEq)]
pub struct HostsPageProps {
    pub hosts: Vec<HostRecord>,
    pub selected_host_ip: Option<String>,
    pub on_host_select: Callback<Option<String>>,
    pub on_filter_packets: Callback<String>,
}

#[function_component(HostsPage)]
pub fn hosts_page(props: &HostsPageProps) -> Html {
    let search_term = use_state(String::new);
    let ranking_metric = use_state(|| "bytes"); // "bytes", "packets", "outbound", "inbound", "peers"

    let filtered_hosts = use_memo(
        (
            props.hosts.clone(),
            (*search_term).clone(),
            (*ranking_metric),
        ),
        |(hosts, term, metric)| {
            let mut list: Vec<HostRecord> = if term.is_empty() {
                hosts.clone()
            } else {
                let lower = term.to_lowercase();
                hosts
                    .iter()
                    .filter(|h| {
                        h.ip.contains(&lower)
                            || h.mac
                                .as_deref()
                                .unwrap_or("")
                                .to_lowercase()
                                .contains(&lower)
                            || h.observed_protocols
                                .iter()
                                .any(|p| p.to_lowercase().contains(&lower))
                    })
                    .cloned()
                    .collect()
            };

            match *metric {
                "packets" => {
                    list.sort_by_key(|a| std::cmp::Reverse(a.packets_sent + a.packets_received))
                }
                "outbound" => list.sort_by_key(|a| std::cmp::Reverse(a.bytes_sent)),
                "inbound" => list.sort_by_key(|a| std::cmp::Reverse(a.bytes_received)),
                "peers" => list.sort_by_key(|a| std::cmp::Reverse(a.peer_count)),
                _ => list.sort_by_key(|a| std::cmp::Reverse(a.total_bytes)),
            }
            list
        },
    );

    let selected_host = props
        .selected_host_ip
        .as_ref()
        .and_then(|ip| props.hosts.iter().find(|h| h.ip == *ip).cloned());

    let on_search_input = {
        let search_term = search_term.clone();
        Callback::from(move |e: InputEvent| {
            if let Some(target) = e.target_dyn_into::<web_sys::HtmlInputElement>() {
                search_term.set(target.value());
            }
        })
    };

    let close_drawer = {
        let cb = props.on_host_select.clone();
        Callback::from(move |_| cb.emit(None))
    };

    html! {
        <div>
            <div style="display: flex; align-items: center; justify-content: space-between; gap: 16px; margin-bottom: 20px; flex-wrap: wrap;">
                <input
                    type="text"
                    class="filter-input"
                    placeholder="Search hosts by IP, MAC, or protocol..."
                    style="max-width: 360px;"
                    value={(*search_term).clone()}
                    oninput={on_search_input}
                />

                <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
                    <span style="font-size: 13px; color: var(--text-muted);">{ "Rank talkers by:" }</span>
                    <button
                        class={classes!("btn", "btn-sm", if *ranking_metric == "bytes" { "btn-primary" } else { "btn-secondary" })}
                        onclick={
                            let m = ranking_metric.clone();
                            Callback::from(move |_| m.set("bytes"))
                        }
                    >
                        { "Total Volume" }
                    </button>
                    <button
                        class={classes!("btn", "btn-sm", if *ranking_metric == "packets" { "btn-primary" } else { "btn-secondary" })}
                        onclick={
                            let m = ranking_metric.clone();
                            Callback::from(move |_| m.set("packets"))
                        }
                    >
                        { "Packets" }
                    </button>
                    <button
                        class={classes!("btn", "btn-sm", if *ranking_metric == "outbound" { "btn-primary" } else { "btn-secondary" })}
                        onclick={
                            let m = ranking_metric.clone();
                            Callback::from(move |_| m.set("outbound"))
                        }
                    >
                        { "Outbound" }
                    </button>
                    <button
                        class={classes!("btn", "btn-sm", if *ranking_metric == "inbound" { "btn-primary" } else { "btn-secondary" })}
                        onclick={
                            let m = ranking_metric.clone();
                            Callback::from(move |_| m.set("inbound"))
                        }
                    >
                        { "Inbound" }
                    </button>
                    <button
                        class={classes!("btn", "btn-sm", if *ranking_metric == "peers" { "btn-primary" } else { "btn-secondary" })}
                        onclick={
                            let m = ranking_metric.clone();
                            Callback::from(move |_| m.set("peers"))
                        }
                    >
                        { "Unique Peers" }
                    </button>
                </div>
            </div>

            <div class="table-container">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>{ "IP Address" }</th>
                            <th>{ "MAC Address" }</th>
                            <th>{ "Family" }</th>
                            <th>{ "Total Volume" }</th>
                            <th>{ "Sent" }</th>
                            <th>{ "Received" }</th>
                            <th>{ "Packets" }</th>
                            <th>{ "Peers" }</th>
                            <th>{ "Observed Protocols" }</th>
                        </tr>
                    </thead>
                    <tbody>
                        {
                            if filtered_hosts.is_empty() {
                                html! {
                                    <tr>
                                        <td colspan="9" style="text-align: center; padding: 40px; color: var(--text-muted);">
                                            { "No network hosts found." }
                                        </td>
                                    </tr>
                                }
                            } else {
                                html! {
                                    {
                                        for filtered_hosts.iter().map(|h| {
                                            let is_selected = props.selected_host_ip.as_deref() == Some(&h.ip);
                                            let row_class = if is_selected { "selected" } else { "" };
                                            let ip = h.ip.clone();
                                            let on_click = {
                                                let cb = props.on_host_select.clone();
                                                let ip_c = ip.clone();
                                                Callback::from(move |_| cb.emit(Some(ip_c.clone())))
                                            };

                                            let vol_str = if h.total_bytes >= 1_048_576 {
                                                format!("{:.2} MB", h.total_bytes as f64 / 1_048_576.0)
                                            } else {
                                                format!("{:.1} KB", h.total_bytes as f64 / 1024.0)
                                            };

                                            html! {
                                                <tr class={row_class} onclick={on_click}>
                                                    <td class="mono-cell" style="color: var(--accent-blue); font-weight: 600;">{ &h.ip }</td>
                                                    <td class="mono-cell" style="color: var(--text-muted);">{ h.mac.as_deref().unwrap_or("N/A") }</td>
                                                    <td><span class="badge badge-info">{ &h.address_family }</span></td>
                                                    <td class="mono-cell">{ vol_str }</td>
                                                    <td class="mono-cell">{ format!("{:.1} KB", h.bytes_sent as f64 / 1024.0) }</td>
                                                    <td class="mono-cell">{ format!("{:.1} KB", h.bytes_received as f64 / 1024.0) }</td>
                                                    <td class="mono-cell">{ h.packets_sent + h.packets_received }</td>
                                                    <td class="mono-cell">{ h.peer_count }</td>
                                                    <td>
                                                        <div style="display: flex; gap: 4px; flex-wrap: wrap;">
                                                            {
                                                                for h.observed_protocols.iter().map(|p| {
                                                                    html! { <span class="badge badge-info" style="font-size: 10px;">{ p }</span> }
                                                                })
                                                            }
                                                        </div>
                                                    </td>
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
                if let Some(host) = selected_host {
                    let on_filter_click = {
                        let cb = props.on_filter_packets.clone();
                        let filter_expr = format!("host == {}", host.ip);
                        Callback::from(move |_| cb.emit(filter_expr.clone()))
                    };

                    html! {
                        <div class="detail-drawer">
                            <div class="drawer-header">
                                <div>
                                    <h3 style="font-size: 18px; font-weight: 700; color: var(--text-primary);">
                                        { format!("Host: {}", host.ip) }
                                    </h3>
                                    <span style="font-size: 12px; color: var(--text-muted); font-family: var(--font-mono);">
                                        { host.mac.as_deref().unwrap_or("No MAC recorded") }
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
                                <span>{ format!("Filter Packets for {}", host.ip) }</span>
                            </button>

                            <div class="card" style="margin-bottom: 0;">
                                <h4 style="font-size: 14px; font-weight: 600; color: var(--text-primary); margin-bottom: 12px;">
                                    { "Traffic Metrics" }
                                </h4>
                                <div style="display: flex; flex-direction: column; gap: 8px; font-size: 13px;">
                                    <div style="display: flex; justify-content: space-between;">
                                        <span style="color: var(--text-muted);">{ "Total Bytes:" }</span>
                                        <span class="mono-cell">{ format!("{} bytes ({:.2} MB)", host.total_bytes, host.total_bytes as f64 / 1_048_576.0) }</span>
                                    </div>
                                    <div style="display: flex; justify-content: space-between;">
                                        <span style="color: var(--text-muted);">{ "Sent Volume:" }</span>
                                        <span class="mono-cell">{ format!("{} bytes ({} pkts)", host.bytes_sent, host.packets_sent) }</span>
                                    </div>
                                    <div style="display: flex; justify-content: space-between;">
                                        <span style="color: var(--text-muted);">{ "Received Volume:" }</span>
                                        <span class="mono-cell">{ format!("{} bytes ({} pkts)", host.bytes_received, host.packets_received) }</span>
                                    </div>
                                    <div style="display: flex; justify-content: space-between;">
                                        <span style="color: var(--text-muted);">{ "First Seen:" }</span>
                                        <span class="mono-cell" style="font-size: 11px;">{ &host.first_seen_iso }</span>
                                    </div>
                                    <div style="display: flex; justify-content: space-between;">
                                        <span style="color: var(--text-muted);">{ "Last Seen:" }</span>
                                        <span class="mono-cell" style="font-size: 11px;">{ &host.last_seen_iso }</span>
                                    </div>
                                </div>
                            </div>

                            <div class="card" style="margin-bottom: 0;">
                                <h4 style="font-size: 14px; font-weight: 600; color: var(--text-primary); margin-bottom: 8px;">
                                    { "Associated DNS Domains" }
                                </h4>
                                {
                                    if host.associated_dns_names.is_empty() {
                                        html! { <span style="font-size: 12px; color: var(--text-muted);">{ "No DNS resolutions correlated with this host." }</span> }
                                    } else {
                                        html! {
                                            <ul style="font-family: var(--font-mono); font-size: 12px; color: var(--accent-cyan); margin-left: 20px;">
                                                {
                                                    for host.associated_dns_names.iter().map(|name| {
                                                        html! { <li>{ name }</li> }
                                                    })
                                                }
                                            </ul>
                                        }
                                    }
                                }
                            </div>

                            <div class="card" style="margin-bottom: 0;">
                                <h4 style="font-size: 14px; font-weight: 600; color: var(--text-primary); margin-bottom: 8px;">
                                    { format!("Connected Peers ({})", host.peer_count) }
                                </h4>
                                <div style="display: flex; gap: 6px; flex-wrap: wrap;">
                                    {
                                        for host.unique_peers.iter().map(|peer| {
                                            html! {
                                                <span class="mono-cell" style="background: var(--bg-input); border: 1px solid var(--border-color); padding: 2px 8px; border-radius: 4px; font-size: 11px;">
                                                    { peer }
                                                </span>
                                            }
                                        })
                                    }
                                </div>
                            </div>

                            <div class="card" style="margin-bottom: 0;">
                                <h4 style="font-size: 14px; font-weight: 600; color: var(--text-primary); margin-bottom: 8px;">
                                    { "Destination Ports Accessed" }
                                </h4>
                                <div style="display: flex; gap: 6px; flex-wrap: wrap;">
                                    {
                                        for host.destination_ports.iter().take(20).map(|port| {
                                            html! {
                                                <span class="badge badge-info" style="font-size: 11px;">
                                                    { port }
                                                </span>
                                            }
                                        })
                                    }
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
