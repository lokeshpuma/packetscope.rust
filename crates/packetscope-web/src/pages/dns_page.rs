use packetscope_core::DnsRecord;
use std::collections::HashMap;
use yew::prelude::*;

#[derive(Properties, PartialEq)]
pub struct DnsPageProps {
    pub dns_records: Vec<DnsRecord>,
    pub on_filter_packets: Callback<String>,
}

#[function_component(DnsPage)]
pub fn dns_page(props: &DnsPageProps) -> Html {
    let domain_search = use_state(String::new);

    let memo_stats = use_memo(props.dns_records.clone(), |records| {
        let mut domain_map: HashMap<String, usize> = HashMap::new();
        let mut type_map: HashMap<String, usize> = HashMap::new();
        let mut rcode_map: HashMap<String, usize> = HashMap::new();
        let mut errors = 0;
        let mut nxdomain = 0;

        for r in records {
            if !r.is_response {
                *domain_map.entry(r.primary_query.clone()).or_insert(0) += 1;
                *type_map.entry(r.primary_query_type.clone()).or_insert(0) += 1;
            } else {
                *rcode_map.entry(r.rcode_name.clone()).or_insert(0) += 1;
                if r.rcode != 0 {
                    errors += 1;
                    if r.rcode == 3 {
                        nxdomain += 1;
                    }
                }
            }
        }

        let mut sorted_domains: Vec<(String, usize)> = domain_map.into_iter().collect();
        sorted_domains.sort_by_key(|a| std::cmp::Reverse(a.1));

        let mut sorted_types: Vec<(String, usize)> = type_map.into_iter().collect();
        sorted_types.sort_by_key(|a| std::cmp::Reverse(a.1));

        let mut sorted_rcodes: Vec<(String, usize)> = rcode_map.into_iter().collect();
        sorted_rcodes.sort_by_key(|a| std::cmp::Reverse(a.1));

        (
            sorted_domains,
            sorted_types,
            sorted_rcodes,
            errors,
            nxdomain,
        )
    });
    let (top_domains, type_counts, rcode_counts, error_count, nxdomain_count) = &*memo_stats;

    let total_dns = props.dns_records.len();
    let unique_domains_count = top_domains.len();
    let total_responses = props.dns_records.iter().filter(|d| d.is_response).count();
    let nxdomain_ratio = if total_responses > 0 {
        (*nxdomain_count as f64 / total_responses as f64) * 100.0
    } else {
        0.0
    };

    let filtered_records = use_memo(
        (props.dns_records.clone(), (*domain_search).clone()),
        |(records, term)| {
            if term.is_empty() {
                records.clone()
            } else {
                let lower = term.to_lowercase();
                records
                    .iter()
                    .filter(|r| {
                        r.primary_query.to_lowercase().contains(&lower)
                            || r.source_ip.contains(&lower)
                            || r.destination_ip.contains(&lower)
                            || r.rcode_name.to_lowercase().contains(&lower)
                    })
                    .cloned()
                    .collect()
            }
        },
    );

    let on_search_input = {
        let domain_search = domain_search.clone();
        Callback::from(move |e: InputEvent| {
            if let Some(target) = e.target_dyn_into::<web_sys::HtmlInputElement>() {
                domain_search.set(target.value());
            }
        })
    };

    if props.dns_records.is_empty() {
        return html! {
            <div class="card" style="text-align: center; padding: 60px 20px;">
                <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="color: var(--text-muted); margin-bottom: 16px;">
                    <circle cx="12" cy="12" r="10"></circle>
                    <line x1="2" y1="12" x2="22" y2="12"></line>
                    <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path>
                </svg>
                <h3 style="font-size: 18px; color: var(--text-primary); margin-bottom: 8px;">{ "No DNS Traffic Detected" }</h3>
                <p style="font-size: 14px; color: var(--text-muted); max-width: 480px; margin: 0 auto;">
                    { "This capture does not contain standard DNS requests or responses on port 53." }
                </p>
            </div>
        };
    }

    html! {
        <div>
            <div class="metrics-grid">
                <div class="metric-card">
                    <span class="metric-title">{ "Total DNS Messages" }</span>
                    <span class="metric-value">{ total_dns }</span>
                    <span class="metric-sub">{ format!("{} responses", total_responses) }</span>
                </div>
                <div class="metric-card">
                    <span class="metric-title">{ "Unique Domains" }</span>
                    <span class="metric-value">{ unique_domains_count }</span>
                    <span class="metric-sub">{ "Queried hostnames" }</span>
                </div>
                <div class="metric-card">
                    <span class="metric-title">{ "DNS Errors" }</span>
                    <span class="metric-value" style={if *error_count > 0 { "color: var(--badge-amber);" } else { "" }}>
                        { *error_count }
                    </span>
                    <span class="metric-sub">{ format!("{} NXDomain", *nxdomain_count) }</span>
                </div>
                <div class="metric-card">
                    <span class="metric-title">{ "NXDOMAIN Ratio" }</span>
                    <span class="metric-value" style={if nxdomain_ratio >= 15.0 { "color: var(--badge-amber);" } else { "" }}>
                        { format!("{:.1}%", nxdomain_ratio) }
                    </span>
                    <span class="metric-sub">{ "Of total responses" }</span>
                </div>
            </div>

            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(360px, 1fr)); gap: 24px; margin-bottom: 24px;">
                <div class="card" style="margin-bottom: 0;">
                    <div class="card-header">
                        <h3 class="card-title">{ "Top Queried Domain Names" }</h3>
                        <span style="font-size: 12px; color: var(--text-muted);">{ "Most frequent queries" }</span>
                    </div>
                    <div class="table-container">
                        <table class="data-table">
                            <thead>
                                <tr>
                                    <th>{ "Domain Name" }</th>
                                    <th>{ "Queries" }</th>
                                    <th>{ "Action" }</th>
                                </tr>
                            </thead>
                            <tbody>
                                {
                                    for top_domains.iter().take(10).map(|(name, count)| {
                                        let on_filter = {
                                            let cb = props.on_filter_packets.clone();
                                            let dom = name.clone();
                                            Callback::from(move |_| cb.emit(format!("dns.qname contains \"{}\"", dom)))
                                        };
                                        html! {
                                            <tr>
                                                <td class="mono-cell" style="color: var(--accent-cyan);">{ name }</td>
                                                <td class="mono-cell">{ count }</td>
                                                <td>
                                                    <button class="btn btn-secondary btn-sm" onclick={on_filter}>
                                                        { "Filter" }
                                                    </button>
                                                </td>
                                            </tr>
                                        }
                                    })
                                }
                            </tbody>
                        </table>
                    </div>
                </div>

                <div class="card" style="margin-bottom: 0;">
                    <div class="card-header">
                        <h3 class="card-title">{ "Types & Response Codes" }</h3>
                    </div>
                    <div style="display: flex; flex-direction: column; gap: 16px;">
                        <div>
                            <h4 style="font-size: 13px; color: var(--text-secondary); margin-bottom: 8px;">{ "Query Record Types:" }</h4>
                            <div style="display: flex; gap: 8px; flex-wrap: wrap;">
                                {
                                    for type_counts.iter().map(|(qtype, cnt)| {
                                        html! {
                                            <span class="badge badge-info" style="font-size: 12px; padding: 4px 10px;">
                                                { format!("{}: {}", qtype, cnt) }
                                            </span>
                                        }
                                    })
                                }
                            </div>
                        </div>

                        <div>
                            <h4 style="font-size: 13px; color: var(--text-secondary); margin-bottom: 8px;">{ "Response Codes:" }</h4>
                            <div style="display: flex; gap: 8px; flex-wrap: wrap;">
                                {
                                    for rcode_counts.iter().map(|(rcode, cnt)| {
                                        let badge_cls = if rcode == "NoError" { "badge-low" } else { "badge-medium" };
                                        html! {
                                            <span class={classes!("badge", badge_cls)} style="font-size: 12px; padding: 4px 10px;">
                                                { format!("{}: {}", rcode, cnt) }
                                            </span>
                                        }
                                    })
                                }
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="card">
                <div class="card-header" style="flex-wrap: wrap; gap: 12px;">
                    <div>
                        <h3 class="card-title">{ "DNS Transaction Log" }</h3>
                        <span style="font-size: 12px; color: var(--text-muted);">{ "Parsed requests and answers" }</span>
                    </div>

                    <input
                        type="text"
                        class="filter-input"
                        placeholder="Search domain or IP..."
                        style="max-width: 240px; padding: 6px 12px; font-size: 12px;"
                        value={(*domain_search).clone()}
                        oninput={on_search_input}
                    />
                </div>

                <div class="table-container">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>{ "Frame" }</th>
                                <th>{ "TXID" }</th>
                                <th>{ "Type" }</th>
                                <th>{ "Client" }</th>
                                <th>{ "Server" }</th>
                                <th>{ "Query Name" }</th>
                                <th>{ "Record" }</th>
                                <th>{ "Status" }</th>
                                <th>{ "Answers" }</th>
                            </tr>
                        </thead>
                        <tbody>
                            {
                                for filtered_records.iter().take(100).map(|r| {
                                    let status_badge = if r.rcode == 0 { "badge-low" } else { "badge-medium" };
                                    let answers_str = r.answers.iter().map(|a| a.data.as_str()).collect::<Vec<_>>().join(", ");
                                    html! {
                                        <tr>
                                            <td class="mono-cell">{ r.packet_index }</td>
                                            <td class="mono-cell">{ format!("0x{:04x}", r.transaction_id) }</td>
                                            <td>{ if r.is_response { "Response" } else { "Query" } }</td>
                                            <td class="mono-cell">{ &r.source_ip }</td>
                                            <td class="mono-cell">{ &r.destination_ip }</td>
                                            <td class="mono-cell" style="color: var(--accent-cyan);">{ &r.primary_query }</td>
                                            <td><span class="badge badge-info">{ &r.primary_query_type }</span></td>
                                            <td><span class={classes!("badge", status_badge)}>{ &r.rcode_name }</span></td>
                                            <td class="mono-cell" style="font-size: 11px; max-width: 240px; overflow: hidden; text-overflow: ellipsis;">
                                                { answers_str }
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
    }
}
