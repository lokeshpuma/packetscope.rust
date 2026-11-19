use crate::components::{HexViewer, LayerTree};
use packetscope_core::{get_filter_completions, parse_filter, PacketRecord};
use std::rc::Rc;
use yew::prelude::*;

#[derive(Properties, PartialEq)]
pub struct PacketsPageProps {
    pub packets: Vec<PacketRecord>,
    pub selected_packet_index: Option<u64>,
    pub on_packet_select: Callback<Option<u64>>,
    pub global_filter: String,
}

#[function_component(PacketsPage)]
pub fn packets_page(props: &PacketsPageProps) -> Html {
    let filter_text = use_state(|| props.global_filter.clone());
    let applied_filter = use_state(|| props.global_filter.clone());
    let filter_error = use_state(|| None::<String>);
    let show_suggestions = use_state(|| false);

    let page_index = use_state(|| 0usize);
    let page_size = use_state(|| 50usize);

    let apply_action = {
        let filter_text = filter_text.clone();
        let applied_filter = applied_filter.clone();
        let filter_error = filter_error.clone();
        let page_index = page_index.clone();
        let show_suggestions = show_suggestions.clone();

        Rc::new(move || {
            show_suggestions.set(false);
            let input = (*filter_text).trim().to_string();
            if input.is_empty() {
                applied_filter.set(String::new());
                filter_error.set(None);
                page_index.set(0);
            } else {
                match parse_filter(&input) {
                    Ok(_) => {
                        applied_filter.set(input);
                        filter_error.set(None);
                        page_index.set(0);
                    }
                    Err(e) => {
                        filter_error.set(Some(e.to_string()));
                    }
                }
            }
        })
    };

    let apply_filter = {
        let action = apply_action.clone();
        Callback::from(move |_: MouseEvent| {
            action();
        })
    };

    let clear_filter = {
        let filter_text = filter_text.clone();
        let applied_filter = applied_filter.clone();
        let filter_error = filter_error.clone();
        let page_index = page_index.clone();
        Callback::from(move |_| {
            filter_text.set(String::new());
            applied_filter.set(String::new());
            filter_error.set(None);
            page_index.set(0);
        })
    };

    // Filter packets
    let filtered_packets = use_memo(
        (props.packets.clone(), (*applied_filter).clone()),
        |(pkts, filter_str)| {
            if filter_str.is_empty() {
                pkts.clone()
            } else if let Ok(expr) = parse_filter(filter_str) {
                pkts.iter().filter(|p| expr.evaluate(p)).cloned().collect()
            } else {
                pkts.clone()
            }
        },
    );

    let total_filtered = filtered_packets.len();
    let total_pages = if total_filtered == 0 {
        1
    } else {
        total_filtered.div_ceil(*page_size)
    };
    let current_page = (*page_index).min(total_pages.saturating_sub(1));

    let start_idx = current_page * *page_size;
    let end_idx = (start_idx + *page_size).min(total_filtered);
    let page_packets = &filtered_packets[start_idx..end_idx];

    let selected_packet = props
        .selected_packet_index
        .and_then(|idx| props.packets.iter().find(|p| p.index == idx).cloned());

    let on_input_change = {
        let filter_text = filter_text.clone();
        let show_suggestions = show_suggestions.clone();
        Callback::from(move |e: InputEvent| {
            if let Some(target) = e.target_dyn_into::<web_sys::HtmlInputElement>() {
                filter_text.set(target.value());
                show_suggestions.set(true);
            }
        })
    };

    let on_keydown = {
        let action = apply_action.clone();
        Callback::from(move |e: KeyboardEvent| {
            if e.key() == "Enter" {
                action();
            }
        })
    };

    let next_page = {
        let page_index = page_index.clone();
        Callback::from(move |_| {
            if current_page + 1 < total_pages {
                page_index.set(current_page + 1);
            }
        })
    };

    let prev_page = {
        let page_index = page_index.clone();
        Callback::from(move |_| {
            if current_page > 0 {
                page_index.set(current_page - 1);
            }
        })
    };

    let close_drawer = {
        let cb = props.on_packet_select.clone();
        Callback::from(move |_| cb.emit(None))
    };

    let select_prev_packet = {
        let cb = props.on_packet_select.clone();
        let cur_idx = props.selected_packet_index;
        let pkts = props.packets.clone();
        Callback::from(move |_| {
            if let Some(idx) = cur_idx {
                if let Some(pos) = pkts.iter().position(|p| p.index == idx) {
                    if pos > 0 {
                        cb.emit(Some(pkts[pos - 1].index));
                    }
                }
            }
        })
    };

    let select_next_packet = {
        let cb = props.on_packet_select.clone();
        let cur_idx = props.selected_packet_index;
        let pkts = props.packets.clone();
        Callback::from(move |_| {
            if let Some(idx) = cur_idx {
                if let Some(pos) = pkts.iter().position(|p| p.index == idx) {
                    if pos + 1 < pkts.len() {
                        cb.emit(Some(pkts[pos + 1].index));
                    }
                }
            }
        })
    };

    html! {
        <div>
            <div class="filter-bar">
                <div class="filter-input-wrap">
                    <input
                        type="text"
                        class="filter-input"
                        placeholder="Filter packets: e.g. ip.src == 192.168.1.10 and tcp.port == 443"
                        value={(*filter_text).clone()}
                        oninput={on_input_change}
                        onkeydown={on_keydown}
                    />
                    {
                        if *show_suggestions && !filter_text.is_empty() {
                            let suggestions = get_filter_completions(&filter_text);
                            html! {
                                <div class="autocomplete-dropdown">
                                    {
                                        for suggestions.into_iter().take(6).map(|s| {
                                            let s_val = s.clone();
                                            let f_text = filter_text.clone();
                                            let show = show_suggestions.clone();
                                            let action = apply_action.clone();
                                            let on_click = Callback::from(move |_| {
                                                f_text.set(s_val.clone());
                                                show.set(false);
                                                action();
                                            });
                                            html! {
                                                <div class="autocomplete-item" onclick={on_click}>
                                                    { s }
                                                </div>
                                            }
                                        })
                                    }
                                </div>
                            }
                        } else {
                            html! {}
                        }
                    }
                </div>

                <button class="btn btn-primary" onclick={apply_filter}>
                    { "Apply Filter" }
                </button>
                <button class="btn btn-secondary" onclick={clear_filter}>
                    { "Clear" }
                </button>
            </div>

            {
                if let Some(ref err) = *filter_error {
                    html! {
                        <div style="color: var(--badge-red); font-size: 12px; margin-top: -8px; margin-bottom: 12px; font-family: var(--font-mono);">
                            { format!("Syntax Error: {}", err) }
                        </div>
                    }
                } else {
                    html! {}
                }
            }

            <div class="table-container">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th style="width: 50px;">{ "No." }</th>
                            <th style="width: 140px;">{ "Time" }</th>
                            <th style="width: 130px;">{ "Source" }</th>
                            <th style="width: 130px;">{ "Destination" }</th>
                            <th style="width: 80px;">{ "Protocol" }</th>
                            <th style="width: 60px;">{ "Length" }</th>
                            <th style="width: 70px;">{ "Src Port" }</th>
                            <th style="width: 70px;">{ "Dst Port" }</th>
                            <th style="width: 80px;">{ "Flags" }</th>
                            <th>{ "Info" }</th>
                        </tr>
                    </thead>
                    <tbody>
                        {
                            if page_packets.is_empty() {
                                html! {
                                    <tr>
                                        <td colspan="10" style="text-align: center; padding: 40px; color: var(--text-muted);">
                                            { "No packets matched the current filter expression." }
                                        </td>
                                    </tr>
                                }
                            } else {
                                html! {
                                    {
                                        for page_packets.iter().map(|pkt| {
                                            let is_selected = props.selected_packet_index == Some(pkt.index);
                                            let row_class = if is_selected { "selected" } else { "" };
                                            let on_click = {
                                                let cb = props.on_packet_select.clone();
                                                let idx = pkt.index;
                                                Callback::from(move |_| cb.emit(Some(idx)))
                                            };

                                            let flag_desc = pkt.tcp_flags.map(|f| f.to_display_string()).unwrap_or_default();

                                            html! {
                                                <tr class={row_class} onclick={on_click}>
                                                    <td class="mono-cell">{ pkt.index }</td>
                                                    <td class="mono-cell" style="color: var(--text-muted);">{ &pkt.timestamp_iso }</td>
                                                    <td class="mono-cell" style="color: var(--accent-blue);">{ pkt.primary_source() }</td>
                                                    <td class="mono-cell" style="color: var(--accent-blue);">{ pkt.primary_destination() }</td>
                                                    <td><span class="badge badge-info">{ pkt.protocol_display() }</span></td>
                                                    <td class="mono-cell">{ pkt.captured_length }</td>
                                                    <td class="mono-cell">{ pkt.source_port.map(|v| v.to_string()).unwrap_or_default() }</td>
                                                    <td class="mono-cell">{ pkt.destination_port.map(|v| v.to_string()).unwrap_or_default() }</td>
                                                    <td class="mono-cell" style="font-size: 11px;">{ flag_desc }</td>
                                                    <td style="max-width: 320px; overflow: hidden; text-overflow: ellipsis;">{ &pkt.info }</td>
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

            <div class="pagination">
                <div>
                    { format!("Showing {}-{} of {} packets", if total_filtered == 0 { 0 } else { start_idx + 1 }, end_idx, total_filtered) }
                    {
                        if total_filtered != props.packets.len() {
                            html! {
                                <span style="color: var(--accent-blue); margin-left: 8px;">
                                    { format!("(filtered from {} total)", props.packets.len()) }
                                </span>
                            }
                        } else {
                            html! {}
                        }
                    }
                </div>

                <div class="pagination-controls">
                    <button class="btn btn-secondary btn-sm" onclick={prev_page} disabled={current_page == 0}>
                        { "◀ Previous" }
                    </button>
                    <span style="font-family: var(--font-mono); font-size: 12px; margin: 0 4px;">
                        { format!("Page {} / {}", current_page + 1, total_pages) }
                    </span>
                    <button class="btn btn-secondary btn-sm" onclick={next_page} disabled={current_page + 1 >= total_pages}>
                        { "Next ▶" }
                    </button>
                </div>
            </div>

            {
                if let Some(pkt) = selected_packet {
                    html! {
                        <div class="detail-drawer">
                            <div class="drawer-header">
                                <div>
                                    <h3 style="font-size: 18px; font-weight: 700; color: var(--text-primary);">
                                        { format!("Frame #{}", pkt.index) }
                                    </h3>
                                    <span style="font-size: 12px; color: var(--text-muted); font-family: var(--font-mono);">
                                        { &pkt.timestamp_iso }
                                    </span>
                                </div>
                                <div style="display: flex; align-items: center; gap: 8px;">
                                    <button class="btn btn-secondary btn-sm" onclick={select_prev_packet} title="Previous Packet">
                                        { "▲" }
                                    </button>
                                    <button class="btn btn-secondary btn-sm" onclick={select_next_packet} title="Next Packet">
                                        { "▼" }
                                    </button>
                                    <button class="btn btn-secondary btn-sm" onclick={close_drawer} title="Close Panel">
                                        { "✕" }
                                    </button>
                                </div>
                            </div>

                            <div style="background: var(--bg-card); padding: 12px 16px; border-radius: 6px; border: 1px solid var(--border-color); font-size: 13px;">
                                <div style="margin-bottom: 6px;">
                                    <strong style="color: var(--accent-blue);">{ pkt.protocol_display() }</strong>
                                    <span style="margin-left: 8px;">{ &pkt.info }</span>
                                </div>
                                <div style="display: flex; gap: 16px; font-size: 12px; color: var(--text-muted); font-family: var(--font-mono);">
                                    <span>{ format!("Wire: {} B", pkt.original_length) }</span>
                                    <span>{ format!("Cap: {} B", pkt.captured_length) }</span>
                                    {
                                        if pkt.truncated {
                                            html! { <span style="color: var(--badge-amber);">{ "[TRUNCATED]" }</span> }
                                        } else {
                                            html! {}
                                        }
                                    }
                                </div>
                            </div>

                            <div>
                                <h4 style="font-size: 14px; font-weight: 600; color: var(--text-primary); margin-bottom: 10px;">
                                    { "Protocol Layer Decodes" }
                                </h4>
                                <LayerTree layers={pkt.layers.clone()} />
                            </div>

                            <div>
                                <h4 style="font-size: 14px; font-weight: 600; color: var(--text-primary); margin-bottom: 10px;">
                                    { "Raw Packet Hex & ASCII" }
                                </h4>
                                <HexViewer bytes={pkt.raw_bytes.clone()} />
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
