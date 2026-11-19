use crate::components::{HostGraph, TimelineChart};
use packetscope_core::{HostRecord, NetworkFlow, TimelineAnalysis};
use yew::prelude::*;

#[derive(Properties, PartialEq)]
pub struct TimelinePageProps {
    pub timeline: TimelineAnalysis,
    pub hosts: Vec<HostRecord>,
    pub flows: Vec<NetworkFlow>,
    pub on_host_select: Callback<String>,
}

#[function_component(TimelinePage)]
pub fn timeline_page(props: &TimelinePageProps) -> Html {
    let selected_bucket_idx = use_state(|| None::<usize>);

    let on_bucket_select = {
        let selected_bucket_idx = selected_bucket_idx.clone();
        Callback::from(move |idx: usize| {
            selected_bucket_idx.set(Some(idx));
        })
    };

    html! {
        <div>
            <div class="card">
                <div class="card-header">
                    <div>
                        <h3 class="card-title">{ "Traffic Timeline (Rate & Composition)" }</h3>
                        <span style="font-size: 12px; color: var(--text-muted);">
                            { format!("Calculated across {} buckets ({:.1}s interval resolution)", props.timeline.buckets.len(), props.timeline.bucket_resolution_seconds) }
                        </span>
                    </div>
                    <div style="display: flex; gap: 16px; font-size: 13px;">
                        <span style="color: var(--accent-blue); font-weight: 600;">
                            { format!("Peak PPS: {:.1}", props.timeline.max_pps) }
                        </span>
                        <span style="color: var(--accent-cyan); font-weight: 600;">
                            { format!("Peak BPS: {:.1} Kbps", props.timeline.max_bps / 1000.0) }
                        </span>
                    </div>
                </div>

                <TimelineChart
                    timeline={props.timeline.clone()}
                    on_bucket_select={Some(on_bucket_select)}
                />
            </div>

            <div class="card">
                <div class="card-header">
                    <div>
                        <h3 class="card-title">{ "Host Communication Topology" }</h3>
                        <span style="font-size: 12px; color: var(--text-muted);">
                            { "Visual map of observed network connections. Edge thickness represents communication volume." }
                        </span>
                    </div>
                </div>
                <HostGraph
                    hosts={props.hosts.clone()}
                    flows={props.flows.clone()}
                    on_host_select={props.on_host_select.clone()}
                />
            </div>

            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">{ "Timeline Measurement Buckets" }</h3>
                    <span style="font-size: 12px; color: var(--text-muted);">{ "Aggregated traffic interval measurements" }</span>
                </div>

                <div class="table-container">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>{ "Bucket #" }</th>
                                <th>{ "Time Window" }</th>
                                <th>{ "Packets" }</th>
                                <th>{ "Packets/s" }</th>
                                <th>{ "Total Bytes" }</th>
                                <th>{ "TCP Volume" }</th>
                                <th>{ "UDP Volume" }</th>
                                <th>{ "Other Volume" }</th>
                            </tr>
                        </thead>
                        <tbody>
                            {
                                for props.timeline.buckets.iter().map(|b| {
                                    html! {
                                        <tr>
                                            <td class="mono-cell">{ b.bucket_index + 1 }</td>
                                            <td class="mono-cell" style="color: var(--text-muted);">{ &b.timestamp_iso }</td>
                                            <td class="mono-cell">{ b.packet_count }</td>
                                            <td class="mono-cell" style="color: var(--accent-blue); font-weight: 600;">{ format!("{:.1}", b.packets_per_second) }</td>
                                            <td class="mono-cell">{ b.byte_count }</td>
                                            <td class="mono-cell">{ b.tcp_bytes }</td>
                                            <td class="mono-cell">{ b.udp_bytes }</td>
                                            <td class="mono-cell">{ b.other_bytes }</td>
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
