use packetscope_core::{HostRecord, NetworkFlow};
use yew::prelude::*;

#[derive(Properties, PartialEq)]
pub struct HostGraphProps {
    pub hosts: Vec<HostRecord>,
    pub flows: Vec<NetworkFlow>,
    pub on_host_select: Callback<String>,
}

#[function_component(HostGraph)]
pub fn host_graph(props: &HostGraphProps) -> Html {
    let top_hosts: Vec<&HostRecord> = props.hosts.iter().take(12).collect();
    if top_hosts.is_empty() {
        return html! {
            <div style="text-align: center; padding: 40px; color: var(--text-muted);">
                { "No hosts found to visualize in communication graph." }
            </div>
        };
    }

    let width = 700.0;
    let height = 360.0;
    let center_x = width / 2.0;
    let center_y = height / 2.0;
    let radius = 130.0;

    let n = top_hosts.len();
    let mut node_coords: Vec<(&HostRecord, f64, f64)> = Vec::new();

    for (i, &h) in top_hosts.iter().enumerate() {
        let angle = (i as f64 / n as f64) * 2.0 * std::f64::consts::PI;
        let x = center_x + radius * angle.cos();
        let y = center_y + radius * angle.sin();
        node_coords.push((h, x, y));
    }

    html! {
        <div style="width: 100%; overflow-x: auto;">
            <svg viewBox={format!("0 0 {} {}", width, height)} style="width: 100%; height: auto; min-width: 500px; display: block;">
                {
                    for props.flows.iter().take(25).filter_map(|flow| {
                        let src_coord = node_coords.iter().find(|(h, _, _)| h.ip == flow.endpoint_a);
                        let dst_coord = node_coords.iter().find(|(h, _, _)| h.ip == flow.endpoint_b);

                        if let (Some((_, x1, y1)), Some((_, x2, y2))) = (src_coord, dst_coord) {
                            let stroke_w = (1.0 + (flow.total_bytes as f64 / 2000.0).log10()).clamp(1.0, 5.0);
                            Some(html! {
                                <line
                                    x1={x1.to_string()}
                                    y1={y1.to_string()}
                                    x2={x2.to_string()}
                                    y2={y2.to_string()}
                                    stroke="rgba(56, 189, 248, 0.35)"
                                    stroke-width={stroke_w.to_string()}
                                >
                                    <title>{ format!("{} ↔ {}: {} packets, {} bytes ({})", flow.endpoint_a, flow.endpoint_b, flow.packet_count, flow.total_bytes, flow.protocol) }</title>
                                </line>
                            })
                        } else {
                            None
                        }
                    })
                }

                {
                    for node_coords.iter().map(|(host, x, y)| {
                        let ip = host.ip.clone();
                        let on_click = {
                            let cb = props.on_host_select.clone();
                            let ip_c = ip.clone();
                            Callback::from(move |_| cb.emit(ip_c.clone()))
                        };

                        let is_dns_or_gateway = host.ip.ends_with(".1") || host.ip == "8.8.8.8" || host.ip == "1.1.1.1";
                        let node_color = if is_dns_or_gateway { "#f59e0b" } else { "#0284c7" };
                        let node_r = (14.0 + (host.total_bytes as f64 / 1000.0).sqrt()).min(24.0);

                        html! {
                            <g style="cursor: pointer;" onclick={on_click}>
                                <circle
                                    cx={x.to_string()}
                                    cy={y.to_string()}
                                    r={node_r.to_string()}
                                    fill={node_color}
                                    stroke="#38bdf8"
                                    stroke-width="2"
                                >
                                    <title>{ format!("Host: {}\nBytes: {}\nPeers: {}", host.ip, host.total_bytes, host.peer_count) }</title>
                                </circle>
                                <text
                                    x={x.to_string()}
                                    y={(y + node_r + 14.0).to_string()}
                                    fill="#f8fafc"
                                    font-size="11"
                                    font-family="var(--font-mono)"
                                    text-anchor="middle"
                                >
                                    { &host.ip }
                                </text>
                            </g>
                        }
                    })
                }
            </svg>
        </div>
    }
}
