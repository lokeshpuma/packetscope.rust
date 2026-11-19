use packetscope_core::{PortStat, ProtocolStat};
use yew::prelude::*;

#[derive(Properties, PartialEq)]
pub struct ProtocolsPageProps {
    pub protocols: Vec<ProtocolStat>,
    pub ports: Vec<PortStat>,
    pub on_filter_packets: Callback<String>,
}

#[function_component(ProtocolsPage)]
pub fn protocols_page(props: &ProtocolsPageProps) -> Html {
    let port_search = use_state(String::new);

    let filtered_ports = use_memo(
        (props.ports.clone(), (*port_search).clone()),
        |(ports, term)| {
            if term.is_empty() {
                ports.clone()
            } else {
                let lower = term.to_lowercase();
                ports
                    .iter()
                    .filter(|p| {
                        p.port.to_string().contains(&lower)
                            || p.service_label.to_lowercase().contains(&lower)
                    })
                    .cloned()
                    .collect()
            }
        },
    );

    let on_search_input = {
        let port_search = port_search.clone();
        Callback::from(move |e: InputEvent| {
            if let Some(target) = e.target_dyn_into::<web_sys::HtmlInputElement>() {
                port_search.set(target.value());
            }
        })
    };

    html! {
        <div>
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">{ "Observed Protocol Distribution" }</h3>
                    <span style="font-size: 12px; color: var(--text-muted);">{ "Decoded network, transport, and application protocols" }</span>
                </div>

                <div class="table-container">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>{ "Protocol" }</th>
                                <th>{ "Packet Count" }</th>
                                <th>{ "Packet %" }</th>
                                <th>{ "Total Bytes" }</th>
                                <th>{ "Byte %" }</th>
                                <th>{ "Distribution" }</th>
                                <th>{ "Action" }</th>
                            </tr>
                        </thead>
                        <tbody>
                            {
                                for props.protocols.iter().map(|proto| {
                                    let on_filter = {
                                        let cb = props.on_filter_packets.clone();
                                        let name = proto.name.clone();
                                        Callback::from(move |_| cb.emit(format!("protocol == \"{}\"", name)))
                                    };

                                    html! {
                                        <tr>
                                            <td><strong style="color: var(--accent-blue);">{ &proto.name }</strong></td>
                                            <td class="mono-cell">{ proto.packet_count }</td>
                                            <td class="mono-cell">{ format!("{:.1}%", proto.percentage_packets) }</td>
                                            <td class="mono-cell">{ format!("{:.1} KB", proto.byte_count as f64 / 1024.0) }</td>
                                            <td class="mono-cell">{ format!("{:.1}%", proto.percentage_bytes) }</td>
                                            <td style="width: 140px;">
                                                <div style="height: 6px; background: var(--bg-input); border-radius: 3px; overflow: hidden; width: 100%;">
                                                    <div style={format!("height: 100%; background: var(--accent-blue); width: {:.0}%;", proto.percentage_bytes)}></div>
                                                </div>
                                            </td>
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

            <div class="card">
                <div class="card-header" style="flex-wrap: wrap; gap: 12px;">
                    <div>
                        <h3 class="card-title">{ "Port Utilization & Service Mapping" }</h3>
                        <span style="font-size: 12px; color: var(--text-muted);">
                            { "Standard port labels represent conventional services, not verified protocol identities." }
                        </span>
                    </div>

                    <input
                        type="text"
                        class="filter-input"
                        placeholder="Search port or service..."
                        style="max-width: 240px; padding: 6px 12px; font-size: 12px;"
                        value={(*port_search).clone()}
                        oninput={on_search_input}
                    />
                </div>

                <div class="table-container">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>{ "Port" }</th>
                                <th>{ "Service Label" }</th>
                                <th>{ "Packets" }</th>
                                <th>{ "Volume" }</th>
                                <th>{ "As Source" }</th>
                                <th>{ "As Destination" }</th>
                                <th>{ "Action" }</th>
                            </tr>
                        </thead>
                        <tbody>
                            {
                                if filtered_ports.is_empty() {
                                    html! {
                                        <tr>
                                            <td colspan="7" style="text-align: center; padding: 40px; color: var(--text-muted);">
                                                { "No matching ports found." }
                                            </td>
                                        </tr>
                                    }
                                } else {
                                    html! {
                                        {
                                            for filtered_ports.iter().take(50).map(|port| {
                                                let on_filter = {
                                                    let cb = props.on_filter_packets.clone();
                                                    let p_num = port.port;
                                                    Callback::from(move |_| cb.emit(format!("tcp.port == {} or udp.port == {}", p_num, p_num)))
                                                };

                                                html! {
                                                    <tr>
                                                        <td class="mono-cell" style="font-weight: 600; color: var(--accent-blue);">{ port.port }</td>
                                                        <td><span class="badge badge-info">{ &port.service_label }</span></td>
                                                        <td class="mono-cell">{ port.packet_count }</td>
                                                        <td class="mono-cell">{ format!("{:.1} KB", port.byte_count as f64 / 1024.0) }</td>
                                                        <td class="mono-cell">{ port.as_source_count }</td>
                                                        <td class="mono-cell">{ port.as_destination_count }</td>
                                                        <td>
                                                            <button class="btn btn-secondary btn-sm" onclick={on_filter}>
                                                                { "Filter" }
                                                            </button>
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
            </div>
        </div>
    }
}
