use packetscope_core::ProtocolLayer;
use yew::prelude::*;

#[derive(Properties, PartialEq)]
pub struct LayerTreeProps {
    pub layers: Vec<ProtocolLayer>,
}

#[function_component(LayerTree)]
pub fn layer_tree(props: &LayerTreeProps) -> Html {
    let expanded_states = use_state(|| vec![true; props.layers.len()]);

    html! {
        <div class="layer-tree">
            {
                for props.layers.iter().enumerate().map(|(idx, layer)| {
                    let is_expanded = expanded_states.get(idx).copied().unwrap_or(true);
                    let toggle_expand = {
                        let states = expanded_states.clone();
                        Callback::from(move |_| {
                            let mut new_states = (*states).clone();
                            if idx < new_states.len() {
                                new_states[idx] = !new_states[idx];
                            }
                            states.set(new_states);
                        })
                    };

                    html! {
                        <div class="layer-item">
                            <div class="layer-header" onclick={toggle_expand}>
                                <span>
                                    { if is_expanded { "▼ " } else { "▶ " } }
                                    { &layer.name }
                                    <span style="color: var(--text-muted); font-size: 11px; margin-left: 8px;">
                                        { format!("({})", &layer.description) }
                                    </span>
                                </span>
                            </div>
                            {
                                if is_expanded {
                                    html! {
                                        <div class="layer-fields">
                                            {
                                                for layer.fields.iter().map(|f| {
                                                    html! {
                                                        <div class="layer-field-row">
                                                            <span class="field-name">{ &f.name }</span>
                                                            <span class="field-value">
                                                                { &f.value }
                                                                {
                                                                    if let Some(ref hex) = f.hex_value {
                                                                        html! {
                                                                            <small style="color: var(--accent-cyan); margin-left: 6px;">
                                                                                { format!("[{}]", hex) }
                                                                            </small>
                                                                        }
                                                                    } else {
                                                                        html! {}
                                                                    }
                                                                }
                                                            </span>
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
                    }
                })
            }
        </div>
    }
}
