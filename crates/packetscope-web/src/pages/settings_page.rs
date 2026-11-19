use crate::state::Theme;
use packetscope_core::RuleConfig;
use yew::prelude::*;

#[derive(Properties, PartialEq)]
pub struct SettingsPageProps {
    pub theme: Theme,
    pub on_theme_toggle: Callback<()>,
    pub rule_config: RuleConfig,
    pub on_rule_config_update: Callback<RuleConfig>,
    pub on_clear_data: Callback<()>,
}

#[function_component(SettingsPage)]
pub fn settings_page(props: &SettingsPageProps) -> Html {
    let burst_val = use_state(|| props.rule_config.burst_baseline_multiplier);
    let fanout_val = use_state(|| props.rule_config.fanout_threshold);
    let rst_val = use_state(|| (props.rule_config.rst_ratio_threshold * 100.0) as u32);
    let dns_val = use_state(|| (props.rule_config.dns_error_ratio_threshold * 100.0) as u32);

    let on_theme_click = {
        let cb = props.on_theme_toggle.clone();
        Callback::from(move |_| cb.emit(()))
    };

    let on_clear_click = {
        let cb = props.on_clear_data.clone();
        Callback::from(move |_| {
            if let Some(window) = web_sys::window() {
                if window
                    .confirm_with_message("Clear current analysis and local session data?")
                    .unwrap_or(false)
                {
                    cb.emit(());
                }
            }
        })
    };

    let on_save_thresholds = {
        let cb = props.on_rule_config_update.clone();
        let b = burst_val.clone();
        let f = fanout_val.clone();
        let r = rst_val.clone();
        let d = dns_val.clone();
        let cfg = props.rule_config.clone();

        Callback::from(move |_| {
            let mut new_cfg = cfg.clone();
            new_cfg.burst_baseline_multiplier = *b;
            new_cfg.fanout_threshold = *f;
            new_cfg.rst_ratio_threshold = (*r as f64) / 100.0;
            new_cfg.dns_error_ratio_threshold = (*d as f64) / 100.0;
            cb.emit(new_cfg);
        })
    };

    html! {
        <div style="max-width: 800px;">
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">{ "Interface & Appearance" }</h3>
                </div>
                <div style="display: flex; align-items: center; justify-content: space-between;">
                    <div>
                        <strong style="font-size: 14px; color: var(--text-primary);">{ "Color Theme" }</strong>
                        <p style="font-size: 13px; color: var(--text-muted);">{ "Toggle between Dark Cyber surface and Clean Light surface." }</p>
                    </div>
                    <button class="btn btn-secondary" onclick={on_theme_click}>
                        {
                            match props.theme {
                                Theme::Dark => "Switch to Light Theme",
                                Theme::Light => "Switch to Dark Theme",
                            }
                        }
                    </button>
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <div>
                        <h3 class="card-title">{ "Heuristic Anomaly Thresholds" }</h3>
                        <span style="font-size: 12px; color: var(--text-muted);">{ "Tune sensitivity parameters for explainable finding detection" }</span>
                    </div>
                </div>

                <div style="display: flex; flex-direction: column; gap: 16px; font-size: 14px;">
                    <div>
                        <label style="display: block; font-weight: 500; margin-bottom: 4px;">
                            { format!("Rule 1: Traffic Burst Multiplier ({:.1}x baseline)", *burst_val) }
                        </label>
                        <input
                            type="range"
                            min="1.5"
                            max="8.0"
                            step="0.5"
                            value={burst_val.to_string()}
                            oninput={
                                let b = burst_val.clone();
                                Callback::from(move |e: InputEvent| {
                                    if let Some(target) = e.target_dyn_into::<web_sys::HtmlInputElement>() {
                                        if let Ok(val) = target.value().parse::<f64>() {
                                            b.set(val);
                                        }
                                    }
                                })
                            }
                            style="width: 100%;"
                        />
                    </div>

                    <div>
                        <label style="display: block; font-weight: 500; margin-bottom: 4px;">
                            { format!("Rule 2: Host Fan-Out Threshold (>= {} unique peers)", *fanout_val) }
                        </label>
                        <input
                            type="range"
                            min="3"
                            max="30"
                            step="1"
                            value={fanout_val.to_string()}
                            oninput={
                                let f = fanout_val.clone();
                                Callback::from(move |e: InputEvent| {
                                    if let Some(target) = e.target_dyn_into::<web_sys::HtmlInputElement>() {
                                        if let Ok(val) = target.value().parse::<usize>() {
                                            f.set(val);
                                        }
                                    }
                                })
                            }
                            style="width: 100%;"
                        />
                    </div>

                    <div>
                        <label style="display: block; font-weight: 500; margin-bottom: 4px;">
                            { format!("Rule 4: High TCP Reset (RST) Ratio (>= {}%)", *rst_val) }
                        </label>
                        <input
                            type="range"
                            min="5"
                            max="50"
                            step="5"
                            value={rst_val.to_string()}
                            oninput={
                                let r = rst_val.clone();
                                Callback::from(move |e: InputEvent| {
                                    if let Some(target) = e.target_dyn_into::<web_sys::HtmlInputElement>() {
                                        if let Ok(val) = target.value().parse::<u32>() {
                                            r.set(val);
                                        }
                                    }
                                })
                            }
                            style="width: 100%;"
                        />
                    </div>

                    <div>
                        <label style="display: block; font-weight: 500; margin-bottom: 4px;">
                            { format!("Rule 5: DNS Error Ratio (>= {}%)", *dns_val) }
                        </label>
                        <input
                            type="range"
                            min="10"
                            max="60"
                            step="5"
                            value={dns_val.to_string()}
                            oninput={
                                let d = dns_val.clone();
                                Callback::from(move |e: InputEvent| {
                                    if let Some(target) = e.target_dyn_into::<web_sys::HtmlInputElement>() {
                                        if let Ok(val) = target.value().parse::<u32>() {
                                            d.set(val);
                                        }
                                    }
                                })
                            }
                            style="width: 100%;"
                        />
                    </div>

                    <button class="btn btn-primary" onclick={on_save_thresholds} style="align-self: flex-start; margin-top: 8px;">
                        { "Apply Heuristic Thresholds" }
                    </button>
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">{ "Local Data & Session Management" }</h3>
                </div>
                <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 16px; line-height: 1.6;">
                    { "PacketScope stores session state and notes locally inside memory and browser storage. Clear local data to immediately wipe all in-memory capture tables and loaded packets." }
                </p>
                <button class="btn btn-danger" onclick={on_clear_click}>
                    { "Clear Current Analysis & Data" }
                </button>
            </div>
        </div>
    }
}
