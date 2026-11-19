use packetscope_core::{Finding, ReviewStatus};
use yew::prelude::*;

#[derive(Properties, PartialEq)]
pub struct FindingsPageProps {
    pub findings: Vec<Finding>,
    pub selected_finding_id: Option<String>,
    pub on_finding_select: Callback<Option<String>>,
    pub on_status_toggle: Callback<String>,
    pub on_note_update: Callback<(String, String)>,
    pub on_filter_packets: Callback<String>,
}

#[function_component(FindingsPage)]
pub fn findings_page(props: &FindingsPageProps) -> Html {
    let severity_filter = use_state(|| "All");

    let filtered_findings = use_memo(
        (props.findings.clone(), (*severity_filter)),
        |(findings, filter)| {
            if *filter == "All" {
                findings.clone()
            } else {
                findings
                    .iter()
                    .filter(|f| f.severity.as_str() == *filter)
                    .cloned()
                    .collect()
            }
        },
    );

    let selected_finding = props
        .selected_finding_id
        .as_ref()
        .and_then(|id| props.findings.iter().find(|f| f.id == *id).cloned());

    let close_drawer = {
        let cb = props.on_finding_select.clone();
        Callback::from(move |_| cb.emit(None))
    };

    html! {
        <div>
            <div class="card" style="background: rgba(30, 41, 59, 0.4); border-color: rgba(56, 189, 248, 0.2); margin-bottom: 20px;">
                <h3 style="font-size: 15px; color: var(--accent-blue); margin-bottom: 6px;">
                    { "Explainable Heuristic Analysis Engine" }
                </h3>
                <p style="font-size: 13px; color: var(--text-secondary); line-height: 1.6;">
                    { "Findings highlight statistically unusual network patterns based on configurable baseline rules. Observations provide actionable evidence and suggested investigation paths; heuristic results should never be interpreted as confirmed network attacks." }
                </p>
            </div>

            <div style="display: flex; align-items: center; justify-content: space-between; gap: 16px; margin-bottom: 20px; flex-wrap: wrap;">
                <div style="display: flex; align-items: center; gap: 8px;">
                    <span style="font-size: 13px; color: var(--text-muted);">{ "Filter Severity:" }</span>
                    {
                        for ["All", "High", "Medium", "Low", "Info"].iter().map(|&sev| {
                            let is_active = *severity_filter == sev;
                            let on_click = {
                                let sf = severity_filter.clone();
                                Callback::from(move |_| sf.set(sev))
                            };
                            html! {
                                <button
                                    class={classes!("btn", "btn-sm", if is_active { "btn-primary" } else { "btn-secondary" })}
                                    onclick={on_click}
                                >
                                    { sev }
                                </button>
                            }
                        })
                    }
                </div>

                <span style="font-size: 13px; color: var(--text-muted);">
                    { format!("{} total observations", props.findings.len()) }
                </span>
            </div>

            <div class="table-container">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th style="width: 80px;">{ "ID" }</th>
                            <th style="width: 100px;">{ "Severity" }</th>
                            <th>{ "Title" }</th>
                            <th>{ "Category" }</th>
                            <th>{ "Affected Host" }</th>
                            <th>{ "Status" }</th>
                            <th>{ "Observed Value" }</th>
                            <th>{ "Action" }</th>
                        </tr>
                    </thead>
                    <tbody>
                        {
                            if filtered_findings.is_empty() {
                                html! {
                                    <tr>
                                        <td colspan="8" style="text-align: center; padding: 40px; color: var(--text-muted);">
                                            { "No heuristic findings match the selected filter." }
                                        </td>
                                    </tr>
                                }
                            } else {
                                html! {
                                    {
                                        for filtered_findings.iter().map(|f| {
                                            let is_selected = props.selected_finding_id.as_deref() == Some(&f.id);
                                            let row_class = if is_selected { "selected" } else { "" };
                                            let id = f.id.clone();
                                            let on_click = {
                                                let cb = props.on_finding_select.clone();
                                                let id_c = id.clone();
                                                Callback::from(move |_| cb.emit(Some(id_c.clone())))
                                            };

                                            let on_toggle = {
                                                let cb = props.on_status_toggle.clone();
                                                let id_c = id.clone();
                                                Callback::from(move |e: MouseEvent| {
                                                    e.stop_propagation();
                                                    cb.emit(id_c.clone());
                                                })
                                            };

                                            let badge_cls = match f.severity.as_str() {
                                                "High" => "badge-high",
                                                "Medium" => "badge-medium",
                                                "Low" => "badge-low",
                                                _ => "badge-info",
                                            };

                                            let status_cls = match f.status {
                                                ReviewStatus::Reviewed => "badge-low",
                                                ReviewStatus::New => "badge-info",
                                            };

                                            html! {
                                                <tr class={row_class} onclick={on_click}>
                                                    <td class="mono-cell">{ &f.id }</td>
                                                    <td><span class={classes!("badge", badge_cls)}>{ f.severity.as_str() }</span></td>
                                                    <td>
                                                        <strong style="color: var(--text-primary);">{ &f.title }</strong>
                                                    </td>
                                                    <td>{ &f.category }</td>
                                                    <td class="mono-cell">{ f.affected_host.as_deref().unwrap_or("Network") }</td>
                                                    <td>
                                                        <span class={classes!("badge", status_cls)}>{ f.status.as_str() }</span>
                                                    </td>
                                                    <td class="mono-cell" style="font-size: 11px;">{ &f.observed_value }</td>
                                                    <td>
                                                        <button class="btn btn-secondary btn-sm" onclick={on_toggle}>
                                                            { if f.status == ReviewStatus::New { "Mark Reviewed" } else { "Reopen" } }
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

            {
                if let Some(finding) = selected_finding {
                    let on_toggle_btn = {
                        let cb = props.on_status_toggle.clone();
                        let id = finding.id.clone();
                        Callback::from(move |_| cb.emit(id.clone()))
                    };

                    let on_filter_host = {
                        let cb = props.on_filter_packets.clone();
                        let host = finding.affected_host.clone();
                        Callback::from(move |_| {
                            if let Some(ref h) = host {
                                cb.emit(format!("host == {}", h));
                            }
                        })
                    };

                    let on_note_change = {
                        let cb = props.on_note_update.clone();
                        let id = finding.id.clone();
                        Callback::from(move |e: InputEvent| {
                            if let Some(target) = e.target_dyn_into::<web_sys::HtmlTextAreaElement>() {
                                cb.emit((id.clone(), target.value()));
                            }
                        })
                    };

                    let badge_cls = match finding.severity.as_str() {
                        "High" => "badge-high",
                        "Medium" => "badge-medium",
                        "Low" => "badge-low",
                        _ => "badge-info",
                    };

                    html! {
                        <div class="detail-drawer">
                            <div class="drawer-header">
                                <div>
                                    <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 4px;">
                                        <span class={classes!("badge", badge_cls)}>{ finding.severity.as_str() }</span>
                                        <span class="mono-cell" style="color: var(--text-muted); font-size: 12px;">{ &finding.id }</span>
                                    </div>
                                    <h3 style="font-size: 16px; font-weight: 700; color: var(--text-primary);">
                                        { &finding.title }
                                    </h3>
                                </div>
                                <button class="btn btn-secondary btn-sm" onclick={close_drawer}>
                                    { "✕" }
                                </button>
                            </div>

                            <div style="display: flex; gap: 8px;">
                                <button class="btn btn-secondary btn-sm" onclick={on_toggle_btn}>
                                    { if finding.status == ReviewStatus::New { "✓ Mark as Reviewed" } else { "↺ Mark as New" } }
                                </button>
                                {
                                    if finding.affected_host.is_some() {
                                        html! {
                                            <button class="btn btn-primary btn-sm" onclick={on_filter_host}>
                                                { "Filter Affected Host" }
                                            </button>
                                        }
                                    } else {
                                        html! {}
                                    }
                                }
                            </div>

                            <div class="card" style="margin-bottom: 0;">
                                <h4 style="font-size: 13px; font-weight: 600; color: var(--accent-blue); margin-bottom: 6px;">
                                    { "What Happened" }
                                </h4>
                                <p style="font-size: 13px; color: var(--text-primary); line-height: 1.6; margin-bottom: 12px;">
                                    { &finding.what_happened }
                                </p>

                                <h4 style="font-size: 13px; font-weight: 600; color: var(--accent-blue); margin-bottom: 6px;">
                                    { "Why Flagged" }
                                </h4>
                                <p style="font-size: 13px; color: var(--text-secondary); line-height: 1.6;">
                                    { &finding.why_flagged }
                                </p>
                            </div>

                            <div class="card" style="margin-bottom: 0;">
                                <h4 style="font-size: 13px; font-weight: 600; color: var(--text-primary); margin-bottom: 10px;">
                                    { "Rule Evidence & Threshold" }
                                </h4>
                                <div style="display: flex; flex-direction: column; gap: 8px; font-size: 13px;">
                                    <div style="display: flex; justify-content: space-between;">
                                        <span style="color: var(--text-muted);">{ "Rule Triggered:" }</span>
                                        <span class="mono-cell">{ &finding.rule_name }</span>
                                    </div>
                                    <div style="display: flex; justify-content: space-between;">
                                        <span style="color: var(--text-muted);">{ "Configured Threshold:" }</span>
                                        <span class="mono-cell" style="color: var(--accent-cyan);">{ &finding.configured_threshold }</span>
                                    </div>
                                    <div style="display: flex; justify-content: space-between;">
                                        <span style="color: var(--text-muted);">{ "Observed Metric:" }</span>
                                        <span class="mono-cell" style="color: var(--badge-amber); font-weight: 600;">{ &finding.observed_value }</span>
                                    </div>
                                    <div style="display: flex; justify-content: space-between;">
                                        <span style="color: var(--text-muted);">{ "Time Window:" }</span>
                                        <span class="mono-cell" style="font-size: 11px;">{ &finding.first_seen_iso }</span>
                                    </div>
                                </div>
                            </div>

                            <div class="card" style="margin-bottom: 0;">
                                <h4 style="font-size: 13px; font-weight: 600; color: var(--text-primary); margin-bottom: 8px;">
                                    { "Recommended Investigation Steps" }
                                </h4>
                                <ol style="font-size: 13px; color: var(--text-secondary); line-height: 1.8; margin-left: 20px;">
                                    {
                                        for finding.investigation_steps.iter().map(|step| {
                                            html! { <li>{ step }</li> }
                                        })
                                    }
                                </ol>
                            </div>

                            <div class="card" style="margin-bottom: 0;">
                                <h4 style="font-size: 13px; font-weight: 600; color: var(--text-primary); margin-bottom: 8px;">
                                    { "Analyst Notes" }
                                </h4>
                                <textarea
                                    class="filter-input"
                                    rows="3"
                                    placeholder="Add investigation conclusions or ticket references..."
                                    value={finding.notes.clone()}
                                    oninput={on_note_change}
                                    style="width: 100%; font-family: var(--font-sans); font-size: 13px; resize: vertical;"
                                />
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
