use packetscope_core::{
    export_analysis_json, export_findings_csv, export_flows_csv, export_hosts_csv,
    export_html_report, export_packets_csv, CaptureResult,
};
use wasm_bindgen::JsCast;
use web_sys::{Blob, BlobPropertyBag, HtmlAnchorElement, Url};
use yew::prelude::*;

#[derive(Properties, PartialEq)]
pub struct ReportsPageProps {
    pub analysis: CaptureResult,
}

#[function_component(ReportsPage)]
pub fn reports_page(props: &ReportsPageProps) -> Html {
    let report = props.analysis.to_analysis_report();

    let trigger_download = |filename: &str, mime_type: &str, content: &str| {
        let bag = BlobPropertyBag::new();
        bag.set_type(mime_type);
        if let Ok(blob) = Blob::new_with_str_sequence_and_options(
            &js_sys::Array::of1(&wasm_bindgen::JsValue::from_str(content)),
            &bag,
        ) {
            if let Ok(url) = Url::create_object_url_with_blob(&blob) {
                if let Some(window) = web_sys::window() {
                    if let Some(doc) = window.document() {
                        if let Ok(element) = doc.create_element("a") {
                            if let Ok(anchor) = element.dyn_into::<HtmlAnchorElement>() {
                                anchor.set_href(&url);
                                anchor.set_download(filename);
                                anchor.click();
                            }
                        }
                    }
                }
                let _ = Url::revoke_object_url(&url);
            }
        }
    };

    let download_packets_csv = {
        let pkts = props.analysis.packets.clone();
        Callback::from(move |_| {
            let csv = export_packets_csv(&pkts);
            trigger_download("packetscope_packets.csv", "text/csv;charset=utf-8", &csv);
        })
    };

    let download_flows_csv = {
        let flows = props.analysis.flows.clone();
        Callback::from(move |_| {
            let csv = export_flows_csv(&flows);
            trigger_download("packetscope_flows.csv", "text/csv;charset=utf-8", &csv);
        })
    };

    let download_hosts_csv = {
        let hosts = props.analysis.hosts.clone();
        Callback::from(move |_| {
            let csv = export_hosts_csv(&hosts);
            trigger_download("packetscope_hosts.csv", "text/csv;charset=utf-8", &csv);
        })
    };

    let download_findings_csv = {
        let findings = props.analysis.findings.clone();
        Callback::from(move |_| {
            let csv = export_findings_csv(&findings);
            trigger_download("packetscope_findings.csv", "text/csv;charset=utf-8", &csv);
        })
    };

    let download_json = {
        let rep = report.clone();
        Callback::from(move |_| {
            if let Ok(json) = export_analysis_json(&rep) {
                trigger_download(
                    "packetscope_report.json",
                    "application/json;charset=utf-8",
                    &json,
                );
            }
        })
    };

    let download_html = {
        let rep = report.clone();
        Callback::from(move |_| {
            let html_str = export_html_report(&rep);
            trigger_download(
                "packetscope_report.html",
                "text/html;charset=utf-8",
                &html_str,
            );
        })
    };

    html! {
        <div>
            <div class="card">
                <div class="card-header">
                    <div>
                        <h3 class="card-title">{ "Export Analysis Results" }</h3>
                        <span style="font-size: 12px; color: var(--text-muted);">
                            { "All exports sanitize against spreadsheet formula injection and format dates in standard ISO 8601." }
                        </span>
                    </div>
                </div>

                <div style="display: flex; gap: 12px; flex-wrap: wrap;">
                    <button class="btn btn-primary" onclick={download_html}>
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                            <polyline points="14 2 14 8 20 8"></polyline>
                        </svg>
                        <span>{ "Download HTML Report" }</span>
                    </button>
                    <button class="btn btn-secondary" onclick={download_json}>
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="16 18 22 12 16 6"></polyline>
                            <polyline points="8 6 2 12 8 18"></polyline>
                        </svg>
                        <span>{ "Export JSON" }</span>
                    </button>
                    <button class="btn btn-secondary" onclick={download_packets_csv}>
                        <span>{ "Packets CSV" }</span>
                    </button>
                    <button class="btn btn-secondary" onclick={download_flows_csv}>
                        <span>{ "Conversations CSV" }</span>
                    </button>
                    <button class="btn btn-secondary" onclick={download_hosts_csv}>
                        <span>{ "Hosts CSV" }</span>
                    </button>
                    <button class="btn btn-secondary" onclick={download_findings_csv}>
                        <span>{ "Findings CSV" }</span>
                    </button>
                </div>
            </div>

            <div class="card" style="background: var(--bg-secondary); border-color: var(--border-color);">
                <div style="border-bottom: 2px solid var(--border-color); padding-bottom: 16px; margin-bottom: 24px;">
                    <h2 style="font-size: 22px; color: var(--accent-blue); margin-bottom: 6px;">
                        { "Analysis Executive Summary" }
                    </h2>
                    <p style="font-size: 13px; color: var(--text-muted);">
                        { format!("Capture: {} | Generated by PacketScope Client-Side Engine", report.summary.filename) }
                    </p>
                </div>

                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 20px; margin-bottom: 24px;">
                    <div style="background: var(--bg-card); padding: 16px; border-radius: 6px; border: 1px solid var(--border-color);">
                        <h4 style="font-size: 13px; font-weight: 600; color: var(--text-primary); margin-bottom: 8px;">{ "Capture Metadata" }</h4>
                        <div style="font-size: 13px; display: flex; flex-direction: column; gap: 4px;">
                            <div><span style="color: var(--text-muted);">{ "Format: " }</span><span class="mono-cell">{ &report.summary.format_name }</span></div>
                            <div><span style="color: var(--text-muted);">{ "File Size: " }</span><span class="mono-cell">{ format!("{} bytes", report.summary.file_size_bytes) }</span></div>
                            <div><span style="color: var(--text-muted);">{ "Link Layer: " }</span><span class="mono-cell">{ &report.summary.link_type_name }</span></div>
                            <div><span style="color: var(--text-muted);">{ "Precision: " }</span><span class="mono-cell">{ &report.summary.timestamp_precision }</span></div>
                        </div>
                    </div>

                    <div style="background: var(--bg-card); padding: 16px; border-radius: 6px; border: 1px solid var(--border-color);">
                        <h4 style="font-size: 13px; font-weight: 600; color: var(--text-primary); margin-bottom: 8px;">{ "Traffic Totals" }</h4>
                        <div style="font-size: 13px; display: flex; flex-direction: column; gap: 4px;">
                            <div><span style="color: var(--text-muted);">{ "Total Packets: " }</span><span class="mono-cell">{ report.summary.packet_count }</span></div>
                            <div><span style="color: var(--text-muted);">{ "Total Bytes: " }</span><span class="mono-cell">{ format!("{} bytes", report.summary.total_bytes) }</span></div>
                            <div><span style="color: var(--text-muted);">{ "Duration: " }</span><span class="mono-cell">{ format!("{:.3} seconds", report.summary.duration_seconds) }</span></div>
                            <div><span style="color: var(--text-muted);">{ "Unique Hosts: " }</span><span class="mono-cell">{ report.summary.host_count }</span></div>
                        </div>
                    </div>
                </div>

                <div style="background: rgba(15, 23, 42, 0.6); padding: 16px; border-radius: 6px; border: 1px solid var(--border-color); font-size: 13px; color: var(--text-secondary); line-height: 1.7;">
                    <strong style="color: var(--accent-blue); display: block; margin-bottom: 6px;">{ "Analysis Limitations & Notes:" }</strong>
                    <ul style="margin-left: 20px;">
                        {
                            for report.limitations.iter().map(|lim| {
                                html! { <li>{ lim }</li> }
                            })
                        }
                    </ul>
                </div>
            </div>
        </div>
    }
}
