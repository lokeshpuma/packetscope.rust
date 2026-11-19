use gloo_file::callbacks::FileReader;
use gloo_file::File;
use web_sys::DragEvent;
use yew::prelude::*;

#[derive(Properties, PartialEq)]
pub struct ImportPageProps {
    pub is_analyzing: bool,
    pub progress: f64,
    pub stage: String,
    pub error_message: Option<String>,
    pub on_file_loaded: Callback<(String, Vec<u8>)>,
    pub on_load_demo: Callback<()>,
}

#[function_component(ImportPage)]
pub fn import_page(props: &ImportPageProps) -> Html {
    let is_drag_over = use_state(|| false);
    let file_reader = use_state(|| None::<FileReader>);

    let on_drag_over = {
        let is_drag_over = is_drag_over.clone();
        Callback::from(move |e: DragEvent| {
            e.prevent_default();
            is_drag_over.set(true);
        })
    };

    let on_drag_leave = {
        let is_drag_over = is_drag_over.clone();
        Callback::from(move |e: DragEvent| {
            e.prevent_default();
            is_drag_over.set(false);
        })
    };

    let read_file_blob = {
        let on_file_loaded = props.on_file_loaded.clone();
        let file_reader = file_reader.clone();
        Callback::from(move |file: web_sys::File| {
            let gloo_file = File::from(file);
            let filename = gloo_file.name();
            let on_loaded = on_file_loaded.clone();

            let task = gloo_file::callbacks::read_as_bytes(&gloo_file, move |res| {
                if let Ok(bytes) = res {
                    on_loaded.emit((filename, bytes));
                }
            });
            file_reader.set(Some(task));
        })
    };

    let on_drop = {
        let is_drag_over = is_drag_over.clone();
        let read_blob = read_file_blob.clone();
        Callback::from(move |e: DragEvent| {
            e.prevent_default();
            is_drag_over.set(false);
            if let Some(dt) = e.data_transfer() {
                if let Some(files) = dt.files() {
                    if let Some(file) = files.get(0) {
                        read_blob.emit(file);
                    }
                }
            }
        })
    };

    let on_file_input_change = {
        let read_blob = read_file_blob.clone();
        Callback::from(move |e: Event| {
            if let Some(input) = e.target_dyn_into::<web_sys::HtmlInputElement>() {
                if let Some(files) = input.files() {
                    if let Some(file) = files.get(0) {
                        read_blob.emit(file);
                    }
                }
            }
        })
    };

    let on_demo_click = {
        let cb = props.on_load_demo.clone();
        Callback::from(move |_| cb.emit(()))
    };

    let drop_class = if *is_drag_over {
        "dropzone active"
    } else {
        "dropzone"
    };

    html! {
        <div style="max-width: 800px; margin: 40px auto; padding: 0 16px;">
            <div style="text-align: center; margin-bottom: 32px;">
                <h1 style="font-size: 32px; font-weight: 800; color: var(--text-primary); margin-bottom: 12px; letter-spacing: -0.5px;">
                    { "Understand Your Network Traffic." }
                </h1>
                <p style="font-size: 16px; color: var(--text-secondary); max-width: 620px; margin: 0 auto; line-height: 1.6;">
                    { "Import a packet capture, inspect decoded communication patterns, analyze protocols, and discover unusual activity — directly inside your browser." }
                </p>
            </div>

            {
                if let Some(ref err) = props.error_message {
                    html! {
                        <div style="background: rgba(239, 68, 68, 0.12); border: 1px solid rgba(239, 68, 68, 0.3); border-radius: 8px; padding: 14px 18px; color: var(--badge-red); margin-bottom: 24px; display: flex; align-items: center; gap: 12px;">
                            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <circle cx="12" cy="12" r="10"></circle>
                                <line x1="12" y1="8" x2="12" y2="12"></line>
                                <line x1="12" y1="16" x2="12.01" y2="16"></line>
                            </svg>
                            <div>
                                <strong>{ "Capture Load Error: " }</strong>
                                <span>{ err }</span>
                            </div>
                        </div>
                    }
                } else {
                    html! {}
                }
            }

            {
                if props.is_analyzing {
                    html! {
                        <div class="card" style="text-align: center; padding: 40px 24px;">
                            <h3 style="color: var(--accent-blue); margin-bottom: 8px;">{ "Analyzing Capture Locally" }</h3>
                            <p style="color: var(--text-secondary); font-size: 14px; margin-bottom: 16px;">
                                { &props.stage }
                            </p>
                            <div class="progress-container">
                                <div class="progress-bar" style={format!("width: {:.0}%;", props.progress * 100.0)}></div>
                            </div>
                            <span style="font-family: var(--font-mono); font-size: 13px; color: var(--text-muted);">
                                { format!("{:.0}% complete", props.progress * 100.0) }
                            </span>
                        </div>
                    }
                } else {
                    html! {
                        <>
                            <div
                                class={drop_class}
                                ondragover={on_drag_over}
                                ondragleave={on_drag_leave}
                                ondrop={on_drop}
                            >
                                <svg class="dropzone-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                                    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                                    <polyline points="17 8 12 3 7 8"></polyline>
                                    <line x1="12" y1="3" x2="12" y2="15"></line>
                                </svg>
                                <div>
                                    <h3 style="font-size: 18px; font-weight: 600; color: var(--text-primary); margin-bottom: 6px;">
                                        { "Drag & drop packet capture file here" }
                                    </h3>
                                    <p style="font-size: 14px; color: var(--text-muted);">
                                        { "Supports standard .pcap and .pcapng files up to 100 MB" }
                                    </p>
                                </div>

                                <label class="btn btn-primary" style="cursor: pointer; margin-top: 8px;">
                                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                        <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path>
                                    </svg>
                                    <span>{ "Browse Capture File" }</span>
                                    <input
                                        type="file"
                                        accept=".pcap,.pcapng,.cap"
                                        style="display: none;"
                                        onchange={on_file_input_change}
                                    />
                                </label>
                            </div>

                            <div style="display: flex; align-items: center; justify-content: center; gap: 16px; margin-top: 24px;">
                                <span style="font-size: 13px; color: var(--text-muted);">{ "Don't have a capture file ready?" }</span>
                                <button class="btn btn-secondary" onclick={on_demo_click}>
                                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                        <polygon points="5 3 19 12 5 21 5 3"></polygon>
                                    </svg>
                                    <span>{ "Load Demo Capture" }</span>
                                </button>
                            </div>

                            <div class="card" style="margin-top: 36px; background: rgba(15, 23, 42, 0.4);">
                                <h4 style="font-size: 14px; font-weight: 600; color: var(--text-primary); margin-bottom: 12px; display: flex; align-items: center; gap: 8px;">
                                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" color="var(--badge-green)">
                                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                                    </svg>
                                    <span>{ "Privacy & Security Guarantee" }</span>
                                </h4>
                                <ul style="font-size: 13px; color: var(--text-secondary); line-height: 1.8; margin-left: 20px;">
                                    <li>{ "All packet parsing and traffic analysis occurs 100% locally inside your browser's WebAssembly sandbox." }</li>
                                    <li>{ "Original capture files and packet payloads are NEVER uploaded or transmitted to any external server." }</li>
                                    <li>{ "No accounts, external trackers, or telemetry cookies required." }</li>
                                    <li>{ "Safe execution: packet content is never interpreted as HTML or script code." }</li>
                                </ul>
                            </div>
                        </>
                    }
                }
            }
        </div>
    }
}
