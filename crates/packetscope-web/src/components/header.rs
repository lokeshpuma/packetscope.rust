use crate::routes::AppRoute;
use crate::state::Theme;
use yew::prelude::*;

#[derive(Properties, PartialEq)]
pub struct HeaderProps {
    pub capture_name: Option<String>,
    pub is_demo: bool,
    pub theme: Theme,
    pub on_theme_toggle: Callback<()>,
    pub on_route_change: Callback<AppRoute>,
    pub on_mobile_toggle: Callback<()>,
    pub search_query: String,
    pub on_search_change: Callback<String>,
}

#[function_component(Header)]
pub fn header(props: &HeaderProps) -> Html {
    let on_search_input = {
        let cb = props.on_search_change.clone();
        Callback::from(move |e: InputEvent| {
            if let Some(target) = e.target_dyn_into::<web_sys::HtmlInputElement>() {
                cb.emit(target.value());
            }
        })
    };

    let on_brand_click = {
        let cb = props.on_route_change.clone();
        let target = if props.capture_name.is_some() {
            AppRoute::Overview
        } else {
            AppRoute::Import
        };
        Callback::from(move |e: MouseEvent| {
            e.prevent_default();
            cb.emit(target);
        })
    };

    let on_theme_click = {
        let cb = props.on_theme_toggle.clone();
        Callback::from(move |_| cb.emit(()))
    };

    let on_burger_click = {
        let cb = props.on_mobile_toggle.clone();
        Callback::from(move |_| cb.emit(()))
    };

    html! {
        <header class="global-header">
            <div class="header-left">
                <button class="btn btn-secondary btn-sm" onclick={on_burger_click} title="Toggle Navigation Menu">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <line x1="3" y1="12" x2="21" y2="12"></line>
                        <line x1="3" y1="6" x2="21" y2="6"></line>
                        <line x1="3" y1="18" x2="21" y2="18"></line>
                    </svg>
                </button>
                <a href="#import" class="app-brand" onclick={on_brand_click}>
                    <svg width="28" height="28" viewBox="0 0 32 32" fill="none">
                        <rect width="32" height="32" rx="8" fill="#1e293b" stroke="#334155" stroke-width="1.5"/>
                        <circle cx="16" cy="16" r="10" stroke="#38bdf8" stroke-width="2" stroke-dasharray="3 2"/>
                        <circle cx="16" cy="16" r="3" fill="#38bdf8"/>
                    </svg>
                    <span>{ "Packet" }<span style="color: var(--accent-blue);">{ "Scope" }</span></span>
                </a>

                {
                    if let Some(ref name) = props.capture_name {
                        html! {
                            <div class="capture-indicator">
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                                    <polyline points="14 2 14 8 20 8"></polyline>
                                </svg>
                                <span>{ name }</span>
                            </div>
                        }
                    } else {
                        html! {}
                    }
                }

                {
                    if props.is_demo {
                        html! {
                            <span class="demo-badge-indicator">{ "DEMO DATA" }</span>
                        }
                    } else {
                        html! {}
                    }
                }
            </div>

            <div class="header-right">
                <input
                    type="text"
                    class="filter-input"
                    placeholder="Global search (IP, port, domain)..."
                    style="width: 240px; padding: 6px 12px; font-size: 12px;"
                    value={props.search_query.clone()}
                    oninput={on_search_input}
                />

                <div class="privacy-badge" title="Original packets are analyzed inside your browser's WebAssembly sandbox. Never transmitted to a server.">
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                    </svg>
                    <span>{ "Local Processing" }</span>
                </div>

                <button class="btn btn-secondary btn-sm" onclick={on_theme_click} title="Switch Dark / Light Theme">
                    {
                        match props.theme {
                            Theme::Dark => html! {
                                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <circle cx="12" cy="12" r="5"></circle>
                                    <line x1="12" y1="1" x2="12" y2="3"></line>
                                    <line x1="12" y1="21" x2="12" y2="23"></line>
                                    <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line>
                                    <line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line>
                                    <line x1="1" y1="12" x2="3" y2="12"></line>
                                    <line x1="21" y1="12" x2="23" y2="12"></line>
                                    <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line>
                                    <line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line>
                                </svg>
                            },
                            Theme::Light => html! {
                                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path>
                                </svg>
                            },
                        }
                    }
                </button>
            </div>
        </header>
    }
}
