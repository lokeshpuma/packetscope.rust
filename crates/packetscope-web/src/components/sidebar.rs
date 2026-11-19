use crate::routes::AppRoute;
use yew::prelude::*;

#[derive(Properties, PartialEq)]
pub struct SidebarProps {
    pub current_route: AppRoute,
    pub has_capture: bool,
    pub is_collapsed: bool,
    pub is_mobile_open: bool,
    pub on_route_change: Callback<AppRoute>,
    pub on_toggle_collapse: Callback<()>,
}

#[function_component(Sidebar)]
pub fn sidebar(props: &SidebarProps) -> Html {
    let make_nav_item = |route: AppRoute, icon_svg: Html| {
        let is_active = props.current_route == route;
        let is_disabled =
            !props.has_capture && route != AppRoute::Import && route != AppRoute::Settings;
        let on_click = {
            let cb = props.on_route_change.clone();
            Callback::from(move |e: MouseEvent| {
                e.prevent_default();
                if !is_disabled {
                    cb.emit(route);
                }
            })
        };

        let active_class = if is_active { "active" } else { "" };
        let disabled_style = if is_disabled {
            "opacity: 0.4; cursor: not-allowed;"
        } else {
            ""
        };

        html! {
            <button
                class={classes!("nav-item", active_class)}
                style={disabled_style}
                onclick={on_click}
                title={route.title()}
            >
                <span class="nav-icon">{ icon_svg }</span>
                {
                    if !props.is_collapsed {
                        html! { <span>{ route.title() }</span> }
                    } else {
                        html! {}
                    }
                }
            </button>
        }
    };

    let on_toggle = {
        let cb = props.on_toggle_collapse.clone();
        Callback::from(move |_| cb.emit(()))
    };

    let collapse_class = if props.is_collapsed { "collapsed" } else { "" };
    let mobile_class = if props.is_mobile_open {
        "mobile-open"
    } else {
        ""
    };

    html! {
        <aside class={classes!("sidebar", collapse_class, mobile_class)}>
            <nav class="sidebar-nav">
                {
                    make_nav_item(AppRoute::Import, html! {
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                            <polyline points="17 8 12 3 7 8"></polyline>
                            <line x1="12" y1="3" x2="12" y2="15"></line>
                        </svg>
                    })
                }

                {
                    make_nav_item(AppRoute::Overview, html! {
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <rect x="3" y="3" width="7" height="7"></rect>
                            <rect x="14" y="3" width="7" height="7"></rect>
                            <rect x="14" y="14" width="7" height="7"></rect>
                            <rect x="3" y="14" width="7" height="7"></rect>
                        </svg>
                    })
                }

                {
                    make_nav_item(AppRoute::Packets, html! {
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <line x1="8" y1="6" x2="21" y2="6"></line>
                            <line x1="8" y1="12" x2="21" y2="12"></line>
                            <line x1="8" y1="18" x2="21" y2="18"></line>
                            <line x1="3" y1="6" x2="3.01" y2="6"></line>
                            <line x1="3" y1="12" x2="3.01" y2="12"></line>
                            <line x1="3" y1="18" x2="3.01" y2="18"></line>
                        </svg>
                    })
                }

                {
                    make_nav_item(AppRoute::Conversations, html! {
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="17 1 21 5 17 9"></polyline>
                            <path d="M3 11V9a4 4 0 0 1 4-4h14"></path>
                            <polyline points="7 23 3 19 7 15"></polyline>
                            <path d="M21 13v2a4 4 0 0 1-4 4H3"></path>
                        </svg>
                    })
                }

                {
                    make_nav_item(AppRoute::Hosts, html! {
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect>
                            <rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect>
                            <line x1="6" y1="6" x2="6.01" y2="6"></line>
                            <line x1="6" y1="18" x2="6.01" y2="18"></line>
                        </svg>
                    })
                }

                {
                    make_nav_item(AppRoute::Protocols, html! {
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M12 2L2 7l10 5 10-5-10-5z"></path>
                            <path d="M2 17l10 5 10-5"></path>
                            <path d="M2 12l10 5 10-5"></path>
                        </svg>
                    })
                }

                {
                    make_nav_item(AppRoute::DnsAnalytics, html! {
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <circle cx="12" cy="12" r="10"></circle>
                            <line x1="2" y1="12" x2="22" y2="12"></line>
                            <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path>
                        </svg>
                    })
                }

                {
                    make_nav_item(AppRoute::Findings, html! {
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
                            <line x1="12" y1="9" x2="12" y2="13"></line>
                            <line x1="12" y1="17" x2="12.01" y2="17"></line>
                        </svg>
                    })
                }

                {
                    make_nav_item(AppRoute::Timeline, html! {
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline>
                        </svg>
                    })
                }

                {
                    make_nav_item(AppRoute::Reports, html! {
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                            <polyline points="14 2 14 8 20 8"></polyline>
                            <line x1="16" y1="13" x2="8" y2="13"></line>
                            <line x1="16" y1="17" x2="8" y2="17"></line>
                            <polyline points="10 9 9 9 8 9"></polyline>
                        </svg>
                    })
                }

                {
                    make_nav_item(AppRoute::Settings, html! {
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <circle cx="12" cy="12" r="3"></circle>
                            <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path>
                        </svg>
                    })
                }
            </nav>

            <div class="sidebar-bottom">
                <button class="nav-item" onclick={on_toggle} title="Toggle Sidebar">
                    <span class="nav-icon">
                        {
                            if props.is_collapsed {
                                html! {
                                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                        <polyline points="9 18 15 12 9 6"></polyline>
                                    </svg>
                                }
                            } else {
                                html! {
                                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                        <polyline points="15 18 9 12 15 6"></polyline>
                                    </svg>
                                }
                            }
                        }
                    </span>
                    {
                        if !props.is_collapsed {
                            html! { <span>{ "Collapse Sidebar" }</span> }
                        } else {
                            html! {}
                        }
                    }
                </button>
            </div>
        </aside>
    }
}
