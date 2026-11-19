use packetscope_core::TimelineAnalysis;
use yew::prelude::*;

#[derive(Properties, PartialEq)]
pub struct TimelineChartProps {
    pub timeline: TimelineAnalysis,
    #[prop_or_default]
    pub on_bucket_select: Option<Callback<usize>>,
}

#[function_component(TimelineChart)]
pub fn timeline_chart(props: &TimelineChartProps) -> Html {
    let buckets = &props.timeline.buckets;
    if buckets.is_empty() {
        return html! {
            <div style="text-align: center; padding: 40px; color: var(--text-muted);">
                { "No timeline bucket data available for this capture." }
            </div>
        };
    }

    let width = 800.0;
    let height = 180.0;
    let padding_left = 50.0;
    let padding_right = 20.0;
    let padding_top = 20.0;
    let padding_bottom = 30.0;

    let chart_w = width - padding_left - padding_right;
    let chart_h = height - padding_top - padding_bottom;

    let max_pps = if props.timeline.max_pps > 0.0 {
        props.timeline.max_pps
    } else {
        1.0
    };
    let n = buckets.len();

    // Generate SVG path for PPS line
    let mut line_points = Vec::new();
    let mut area_points = Vec::new();

    area_points.push(format!("{},{}", padding_left, height - padding_bottom));

    for (i, b) in buckets.iter().enumerate() {
        let x = padding_left + (i as f64 / (n.max(2) - 1) as f64) * chart_w;
        let y = padding_top + chart_h - (b.packets_per_second / max_pps) * chart_h;
        line_points.push(format!("{},{}", x, y));
        area_points.push(format!("{},{}", x, y));
    }

    area_points.push(format!(
        "{},{}",
        padding_left + chart_w,
        height - padding_bottom
    ));

    let line_d = format!("M {}", line_points.join(" L "));
    let area_d = format!("M {} Z", area_points.join(" L "));

    html! {
        <div style="width: 100%; overflow-x: auto;">
            <svg viewBox={format!("0 0 {} {}", width, height)} style="width: 100%; height: auto; min-width: 500px; display: block;">
                <line x1={padding_left.to_string()} y1={padding_top.to_string()} x2={(padding_left + chart_w).to_string()} y2={padding_top.to_string()} stroke="#2b3952" stroke-dasharray="3 3"/>
                <line x1={padding_left.to_string()} y1={(padding_top + chart_h / 2.0).to_string()} x2={(padding_left + chart_w).to_string()} y2={(padding_top + chart_h / 2.0).to_string()} stroke="#2b3952" stroke-dasharray="3 3"/>
                <line x1={padding_left.to_string()} y1={(height - padding_bottom).to_string()} x2={(padding_left + chart_w).to_string()} y2={(height - padding_bottom).to_string()} stroke="#2b3952"/>

                <text x="42" y={(padding_top + 4.0).to_string()} fill="#94a3b8" font-size="10" text-anchor="end">{ format!("{:.0}", max_pps) }</text>
                <text x="42" y={(padding_top + chart_h / 2.0 + 4.0).to_string()} fill="#94a3b8" font-size="10" text-anchor="end">{ format!("{:.0}", max_pps / 2.0) }</text>
                <text x="42" y={(height - padding_bottom).to_string()} fill="#94a3b8" font-size="10" text-anchor="end">{ "0" }</text>

                <defs>
                    <linearGradient id="pps-gradient" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stop-color="#38bdf8" stop-opacity="0.35"/>
                        <stop offset="100%" stop-color="#0284c7" stop-opacity="0.0"/>
                    </linearGradient>
                </defs>

                <path d={area_d} fill="url(#pps-gradient)"/>
                <path d={line_d} fill="none" stroke="#38bdf8" stroke-width="2.5" stroke-linejoin="round"/>

                {
                    for buckets.iter().enumerate().map(|(i, b)| {
                        let x = padding_left + (i as f64 / (n.max(2) - 1) as f64) * chart_w;
                        let y = padding_top + chart_h - (b.packets_per_second / max_pps) * chart_h;
                        html! {
                            <circle
                                cx={x.to_string()}
                                cy={y.to_string()}
                                r="4"
                                fill="#06b6d4"
                                stroke="#0b0f19"
                                stroke-width="1.5"
                            >
                                <title>{ format!("Time: {}\nPackets/s: {:.1}\nVolume: {} bytes", b.timestamp_iso, b.packets_per_second, b.byte_count) }</title>
                            </circle>
                        }
                    })
                }

                {
                    if let Some(first) = buckets.first() {
                        html! {
                            <text x={padding_left.to_string()} y={(height - 10.0).to_string()} fill="#64748b" font-size="10" text-anchor="start">
                                { &first.timestamp_iso }
                            </text>
                        }
                    } else { html! {} }
                }
                {
                    if let Some(last) = buckets.last() {
                        html! {
                            <text x={(padding_left + chart_w).to_string()} y={(height - 10.0).to_string()} fill="#64748b" font-size="10" text-anchor="end">
                                { &last.timestamp_iso }
                            </text>
                        }
                    } else { html! {} }
                }
            </svg>
        </div>
    }
}
