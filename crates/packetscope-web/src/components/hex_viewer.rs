use yew::prelude::*;

#[derive(Properties, PartialEq)]
pub struct HexViewerProps {
    pub bytes: Vec<u8>,
}

#[function_component(HexViewer)]
pub fn hex_viewer(props: &HexViewerProps) -> Html {
    let lines = use_memo(props.bytes.clone(), |data| {
        let mut result = Vec::new();
        let chunk_size = 16;
        for (i, chunk) in data.chunks(chunk_size).enumerate() {
            let offset = format!("{:04x}:", i * chunk_size);

            let mut hex_parts = Vec::new();
            for b in chunk {
                hex_parts.push(format!("{:02x}", b));
            }
            while hex_parts.len() < chunk_size {
                hex_parts.push("  ".to_string());
            }

            let ascii_str: String = chunk
                .iter()
                .map(|&b| {
                    if (32..=126).contains(&b) {
                        b as char
                    } else {
                        '.'
                    }
                })
                .collect();

            result.push((offset, hex_parts.join(" "), ascii_str));
        }
        result
    });

    html! {
        <div class="hex-viewer">
            {
                for lines.iter().map(|(offset, hex_bytes, ascii)| {
                    html! {
                        <div class="hex-line">
                            <span class="hex-offset">{ offset }</span>
                            <span class="hex-bytes">{ hex_bytes }</span>
                            <span class="hex-ascii">{ ascii }</span>
                        </div>
                    }
                })
            }
        </div>
    }
}
