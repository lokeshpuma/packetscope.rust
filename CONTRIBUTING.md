# Contributing to PacketScope

Thank you for contributing to PacketScope! We welcome bug reports, feature requests, protocol decoders, and documentation improvements.

## Development Setup

1. **Prerequisites**:
   - Rust 1.80+ (Stable)
   - Trunk (`cargo install trunk`)
   - `wasm32-unknown-unknown` target (`rustup target add wasm32-unknown-unknown`)

2. **Clone and Build**:
   ```bash
   git clone https://github.com/your-username/packetscope-rust.git
   cd packetscope-rust
   cargo test --workspace
   trunk serve
   ```
   Open `http://127.0.0.1:8080` in your browser.

## Code Quality Standards

Before submitting a pull request, please verify that your changes adhere to our continuous integration gates:

1. **Formatting**:
   ```bash
   cargo fmt --check
   ```
2. **Clippy Linter**:
   ```bash
   cargo clippy --workspace --all-targets -- -D warnings
   ```
3. **Tests**:
   ```bash
   cargo test --workspace
   ```
4. **WASM Compilation**:
   ```bash
   trunk build
   ```

## Adding New Protocol Decoders

Protocol decoders reside in `crates/packetscope-core/src/protocols/`:
1. Implement dissection functions that accept byte slices and return structured field definitions.
2. Ensure all slice indexing is bounds-checked and safe against truncated data.
3. Add corresponding test fixtures in `crates/packetscope-core/tests/` to guarantee parser robustness.
