# Troubleshooting Guide

This guide covers common issues and questions when developing or using PacketScope.

## Common Development Issues

### 1. `error[E0463]: can't find crate for 'core'` with target wasm32
- **Cause**: The `wasm32-unknown-unknown` standard library component is not installed.
- **Resolution**:
  ```bash
  rustup target add wasm32-unknown-unknown
  ```

### 2. Trunk Command Not Found
- **Cause**: Cargo's binary directory is not in your environment `PATH`.
- **Resolution**: Ensure `$HOME/.cargo/bin` is in your shell profile (`~/.zshrc`, `~/.bashrc`, or `~/.zshenv`):
  ```bash
  export PATH="$HOME/.cargo/bin:$PATH"
  ```

### 3. File Refresh / Cache Invalidation During Local Development
- **Cause**: Browser aggressive caching of WebAssembly `.wasm` binaries.
- **Resolution**:
  - Run Trunk with live reloading: `trunk serve`
  - Perform a hard refresh in the browser (`Cmd+Shift+R` or `Ctrl+F5`) or open an incognito window.

## Analysis & Runtime Questions

### 1. File Upload Shows "Invalid capture header"
- **Cause**: The selected file is not a standard PCAP or PCAPNG container, or it was compressed (e.g. `.pcap.gz`).
- **Resolution**: Decompress the capture file prior to upload (`gzip -d capture.pcap.gz`), or verify that the capture file has valid magic bytes using `hexdump -C -n 4 capture.pcap`.

### 2. Large Captures (>100MB) Cause Sluggish UI
- **Cause**: Parsing hundreds of thousands of frames in a single browser thread.
- **Resolution**:
  - For large capture analysis, slice the capture using `editcap` or `tcpdump` to isolate the time window or hosts of interest before loading.
  - Tune heuristic anomaly thresholds in the Settings page to reduce evaluation overhead.
