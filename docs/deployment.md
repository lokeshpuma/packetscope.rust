# Deployment Guide

PacketScope is a static WebAssembly client application that can be hosted on any static web host, CDN, or object store without requiring a backend runtime.

## Deploying to GitHub Pages

PacketScope includes a GitHub Actions deployment workflow at `.github/workflows/deploy-pages.yml`.

### Step-by-Step Setup
1. Push your repository to GitHub.
2. In your repository settings on GitHub, navigate to **Settings** → **Pages**.
3. Under **Build and deployment**, set **Source** to **GitHub Actions**.
4. Push to `main` (or run the workflow manually via `workflow_dispatch`).
5. GitHub Actions will compile the Rust source to WebAssembly via Trunk and deploy the distribution artifacts directly to GitHub Pages.

## Manual Static Hosting Build

To build the static distribution bundle manually for hosting on Nginx, Apache, Cloudflare Pages, Vercel, or Netlify:

```bash
# Install Trunk if not already installed
cargo install --locked trunk

# Add the WebAssembly target
rustup target add wasm32-unknown-unknown

# Build the release bundle
trunk build --release --public-url /
```

The output artifacts will be placed in the `dist/` directory:
- `index.html`
- `packetscope-web-<hash>.js`
- `packetscope-web-<hash>_bg.wasm`
- `style-<hash>.css`
- `favicon.svg`
- `logo.svg`

Copy the contents of `dist/` to any static web server root directory.
