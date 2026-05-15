# Reproducible Builds

PWDnow uses reproducible builds to ensure that the published artifacts exactly match the source code.

## Node.js and NPM version pin
To maintain a strict and reproducible frontend build, we pin the Node.js version.
- **Node.js**: v20.14.0 (as specified in `.nvmrc` and `.node-version`)
- **NPM**: Uses `npm ci --strict-peer-deps` alongside `package-lock.json` to enforce strict dependency trees and versions.

## Rust Daemon
- We use a fixed `SOURCE_DATE_EPOCH` in our GitHub Actions release workflow.
- `Cargo.toml` and `.cargo/config.toml` enforce:
  - `codegen-units = 1`
  - `strip = "symbols"`
  - `panic = "abort"`
  - `rustflags = ["-C", "metadata="]`
