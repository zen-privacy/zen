# Build Rules

All builds must match CI (.github/workflows/build.yml) exactly.

## Build commands
```bash
# macOS
npx tauri build --target aarch64-apple-darwin --bundles dmg

# Windows
npx tauri build --bundles nsis

# Linux
npx tauri build --bundles deb,rpm
```

## Quick compilation check
```bash
cargo build --manifest-path src-tauri/Cargo.toml
```

## Tests
```bash
cargo test --manifest-path src-tauri/Cargo.toml
```
Always run before committing. All tests must pass.

## Output paths
- macOS: `src-tauri/target/aarch64-apple-darwin/release/bundle/dmg/`
- Windows: `src-tauri/target/release/bundle/nsis/`
- Linux: `src-tauri/target/release/bundle/deb/` and `rpm/`
