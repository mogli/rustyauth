# Usage
Example command to start server: `cargo run --release -- -i -c --db_address "postgres@localhost:5432" -p 8000`

# Development
## Linters and scanners

- `cargo fmt --all` (install via `rustup component add rustfmt`)
- `cargo audit` (install via `cargo install cargo-audit`)
