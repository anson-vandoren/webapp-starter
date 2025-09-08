#!/usr/bin/env sh
cargo sort-derives # Keep derives in alphabetical order
cargo sort # Keep dependencies in Cargo.toml in alphabetical order
cargo fmt --all -- --config-path .rustfmt.stable.toml --config unstable_features=true --config imports_granularity=Crate --config reorder_impl_items=true --config group_imports=StdExternalCrate
cargo clippy
cargo sqlx migrate run && cargo sqlx prepare --check -- --all-features
cargo +nightly udeps
cargo upgrade --dry-run
