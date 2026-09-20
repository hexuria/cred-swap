#!/usr/bin/env bash
#
# Everything CI runs, in the order CI runs it.
#
# This exists because the interesting failures were all ones a normal
# `cargo test` could not see: a lint only the newest stable knows about, a
# browser build that compiles the core with a feature turned off, a scan that
# walks tracked files and so cannot see a file you have not staged yet. Run
# this before pushing and CI holds no surprises.
set -euo pipefail

cd "$(dirname "$0")/.."

step() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }

step "Format"
cargo fmt --all --check

step "Clippy"
cargo clippy --workspace --all-targets --all-features -- -D warnings

step "Clippy, browser build"
# The core compiles differently here: no default features, so no OS entropy
# and no getrandom. Code that only ever built with them on breaks here first.
rustup target add wasm32-unknown-unknown >/dev/null 2>&1 || true
cargo clippy -p cred-swap-wasm --target wasm32-unknown-unknown --all-targets -- -D warnings

step "Documentation"
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --document-private-items

step "Tests"
cargo test --workspace --all-features

step "Browser tests"
if command -v wasm-pack >/dev/null 2>&1; then
  wasm-pack test --node crates/cred-swap-wasm
else
  echo "wasm-pack not installed, skipping (CI will run these)"
fi

step "Scan our own source"
cargo build --release -q -p cred-swap-cli
# Tracked files only, matching CI. A file you have not staged is invisible to
# both, which is exactly how the demo page slipped through once.
found=0
while IFS= read -r file; do
  if ! ./target/release/cred-swap detect --strict --config .cred-swap.toml "$file" >/tmp/cred-swap-scan.txt 2>&1; then
    echo "  in ${file}:"
    sed "s/^/    /" /tmp/cred-swap-scan.txt
    found=1
  fi
done < <(git ls-files '*.rs' '*.toml' '*.yml' '*.md' '*.html')
if [ "$found" -ne 0 ]; then
  echo
  echo "cred-swap found something. If it is a test fixture, add it to"
  echo ".cred-swap.toml with a reason."
  exit 1
fi

printf '\n\033[32mAll clear.\033[0m\n'
