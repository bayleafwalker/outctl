set shell := ["bash", "-euo", "pipefail", "-c"]

default: verify

# Keep the developer entry points on the repository's existing uv workflow.
sync:
    uv sync --all-extras --dev

test:
    uv build
    uv run pytest

lint:
    uv run ruff check .

typecheck:
    uv run mypy src

package:
    uv build

package-test: package
    uv run pytest tests/test_packaging.py
    python scripts/check_package.py

verify: test lint typecheck package-test native-check hybrid-package-test

native-check:
    cargo fmt --all -- --check
    cargo check --workspace --all-targets
    cargo clippy --workspace --all-targets -- -D warnings
    cargo test --workspace
    uv run pytest tests/test_native_capabilities.py tests/test_w3_native.py

hybrid-package-test: package
    cargo build --locked --release --package outctl-cli --bin outctl-native
    uv run pytest tests/test_w8_bundle.py tests/test_w8_rollout.py
