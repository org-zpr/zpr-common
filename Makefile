
.PHONY: all build test clean check submodules

all: build

build:
	cargo build --all-targets -F all

test:
	cargo test --verbose

check:
	cargo fmt --check && cargo rustc --lib -- -D warnings

clean:
	cargo clean

submodules:
	git submodule update --init --recursive

.DEFAULT_GOAL := all
