
.PHONY: all build test clean check submodules-pull submodules-update

all: build

build:
	cargo build --all-targets -F all

test:
	cargo test --verbose

check:
	cargo fmt --check && cargo rustc --lib -- -D warnings

clean:
	cargo clean

# This command updates your local submodules if the submodule has been pointed
# to a new commit in the remote branch
submodules-pull:
	git submodule update --init --recursive

# This command will point the submodule to a new commit when the repo it points
# to has been updated
submodules-update:
	git submodule update --remote --merge

.DEFAULT_GOAL := all
