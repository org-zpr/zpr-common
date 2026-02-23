# zpr-common

Shared ZPR definitions and utilities. This crate packages core protocol types,
common constants, and IDL schemas used across ZPR services and libraries.


> **Pre-Release / Beta Notice**
>
> This repository is in active, early-stage development. The code contained here is **not stable** and should be treated as beta-quality work.
>
> - **Breaking changes may occur at any time** without prior notice or deprecation periods.
> - Do **not** rely on these definitions for production systems until a stable release is announced.
>
> Feedback and contributions are welcome, but please be aware that any work built on top of this code may need to be updated as it evolves.



## What is here
- Rust crate `zpr` with shared types (addresses, DNs, packet metadata, and
  helpers for writing/serializing structures).
- Feature-gated policy and VSAPI type wrappers used by multiple services.
- IDL sources for ZPR sub-protocols. These are included as **submodules**.
  - `zpr-policy/` Policy schema (Cap'n Proto). 
  - `zpr-vsapi/` Visa Service API IDL (Cap'n Proto).  

## Crate features
- `policy` - builds Cap'n Proto bindings and helpers for policy types.
- `vsapi` - builds Cap'n Proto bindings plus VSAPI type helpers.
- `all` - enables all of the above.

## Build and test
```sh
make build
make test
```

Directly with Cargo:
```sh
cargo build --all-targets -F all
cargo test
```

## Code layout
- `src/lib.rs` - crate entry and feature-gated exports.
- `src/addrs.rs`, `src/dn.rs` - well-known addresses and DNs.
- `src/packet_info.rs` - protocol-level types/constants.
- `src/write_to.rs` - helpers for writing/serializing structures.
- `src/policy_types/` - policy helpers (feature `policy`).
- `src/vsapi_types/` - VSAPI helpers (feature `vsapi`).
- `build.rs` - compiles Cap'n Proto schemas from the IDL folders.

## License
Apache-2.0 
