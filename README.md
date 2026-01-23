# zpr-common

Shared ZPR definitions and utilities. This crate packages core protocol types,
common constants, and IDL schemas used across ZPR services and libraries.

## What is here
- Rust crate `zpr` with shared types (addresses, DNs, packet metadata, RPC
  commands, and helpers for writing/serializing structures).
- Feature-gated policy and VSAPI type wrappers used by multiple services.
- IDL sources for ZPR sub-protocols. These are included as **submodules** at
  the moment but at some point will live here directly.
  - `zpr-admin-api/` Cap'n Proto schema for the PH CLI/admin API.
  - `zpr-policy/` Policy schema (Proto + Cap'n Proto). All new code should be
    using the Cap'n Proto version.
  - `zpr-vsapi/` Visa Service API IDL (Cap'n Proto + Thrift).  All new code 
    should be using the Cap'n Proto version.

## Crate features
- `admin-api` - builds Cap'n Proto bindings for the admin/CLI API.
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
- `src/packet_info.rs`, `src/rpc_commands.rs` - protocol-level types/constants.
- `src/policy_types/` - policy helpers (feature `policy`).
- `src/vsapi_types/` - VSAPI helpers (feature `vsapi`).
- `build.rs` - compiles Cap'n Proto schemas from the IDL folders.

## License
Apache-2.0 
