fn main() {
    capnpc::CompilerCommand::new()
        .src_prefix("zpr-policy")
        .file("zpr-policy/policy.capnp")
        .run()
        .expect("failed to compile zpr-policy capnp schema");

    capnpc::CompilerCommand::new()
        .src_prefix("zpr-vsapi")
        .file("zpr-vsapi/vs.capnp")
        .run()
        .expect("failed to compile zpr-vsapi capnp schema");
}
