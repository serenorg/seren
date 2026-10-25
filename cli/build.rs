fn main() {
    println!("cargo::rerun-if-changed=build.rs");

    // The command tree and async dispatch share the executable's main-thread stack.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows")
        && std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc")
    {
        println!("cargo::rustc-link-arg-bin=seren=/STACK:8388608");
    }
}
