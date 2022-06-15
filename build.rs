use std::env;

fn main() {
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    println!("cargo:rustc-env=BUILD_ARCH={}", arch);
}