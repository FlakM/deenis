extern crate bindgen;

use std::env;
use std::path::PathBuf;

fn main() {
    // The `bindgen::Builder` is the main entry point to `bindgen`.
    let bindings = bindgen::Builder::default()
        // Input header we would like to generate bindings for.
        .header_contents("wrapper.h", "#include <netdb.h>")
        .allowlist_type("addrinfo")
        // Since addrinfo might depend on other types defined in netdb.h, you can
        // tell bindgen to also generate bindings for these types as needed
        .allowlist_type("sockaddr")
        .allowlist_type("sockaddr_storage")
        .allowlist_type("sockaddr_in")
        .allowlist_type("sockaddr_in6")
        .allowlist_type("in_addr")
        .allowlist_type("in6_addr")
        // allow ai_family to be used in the generated bindings
        .allowlist_var("ai_family")
        .layout_tests(false)
        .use_core()
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
