use std::{env, path::PathBuf};

fn main() {
    // Tell cargo to look for shared libraries in the specified directory
    if let Ok(rustc_link_search) = env::var("LIBCAP_LIB_PATH") {
        println!("cargo:rustc-link-search={rustc_link_search}");
    }

    // Tell cargo to tell rustc to link the system bzip2
    // shared library.
    println!("cargo:rustc-link-lib=cap");

    // Tell cargo to invalidate the built crate whenever the wrapper changes
    println!("cargo:rerun-if-changed=src/wrapper.h");

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header("src/wrapper.h")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        // Set whitelist of function/types/etc
        .allowlist_function("^cap_(?:free|[sg]et_(?:proc|flag)|to_text|compare)$")
        .allowlist_type("^cap_(?:flag_)?t$")
        .allowlist_var("^CAP_\\w+$")
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
