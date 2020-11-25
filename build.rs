//
// Copyright (C) 2020 Curt Brune <curt@brune.net>
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

extern crate bindgen;

use std::env;
use std::path::PathBuf;

fn main() {
    let wrapper_h: PathBuf = [
        &env::var("CARGO_MANIFEST_DIR").unwrap(),
        "c_src",
        "wrapper.h",
    ]
    .iter()
    .collect();

    // Tell cargo to invalidate the built crate whenever the wrapper changes
    println!("cargo:rerun-if-changed={}", wrapper_h.to_str().unwrap());

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header(wrapper_h.to_str().unwrap())
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindgen_wrapper.rs"))
        .expect("Couldn't write bindings!");
}
