use std::env;
use std::path::PathBuf;

fn main() {
    // Get the path to the keylib include directory
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:warning=CARGO_MANIFEST_DIR: {}", manifest_dir);
    let keylib_include = PathBuf::from(manifest_dir.clone())
        .parent()
        .unwrap()
        .join("bindings")
        .join("c")
        .join("include");
    println!(
        "cargo:warning=keylib_include path: {}",
        keylib_include.display()
    );
    println!(
        "cargo:warning=keylib_include exists: {}",
        keylib_include.exists()
    );

    // Build the Zig libraries first
    println!("cargo:warning=Building Zig libraries...");
    let output = std::process::Command::new("zig")
        .args(["build", "install"])
        .current_dir(manifest_dir.clone())
        .output()
        .expect("Failed to build Zig libraries");

    println!(
        "cargo:warning=Zig stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    println!(
        "cargo:warning=Zig stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    if !output.status.success() {
        panic!(
            "Zig build failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    println!("cargo:warning=Zig libraries built successfully");

    println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rerun-if-changed=../bindings/c/include/keylib.h");
    println!("cargo:rerun-if-changed=../bindings/linux/include/uhid.h");

    let keylib_include = PathBuf::from("../bindings/c/include");
    let uhid_include = PathBuf::from("../bindings/linux/include");

    let bindings = bindgen::Builder::default()
        .header(keylib_include.join("keylib.h").to_str().unwrap())
        .header(uhid_include.join("uhid.h").to_str().unwrap())
        .clang_arg(format!("-I{}", keylib_include.display()))
        .clang_arg(format!("-I{}", uhid_include.display()))
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");

    // Link the keylib static library
    println!("cargo:rustc-link-lib=static=keylib");
    println!("cargo:rustc-link-lib=static=uhid");
    println!("cargo:rustc-link-lib=udev");
    println!("cargo:rustc-link-lib=hidapi-hidraw");

    // Tell cargo where to find the library
    let lib_dir = PathBuf::from(manifest_dir)
        .parent()
        .unwrap()
        .join("zig-out")
        .join("lib");

    println!("cargo:rustc-link-search=native={}", lib_dir.display());
}
