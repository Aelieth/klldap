use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    println!("cargo:rustc-link-lib=krb5");
    println!("cargo:rustc-link-lib=kadm5clnt");
    println!("cargo:rustc-link-lib=kadm5srv");

    let krb5 = pkg_config::Config::new()
        .probe("krb5")
        .expect("Failed to probe krb5 via pkg-config");

    let include_dir = krb5
        .include_paths
        .first()
        .expect("No include paths from pkg-config");

    let admin_header = include_dir.join("kadm5/admin.h");
    let krb5_header = include_dir.join("krb5.h");

    // -target makes clang lay out va_list for the target ABI, not the build host.
    let target = env::var("TARGET")
        .or_else(|_| env::var("HOST"))
        .unwrap_or_else(|_| "x86_64-unknown-linux-gnu".to_string());

    let mut builder = bindgen::Builder::default()
        .header(admin_header.to_str().unwrap())
        .header(krb5_header.to_str().unwrap())
        .clang_args(
            krb5.include_paths
                .iter()
                .map(|p| format!("-I{}", p.display())),
        )
        .clang_arg("-target")
        .clang_arg(&target);

    builder = builder
        .allowlist_function("kadm5_.*")
        .allowlist_type("kadm5_.*")
        .allowlist_var("KADM5_.*")
        .allowlist_function("krb5_.*")
        .allowlist_type("krb5_.*")
        .allowlist_type("kadm5_config_params")
        .allowlist_var("KADM5_CONFIG_.*");

    builder = builder
        .opaque_type("va_list")
        .blocklist_type("__va_list_tag")
        .blocklist_type("_Float64x")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .layout_tests(false)
        .generate_comments(false);

    let bindings = builder.generate().expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    let bindings_file = out_path.join("bindings.rs");

    bindings
        .write_to_file(&bindings_file)
        .expect("Couldn't write bindings!");

    let mut content = fs::read_to_string(&bindings_file).expect("Failed to read bindings");
    content = content.replace("extern \"C\" {", "unsafe extern \"C\" {");
    // bindgen's va_list layout varies by clang/arch and trips improper_ctypes; no vararg
    // is called, so every emitted definition is replaced with one opaque type.
    if content.contains("va_list") {
        content = content.replace("pub type va_list = ", "// neutralized: pub type va_list = ");
        content = content.replace(
            "pub type __va_list_tag = ",
            "// neutralized: pub type __va_list_tag = ",
        );
        if !content.contains("pub struct va_list {") {
            content.push_str("\n#[repr(C)]\npub struct va_list {\n    _unused: [u8; 0],\n}\n\n");
            content.push_str("pub type __va_list_tag = va_list;\n");
            content.push_str("pub type __builtin_va_list = va_list;\n");
        }
    }

    fs::write(&bindings_file, content).expect("Failed to write fixed bindings!");

    println!("cargo:rerun-if-changed=build.rs");
}
