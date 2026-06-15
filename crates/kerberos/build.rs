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

    // Determine target for cross-compilation awareness (e.g. arm64 builder -> x86_64 target in Dockerfile).
    // This helps clang pick the correct target-specific stdarg.h / va_list layout.
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
        // Pass -target (single dash) to clang so va_list / __va_list_tag layout matches
        // the *target* ABI (important for cross-compilation and consistent bindings on any host).
        // Using the correct single-dash form that clang/bindgen expects.
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
        .generate_comments(false);

    let bindings = builder.generate().expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    let bindings_file = out_path.join("bindings.rs");

    bindings
        .write_to_file(&bindings_file)
        .expect("Couldn't write bindings!");

    // === Post-processing ===
    let mut content = fs::read_to_string(&bindings_file).expect("Failed to read bindings");

    // 1. Make extern blocks unsafe (required for modern Rust editions / recent bindgen)
    content = content.replace("extern \"C\" {", "unsafe extern \"C\" {");

    // 2. Robust cross-platform + cross-clang fix for va_list / __va_list_tag.
    // Bindgen + different clang versions / architectures emit varying forms, e.g.:
    //   pub type va_list = [u64; 4];
    //   pub type va_list = [u64; 3usize];
    //   pub type va_list = __va_list_tag;
    // etc. These cause either improper_ctypes warnings or duplicate definition errors
    // when we append our opaque struct.
    //
    // Strategy:
    //   a) Broadly neutralize (comment out) ANY existing pub type va_list / __va_list_tag definitions.
    //   b) Append ONE canonical FFI-safe opaque struct definition.
    //
    // This is 100% safe because we never call the vararg va_list functions in our FFI layer.
    // Opaque ZST works everywhere and eliminates all warnings + duplicate-definition panics.
    if content.contains("va_list") {
        // Neutralize every possible original typedef (works for any RHS: [u64; N], __va_list_tag, etc.)
        content = content.replace(
            "pub type va_list = ",
            "// neutralized original definition: pub type va_list = ",
        );
        content = content.replace(
            "pub type __va_list_tag = ",
            "// neutralized original definition: pub type __va_list_tag = ",
        );

        // Also catch any stragglers from previous attempts
        content = content.replace("pub type va_list = [u64; 4];", "// neutralized");
        content = content.replace("pub type va_list = [u64; 3usize];", "// neutralized");

        // Append our single authoritative FFI-safe definition (only if not already present)
        if !content.contains("pub struct va_list {") {
            content.push_str(
                "\n\n// === FFI-safe opaque va_list (production-grade, cross-platform fix) ===\n",
            );
            content.push_str("// We neutralize whatever bindgen/clang emitted above and provide one clean opaque type.\n");
            content.push_str("// Prevents improper_ctypes warnings and E0428 duplicate definition errors on any host.\n");
            content.push_str("#[repr(C)]\n");
            content.push_str("pub struct va_list {\n");
            content.push_str("    _unused: [u8; 0],\n");
            content.push_str("}\n\n");
            content.push_str("pub type __va_list_tag = va_list;\n");
            content.push_str("pub type __builtin_va_list = va_list;\n");
        }
    }

    fs::write(&bindings_file, content).expect("Failed to write fixed bindings!");

    println!("cargo:rerun-if-changed=build.rs");
}
