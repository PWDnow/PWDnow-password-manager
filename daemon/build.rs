use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    // ── libsodium ─────────────────────────────────────────────────────────────
    // libsodium-sys already has use-pkg-config in Cargo.toml, but we still
    // need the link-search when pkg-config is unavailable on the host.
    link_lib_via_pkg_config_or_fallback("libsodium", "sodium", &[]);

    // ── SQLCipher ─────────────────────────────────────────────────────────────
    link_lib_via_pkg_config_or_fallback("sqlcipher", "sqlcipher", &[]);
    // Tell rusqlite where to find the sqlcipher headers.
    if let Ok(include) = pkg_config_cflags_include("sqlcipher") {
        println!("cargo:rustc-env=SQLITE_INCLUDE_DIR={include}");
    } else {
        // Fallback: common system paths on Debian/Ubuntu/macOS-brew.
        for p in &[
            "/usr/include/sqlcipher",
            "/usr/local/include/sqlcipher",
            "/opt/homebrew/include/sqlcipher",
            "/opt/homebrew/opt/sqlcipher/include/sqlcipher",
        ] {
            if std::path::Path::new(p).exists() {
                println!("cargo:rustc-env=SQLITE_INCLUDE_DIR={p}");
                break;
            }
        }
    }

    // ── liboqs (post-quantum) ────────────────────────────────────────────────
    if env::var("CARGO_FEATURE_PQ").is_ok() {
        link_lib_via_pkg_config_or_fallback("liboqs", "oqs", &["/usr/local/lib"]);
    }

    // ── LIBCLANG_PATH (for bindgen) ──────────────────────────────────────────
    // Prefer LIBCLANG_PATH already set in the environment (CI / cross builds).
    if env::var("LIBCLANG_PATH").is_err() {
        if let Some(p) = find_libclang_path() {
            println!("cargo:rustc-env=LIBCLANG_PATH={p}");
        }
    }

    // ── libfido2 ─────────────────────────────────────────────────────────────
    // Always link libfido2. The mock-fido2 feature adds mock DeviceBackend
    // implementations for testing but does not replace the native symbols.
    link_lib_via_pkg_config_or_fallback("libfido2", "fido2", &[]);

    // Locate fido.h via pkg-config --cflags, then fall back to common paths.
    let fido_header = find_fido_header();

    let mut builder = bindgen::Builder::default()
        .header(&fido_header)
        .allowlist_function("fido_init")
        .allowlist_function("fido_strerr")
        .allowlist_function("fido_dev_new")
        .allowlist_function("fido_dev_free")
        .allowlist_function("fido_dev_open")
        .allowlist_function("fido_dev_close")
        .allowlist_function("fido_dev_make_cred")
        .allowlist_function("fido_dev_get_assert")
        .allowlist_function("fido_dev_info_new")
        .allowlist_function("fido_dev_info_free")
        .allowlist_function("fido_dev_info_manifest")
        .allowlist_function("fido_dev_info_ptr")
        .allowlist_function("fido_dev_info_path")
        .allowlist_function("fido_cred_new")
        .allowlist_function("fido_cred_free")
        .allowlist_function("fido_cred_set_type")
        .allowlist_function("fido_cred_set_rp")
        .allowlist_function("fido_cred_set_user")
        .allowlist_function("fido_cred_set_rk")
        .allowlist_function("fido_cred_set_clientdata_hash")
        .allowlist_function("fido_cred_id_ptr")
        .allowlist_function("fido_cred_id_len")
        .allowlist_function("fido_cred_authdata_ptr")
        .allowlist_function("fido_cred_authdata_len")
        .allowlist_function("fido_cred_pubkey_ptr")
        .allowlist_function("fido_cred_pubkey_len")
        .allowlist_function("fido_assert_new")
        .allowlist_function("fido_assert_free")
        .allowlist_function("fido_assert_set_rp")
        .allowlist_function("fido_assert_set_clientdata_hash")
        .allowlist_function("fido_assert_set_up")
        .allowlist_function("fido_assert_set_uv")
        .allowlist_function("fido_assert_allow_cred")
        .allowlist_function("fido_assert_set_count")
        .allowlist_function("fido_assert_count")
        .allowlist_function("fido_assert_authdata_ptr")
        .allowlist_function("fido_assert_authdata_len")
        .allowlist_function("fido_assert_id_ptr")
        .allowlist_function("fido_assert_id_len")
        .allowlist_function("fido_assert_sig_ptr")
        .allowlist_function("fido_assert_sig_len")
        .allowlist_function("fido_assert_verify")
        .allowlist_function("fido_assert_set_authdata_raw")
        .allowlist_function("fido_assert_set_sig")
        .allowlist_type("fido_opt_t")
        .allowlist_var("FIDO_OK")
        .allowlist_var("FIDO_ERR_.*")
        .allowlist_var("COSE_ES256")
        .allowlist_var("FIDO_OPT_.*")
        .opaque_type("fido_assert_t")
        .opaque_type("fido_cred_t")
        .opaque_type("fido_dev_t")
        .opaque_type("fido_dev_info_t")
        .layout_tests(false);

    // Add any include dirs that pkg-config reported for libfido2.
    if let Ok(flags) = pkg_config_raw_cflags("libfido2") {
        for flag in flags.split_whitespace() {
            if let Some(dir) = flag.strip_prefix("-I") {
                builder = builder.clang_arg(format!("-I{dir}"));
            }
        }
    }

    let bindings = builder.generate().expect(
        "bindgen failed — install libfido2-dev and ensure LIBCLANG_PATH points to a clang lib dir"
    );

    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out.join("fido2_bindings.rs"))
        .expect("failed to write fido2_bindings.rs");

    // ── gRPC Protobuf ────────────────────────────────────────────────────────
    tonic_prost_build::compile_protos("../proto/vault.proto")
        .expect("Failed to compile gRPC protobufs");

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../proto/vault.proto");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_PQ");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_MOCK_FIDO2");
    println!("cargo:rerun-if-env-changed=LIBCLANG_PATH");
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Emit link directives for `lib_name` using pkg-config when available,
/// falling back to the provided extra search paths.
fn link_lib_via_pkg_config_or_fallback(pkg: &str, lib: &str, extra_search: &[&str]) {
    match pkg_config::probe_library(pkg) {
        Ok(_) => { /* pkg-config emits the link directives automatically */ }
        Err(_) => {
            // pkg-config unavailable or library not registered — emit manually.
            for path in extra_search {
                println!("cargo:rustc-link-search=native={path}");
            }
            println!("cargo:rustc-link-lib=dylib={lib}");
        }
    }
}

/// Return the raw `-I...` flags from `pkg-config --cflags <pkg>`.
fn pkg_config_raw_cflags(pkg: &str) -> Result<String, ()> {
    let out = Command::new("pkg-config").args(["--cflags", pkg]).output().map_err(|_| ())?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        Err(())
    }
}

/// Extract the first `-I<dir>` path from `pkg-config --cflags <pkg>`.
fn pkg_config_cflags_include(pkg: &str) -> Result<String, ()> {
    let flags = pkg_config_raw_cflags(pkg)?;
    for flag in flags.split_whitespace() {
        if let Some(dir) = flag.strip_prefix("-I") {
            return Ok(dir.to_string());
        }
    }
    Err(())
}

/// Locate the clang lib directory by querying `llvm-config` or scanning
/// common distro paths.  Returns `None` if nothing is found (caller keeps
/// any LIBCLANG_PATH already set in the environment).
fn find_libclang_path() -> Option<String> {
    // 1. Try llvm-config (present on most Linux distros + macOS via brew).
    if let Ok(out) = Command::new("llvm-config").arg("--libdir").output() {
        if out.status.success() {
            let p = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !p.is_empty() { return Some(p); }
        }
    }
    // 2. Try clang --print-search-dirs (macOS Xcode / brew clang).
    if let Ok(out) = Command::new("clang").arg("--print-search-dirs").output() {
        if out.status.success() {
            for line in String::from_utf8_lossy(&out.stdout).lines() {
                if let Some(rest) = line.strip_prefix("libraries: =") {
                    // First entry in the colon-separated list.
                    if let Some(first) = rest.split(':').next() {
                        return Some(first.to_string());
                    }
                }
            }
        }
    }
    // 3. Scan common distro paths (llvm-14 through llvm-21).
    let candidates = [
        "/usr/lib/llvm-21/lib", "/usr/lib/llvm-20/lib", "/usr/lib/llvm-19/lib",
        "/usr/lib/llvm-18/lib", "/usr/lib/llvm-17/lib", "/usr/lib/llvm-16/lib",
        "/usr/lib/llvm-15/lib", "/usr/lib/llvm-14/lib",
        // macOS Homebrew
        "/opt/homebrew/opt/llvm/lib", "/usr/local/opt/llvm/lib",
    ];
    for p in &candidates {
        if std::path::Path::new(p).exists() {
            return Some(p.to_string());
        }
    }
    None
}

/// Locate fido.h via pkg-config, then common filesystem paths.
fn find_fido_header() -> String {
    if let Ok(flags) = pkg_config_raw_cflags("libfido2") {
        for flag in flags.split_whitespace() {
            if let Some(dir) = flag.strip_prefix("-I") {
                let h = format!("{dir}/fido.h");
                if std::path::Path::new(&h).exists() { return h; }
            }
        }
    }
    let candidates = [
        "/usr/include/fido.h",
        "/usr/local/include/fido.h",
        "/opt/homebrew/include/fido.h",
        "/opt/homebrew/opt/libfido2/include/fido.h",
    ];
    for p in &candidates {
        if std::path::Path::new(p).exists() { return p.to_string(); }
    }
    panic!(
        "Cannot locate fido.h. Install libfido2-dev (apt/dnf) or libfido2 (brew) \
         and ensure pkg-config can find it."
    );
}
