use std::path::Path;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=app_resources.rc");
    println!("cargo:rerun-if-changed=app_icon.ico");

    if std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() == "windows" {
        let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
        let res_o = Path::new(&out_dir).join("app_resources.res.o");

        let status = Command::new("windres")
            .current_dir("crates/shadow-gui")
            .arg("app_resources.rc")
            .arg("-O")
            .arg("coff")
            .arg("-o")
            .arg(&res_o)
            .status();

        // 尝试从当前目录或者 crate 目录编译资源
        let status = if status.as_ref().map(|s| s.success()).unwrap_or(false) {
            status
        } else {
            Command::new("windres")
                .arg("app_resources.rc")
                .arg("-O")
                .arg("coff")
                .arg("-o")
                .arg(&res_o)
                .status()
        };

        if let Ok(s) = status {
            if s.success() {
                println!("cargo:rustc-link-arg={}", res_o.display());
            }
        }
    }
}
