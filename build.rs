//! 建置腳本：在 Windows 目標上，把 assets/icon.ico 嵌入 exe，
//! 並帶入 Cargo.toml 的版本／描述等資訊到檔案屬性。
//!
//! 注意：build.rs 是在「主機」上執行，所以要用 CARGO_CFG_TARGET_OS
//! 判斷「目標平台」是不是 windows，而不是用 cfg!(target_os)。

fn main() {
    // 只在目標為 Windows 時嵌入資源
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("assets/icon.ico");
        // 若編譯失敗（例如缺 icon 檔或缺工具鏈），印出提示但不要中斷整包建置
        if let Err(e) = res.compile() {
            println!("cargo:warning=嵌入 Windows 圖示失敗: {e}");
        }
    }

    // 當 icon 檔變更時，重新執行 build script
    println!("cargo:rerun-if-changed=assets/icon.ico");
    println!("cargo:rerun-if-changed=build.rs");
}
