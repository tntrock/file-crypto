// Release 版隱藏主控台視窗（除錯版保留，方便看 panic 訊息）
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod crypto;

use eframe::egui;

fn main() -> eframe::Result<()> {
    // 載入視窗圖示（標題列／工作列）。解碼失敗時退回預設，不影響啟動。
    let icon = eframe::icon_data::from_png_bytes(
        include_bytes!("../assets/icon.png").as_slice(),
    )
    .unwrap_or_default();

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([560.0, 460.0])
            .with_min_inner_size([460.0, 400.0])
            .with_icon(std::sync::Arc::new(icon)),
        ..Default::default()
    };
    eframe::run_native(
        "檔案加解密工具",
        native_options,
        Box::new(|cc| Box::new(app::EncryptorApp::new(cc))),
    )
}
