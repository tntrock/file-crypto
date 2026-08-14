//! egui GUI 應用層

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use eframe::egui;
use zeroize::Zeroize;

use crate::crypto::{self, Progress, KEY_SOURCE_KEYFILE, KEY_SOURCE_PASSWORD};

#[derive(PartialEq, Clone, Copy)]
enum Mode {
    Encrypt,
    Decrypt,
}

#[derive(PartialEq, Clone, Copy)]
enum KeyMode {
    Password,
    Keyfile,
}

/// 由背景執行緒回報的最終結果。
type JobResult = Arc<Mutex<Option<Result<String, String>>>>;

pub struct EncryptorApp {
    mode: Mode,
    key_mode: KeyMode,

    input_path: Option<PathBuf>,
    output_path: Option<PathBuf>,
    keyfile_path: Option<PathBuf>,

    password: String,
    password_confirm: String,
    show_password: bool,

    status: String,
    is_error: bool,

    // 背景工作共享狀態
    progress: Arc<Progress>,
    running: Arc<AtomicBool>,
    result: JobResult,
}

impl EncryptorApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        install_cjk_font(&cc.egui_ctx);
        Self {
            mode: Mode::Encrypt,
            key_mode: KeyMode::Password,
            input_path: None,
            output_path: None,
            keyfile_path: None,
            password: String::new(),
            password_confirm: String::new(),
            show_password: false,
            status: "請選擇檔案並輸入密碼或金鑰檔。".to_owned(),
            is_error: false,
            progress: Arc::new(Progress::default()),
            running: Arc::new(AtomicBool::new(false)),
            result: Arc::new(Mutex::new(None)),
        }
    }

    /// 依模式與輸入檔，推算預設輸出路徑。
    fn suggest_output(&mut self) {
        let Some(input) = self.input_path.clone() else {
            return;
        };
        match self.mode {
            Mode::Encrypt => {
                let mut s = input.into_os_string();
                s.push(".enc");
                self.output_path = Some(PathBuf::from(s));
            }
            Mode::Decrypt => {
                // 優先使用加密檔內記錄的原始檔名
                if let Ok(info) = crypto::peek_header(&input) {
                    let dir = input.parent().map(PathBuf::from).unwrap_or_default();
                    let mut candidate = dir.join(&info.original_name);
                    if candidate == input {
                        // 避免覆蓋來源，加上 .dec
                        let mut s = candidate.into_os_string();
                        s.push(".dec");
                        candidate = PathBuf::from(s);
                    }
                    self.output_path = Some(candidate);
                    if info.key_source == KEY_SOURCE_KEYFILE {
                        self.key_mode = KeyMode::Keyfile;
                    }
                } else if input.extension().and_then(|e| e.to_str()) == Some("enc") {
                    self.output_path = Some(input.with_extension(""));
                } else {
                    let mut s = input.into_os_string();
                    s.push(".dec");
                    self.output_path = Some(PathBuf::from(s));
                }
            }
        }
    }

    fn validate(&self) -> Result<Vec<u8>, String> {
        let Some(_) = &self.input_path else {
            return Err("尚未選擇輸入檔。".into());
        };
        let Some(_) = &self.output_path else {
            return Err("尚未指定輸出檔。".into());
        };
        match self.key_mode {
            KeyMode::Password => {
                if self.password.is_empty() {
                    return Err("密碼不可為空。".into());
                }
                if self.mode == Mode::Encrypt && self.password != self.password_confirm {
                    return Err("兩次輸入的密碼不一致。".into());
                }
                Ok(self.password.as_bytes().to_vec())
            }
            KeyMode::Keyfile => {
                let Some(kf) = &self.keyfile_path else {
                    return Err("尚未選擇金鑰檔。".into());
                };
                std::fs::read(kf).map_err(|e| format!("讀取金鑰檔失敗: {e}"))
            }
        }
    }

    fn start_job(&mut self, ctx: &egui::Context) {
        let mut material = match self.validate() {
            Ok(m) => m,
            Err(e) => {
                self.status = e;
                self.is_error = true;
                return;
            }
        };

        let input = self.input_path.clone().unwrap();
        let output = self.output_path.clone().unwrap();
        let mode = self.mode;
        let key_source = match self.key_mode {
            KeyMode::Password => KEY_SOURCE_PASSWORD,
            KeyMode::Keyfile => KEY_SOURCE_KEYFILE,
        };

        *self.result.lock().unwrap() = None;
        self.running.store(true, Ordering::Relaxed);
        self.is_error = false;
        self.status = "處理中…".to_owned();

        let progress = self.progress.clone();
        let running = self.running.clone();
        let result = self.result.clone();
        let ctx = ctx.clone();

        thread::spawn(move || {
            let outcome = match mode {
                Mode::Encrypt => {
                    crypto::encrypt_file(&input, &output, &material, key_source, &progress)
                }
                Mode::Decrypt => crypto::decrypt_file(&input, &output, &material, &progress),
            };
            material.zeroize();

            let msg = match outcome {
                Ok(()) => Ok(format!("完成！已輸出至：\n{}", output.display())),
                Err(e) => {
                    // 失敗時刪除半成品輸出檔，避免留下損毀檔案
                    let _ = std::fs::remove_file(&output);
                    Err(format!("失敗：{e}"))
                }
            };
            *result.lock().unwrap() = Some(msg);
            running.store(false, Ordering::Relaxed);
            ctx.request_repaint();
        });
    }
}

impl eframe::App for EncryptorApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // 收取背景結果
        if let Some(res) = self.result.lock().unwrap().take() {
            match res {
                Ok(m) => {
                    self.status = m;
                    self.is_error = false;
                }
                Err(m) => {
                    self.status = m;
                    self.is_error = true;
                }
            }
        }
        let running = self.running.load(Ordering::Relaxed);

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("🔐 檔案加解密工具");
            ui.label("AES-256-GCM ｜ 單一檔案 ｜ 免安裝可攜版");
            ui.separator();

            ui.add_enabled_ui(!running, |ui| {
                // 模式
                ui.horizontal(|ui| {
                    ui.label("模式：");
                    if ui
                        .selectable_label(self.mode == Mode::Encrypt, "🔒 加密")
                        .clicked()
                    {
                        self.mode = Mode::Encrypt;
                        self.suggest_output();
                    }
                    if ui
                        .selectable_label(self.mode == Mode::Decrypt, "🔓 解密")
                        .clicked()
                    {
                        self.mode = Mode::Decrypt;
                        self.suggest_output();
                    }
                });

                ui.add_space(4.0);

                // 輸入檔
                ui.horizontal(|ui| {
                    if ui.button("選擇輸入檔…").clicked() {
                        if let Some(p) = rfd::FileDialog::new().pick_file() {
                            self.input_path = Some(p);
                            self.suggest_output();
                        }
                    }
                    let txt = self
                        .input_path
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "（未選擇）".into());
                    ui.label(txt);
                });

                // 輸出檔
                ui.horizontal(|ui| {
                    if ui.button("輸出位置…").clicked() {
                        let mut dlg = rfd::FileDialog::new();
                        if let Some(p) = &self.output_path {
                            if let Some(name) = p.file_name().and_then(|s| s.to_str()) {
                                dlg = dlg.set_file_name(name);
                            }
                            if let Some(dir) = p.parent() {
                                dlg = dlg.set_directory(dir);
                            }
                        }
                        if let Some(p) = dlg.save_file() {
                            self.output_path = Some(p);
                        }
                    }
                    let txt = self
                        .output_path
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "（未指定）".into());
                    ui.label(txt);
                });

                ui.separator();

                // 金鑰來源
                ui.horizontal(|ui| {
                    ui.label("金鑰來源：");
                    ui.selectable_value(&mut self.key_mode, KeyMode::Password, "🔑 密碼");
                    ui.selectable_value(&mut self.key_mode, KeyMode::Keyfile, "📄 金鑰檔");
                });

                match self.key_mode {
                    KeyMode::Password => {
                        ui.horizontal(|ui| {
                            ui.label("密碼：");
                            ui.add(
                                egui::TextEdit::singleline(&mut self.password)
                                    .password(!self.show_password)
                                    .desired_width(260.0),
                            );
                        });
                        if self.mode == Mode::Encrypt {
                            ui.horizontal(|ui| {
                                ui.label("確認：");
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.password_confirm)
                                        .password(!self.show_password)
                                        .desired_width(260.0),
                                );
                            });
                        }
                        ui.checkbox(&mut self.show_password, "顯示密碼");
                    }
                    KeyMode::Keyfile => {
                        ui.horizontal(|ui| {
                            if ui.button("選擇金鑰檔…").clicked() {
                                if let Some(p) = rfd::FileDialog::new().pick_file() {
                                    self.keyfile_path = Some(p);
                                }
                            }
                            let txt = self
                                .keyfile_path
                                .as_ref()
                                .map(|p| p.display().to_string())
                                .unwrap_or_else(|| "（未選擇）".into());
                            ui.label(txt);
                        });
                        ui.label(
                            egui::RichText::new(
                                "提示：任何檔案都可當金鑰檔，但務必妥善備份；遺失將無法解密。",
                            )
                            .small()
                            .italics(),
                        );
                    }
                }

                ui.separator();

                let btn_text = match self.mode {
                    Mode::Encrypt => "🔒 開始加密",
                    Mode::Decrypt => "🔓 開始解密",
                };
                if ui
                    .add_sized([160.0, 32.0], egui::Button::new(btn_text))
                    .clicked()
                {
                    self.start_job(ctx);
                }
            });

            // 進度與取消
            if running {
                ui.add_space(8.0);
                let frac = self.progress.fraction();
                ui.add(egui::ProgressBar::new(frac).show_percentage().animate(true));
                if ui.button("取消").clicked() {
                    self.progress.cancel.store(true, Ordering::Relaxed);
                }
                ctx.request_repaint();
            }

            ui.add_space(8.0);
            let color = if self.is_error {
                egui::Color32::from_rgb(200, 60, 60)
            } else {
                egui::Color32::from_rgb(40, 140, 70)
            };
            ui.colored_label(color, &self.status);
        });
    }
}

/// 從 Windows 系統字型載入 CJK 字型，讓中文能正常顯示。
/// 在非 Windows 平台上找不到檔案時會靜默略過。
fn install_cjk_font(ctx: &egui::Context) {
    let candidates = [
        r"C:\Windows\Fonts\msjh.ttc",    // 微軟正黑體（繁中，首選）
        r"C:\Windows\Fonts\msjhl.ttc",   // 微軟正黑體 Light
        r"C:\Windows\Fonts\mingliu.ttc", // 細明體
        r"C:\Windows\Fonts\kaiu.ttf",    // 標楷體
        r"C:\Windows\Fonts\msyh.ttc",    // 微軟雅黑（簡中）
        r"C:\Windows\Fonts\simsun.ttc",  // 新宋體
    ];
    for path in candidates {
        if let Ok(bytes) = std::fs::read(path) {
            let mut fonts = egui::FontDefinitions::default();
            fonts
                .font_data
                .insert("cjk".to_owned(), egui::FontData::from_owned(bytes));
            fonts
                .families
                .entry(egui::FontFamily::Proportional)
                .or_default()
                .insert(0, "cjk".to_owned());
            fonts
                .families
                .entry(egui::FontFamily::Monospace)
                .or_default()
                .push("cjk".to_owned());
            ctx.set_fonts(fonts);
            return;
        }
    }
}
