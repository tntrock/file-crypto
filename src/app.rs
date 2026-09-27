//! egui GUI 應用層

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use eframe::egui;
use zeroize::Zeroize;

use crate::crypto::{self, Output, Progress, KEY_SOURCE_KEYFILE, KEY_SOURCE_PASSWORD};

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
    output: Option<Output>,
    /// 解密前就能得知的原始檔名（只有 v1 檔案才有），僅供顯示。
    known_name: Option<String>,
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
            output: None,
            known_name: None,
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

    /// 依模式與輸入檔，推算預設輸出位置。
    fn suggest_output(&mut self) {
        let Some(input) = self.input_path.clone() else {
            return;
        };
        self.known_name = None;
        match self.mode {
            Mode::Encrypt => {
                let mut s = input.into_os_string();
                s.push(".enc");
                self.output = Some(Output::File(PathBuf::from(s)));
            }
            Mode::Decrypt => {
                // 預設輸出到同一資料夾，檔名使用加密檔內記錄的原始檔名
                self.output = Some(Output::AutoName(parent_dir(&input)));
                if let Ok(info) = crypto::peek_header(&input) {
                    if info.version == 1 {
                        self.status = "提示：這是舊版（v1）加密檔，標頭未受保護且檔名未加密；\
                                       建議解密後用新版重新加密。"
                            .to_owned();
                        self.is_error = false;
                    }
                    self.known_name = info.original_name;
                    self.key_mode = if info.key_source == KEY_SOURCE_KEYFILE {
                        KeyMode::Keyfile
                    } else {
                        KeyMode::Password
                    };
                }
            }
        }
    }

    fn output_label(&self) -> String {
        match &self.output {
            None => "（未指定）".into(),
            Some(Output::File(p)) => p.display().to_string(),
            Some(Output::AutoName(dir)) => {
                let name = self.known_name.as_deref().unwrap_or("原始檔名，解密後還原");
                format!("{}（{name}；同名時自動加編號）", dir.join("").display())
            }
        }
    }

    fn validate(&self) -> Result<Vec<u8>, String> {
        let Some(input) = &self.input_path else {
            return Err("尚未選擇輸入檔。".into());
        };
        match (&self.output, self.mode) {
            (None, _) | (Some(Output::AutoName(_)), Mode::Encrypt) => {
                return Err("尚未指定輸出檔。".into());
            }
            (Some(Output::File(output)), _) if output == input => {
                return Err("輸出檔不可與輸入檔相同。".into());
            }
            _ => {}
        }
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
        let output = self.output.clone().unwrap();

        // 指定的輸出檔已存在時先詢問；只有成功完成才會真的取代它。
        // 自動命名模式永遠不覆蓋，不需詢問。
        let overwrite = matches!(&output, Output::File(p) if p.exists());
        if overwrite && !confirm_overwrite(output.path()) {
            material.zeroize();
            self.status = "已取消：輸出檔已存在。".to_owned();
            self.is_error = true;
            return;
        }
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
                Mode::Encrypt => crypto::encrypt_file(
                    &input,
                    output.path(),
                    &material,
                    key_source,
                    overwrite,
                    &progress,
                )
                .map(|()| output.path().to_path_buf()),
                Mode::Decrypt => {
                    crypto::decrypt_file(&input, &output, &material, overwrite, &progress)
                }
            };
            material.zeroize();

            let msg = match outcome {
                Ok(written) => Ok(format!("完成！已輸出至：\n{}", written.display())),
                // 半成品只存在於暫存檔，crypto 模組失敗時會自行清除
                Err(e) => Err(format!("失敗：{e}")),
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
                        match &self.output {
                            Some(Output::File(p)) => {
                                if let Some(name) = p.file_name().and_then(|s| s.to_str()) {
                                    dlg = dlg.set_file_name(name);
                                }
                                dlg = dlg.set_directory(parent_dir(p));
                            }
                            Some(Output::AutoName(dir)) => {
                                if let Some(name) = &self.known_name {
                                    dlg = dlg.set_file_name(name);
                                }
                                dlg = dlg.set_directory(dir);
                            }
                            None => {}
                        }
                        if let Some(p) = dlg.save_file() {
                            self.output = Some(Output::File(p));
                        }
                    }
                    if self.mode == Mode::Decrypt
                        && matches!(self.output, Some(Output::File(_)))
                        && ui.button("使用原始檔名").clicked()
                    {
                        self.suggest_output();
                    }
                    ui.label(self.output_label());
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

fn parent_dir(path: &Path) -> PathBuf {
    path.parent().map(PathBuf::from).unwrap_or_default()
}

fn confirm_overwrite(output: &Path) -> bool {
    rfd::MessageDialog::new()
        .set_level(rfd::MessageLevel::Warning)
        .set_title("輸出檔已存在")
        .set_description(format!(
            "以下檔案已存在：\n{}\n\n要在處理成功後覆蓋它嗎？（失敗時不會動到原檔）",
            output.display()
        ))
        .set_buttons(rfd::MessageButtons::YesNo)
        .show()
        == rfd::MessageDialogResult::Yes
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
