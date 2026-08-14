# 檔案加解密工具（Rust + egui）

一個 Windows 桌面 GUI 工具，用來對**單一檔案**做加密與解密。介面純中文、免安裝、可攜。

## ✨ 功能特色

- **加密演算法**：AES-256-GCM（AEAD，含完整性驗證，防竄改）
- **金鑰衍生**：Argon2id（64 MiB / 3 iterations / 平行度 1），抗暴力破解
- **串流分塊加密**：以 1 MiB 分塊處理，支援 GB 等級大檔，不吃爆記憶體
- **兩種金鑰來源**：使用者密碼 **或** 金鑰檔（任何檔案皆可當金鑰）
- **產生新檔**：不覆蓋原始檔案（加密輸出 `原名.enc`；解密自動還原原始檔名）
- **進度顯示 + 取消**：即時進度條，可中途取消
- **記憶體安全**：密碼與金鑰使用後以 `zeroize` 清零
- **單一 exe**：`--release` 編譯後為單一執行檔，複製即用

## 🔒 安全設計說明

- AES-256-GCM 為業界標準的認證式加密（AEAD）；若密碼/金鑰錯誤或檔案被竄改，解密會直接失敗並提示，不會輸出錯誤明文。
- 每次加密都會產生**隨機 salt 與隨機 nonce**，寫入檔案標頭；相同檔案相同密碼，每次密文都不同。
- 使用 STREAM（BE32）建構，逐塊各自帶驗證標籤，可安全處理大檔並抵抗分塊重排/截斷攻擊。

> ⚠️ **請務必牢記密碼或保管好金鑰檔。** 本工具無任何後門或救援機制，遺失即無法解密。

## 🛠️ 建置方式

### 前置需求
- 安裝 [Rust 工具鏈](https://rustup.rs/)（含 `cargo`）。

### 在 Windows 上直接編譯（最簡單）
```powershell
cd file-crypto
cargo build --release
```
產物：`target\release\file-crypto.exe`（雙擊即可執行，可自由複製到隨身碟）。

### 從 Linux / macOS 交叉編譯成 Windows exe
```bash
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu
# 產物：target/x86_64-pc-windows-gnu/release/file-crypto.exe
```
（需安裝 MinGW-w64；Debian/Ubuntu：`sudo apt install mingw-w64`）

## 🧪 使用步驟

1. 選擇「🔒 加密」或「🔓 解密」。
2. 點「選擇輸入檔…」挑選要處理的檔案。
3. 確認「輸出位置」（已自動填好建議路徑，可自行更改）。
4. 選金鑰來源：輸入密碼（加密需再確認一次）或選擇金鑰檔。
5. 按「開始加密／解密」，等待進度條完成。

## 📄 加密檔格式

自訂容器，標頭（明文）記錄版本、演算法、Argon2 參數、salt、nonce 前綴與原始檔名，
之後接續 AES-256-GCM STREAM 的密文分塊。詳見 `src/crypto.rs` 檔頭註解。

## 🎨 更換應用程式圖示

圖示分兩個層次，都已設定好：

- **EXE 檔案圖示**（檔案總管縮圖）：由 `build.rs` 透過 `winresource` 把 `assets/icon.ico` 嵌入 exe。
- **視窗圖示**（標題列／工作列）：`main.rs` 用 `eframe::icon_data::from_png_bytes` 讀取 `assets/icon.png`。

想換成自己的圖示，只要替換這兩個檔案即可：
- `assets/icon.ico`（多尺寸，建議含 256/48/32/16）
- `assets/icon.png`（建議 256×256）

> 在 Windows 上以 MSVC 工具鏈編譯，`winresource` 需要 Windows SDK 的 `rc.exe`（安裝 Visual Studio Build Tools 即內含）；GNU 工具鏈則需 MinGW-w64。

## 📁 專案結構
```
file-crypto/
├─ Cargo.toml
├─ build.rs          # 建置腳本：嵌入 exe 圖示與版本資訊
├─ README.md
├─ assets/
│  ├─ icon.ico       # exe 檔案圖示（多尺寸）
│  └─ icon.png       # 視窗／工作列圖示（256×256）
└─ src/
   ├─ main.rs        # 進入點、視窗設定、載入視窗圖示
   ├─ app.rs         # egui GUI 介面與背景工作執行緒
   └─ crypto.rs      # AES-256-GCM + Argon2id 核心與檔案格式
```
