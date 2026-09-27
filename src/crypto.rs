//! 核心密碼學模組
//!
//! 檔案格式 v2（自訂容器，小端序）：
//! ┌────────────┬──────┬───────────────────────────────────────────────┐
//! │ 位移       │ 長度 │ 欄位                                           │
//! ├────────────┼──────┼───────────────────────────────────────────────┤
//! │ 0          │ 6    │ Magic  = b"RFENC1"                             │
//! │ 6          │ 1    │ 版本   (VERSION = 2)                           │
//! │ 7          │ 1    │ 演算法 (1 = AES-256-GCM / STREAM BE32)         │
//! │ 8          │ 1    │ 金鑰來源 (0 = 密碼, 1 = 舊式金鑰檔, 2 = 金鑰檔雜湊)│
//! │ 9          │ 4    │ Argon2 m_cost (KiB)                            │
//! │ 13         │ 4    │ Argon2 t_cost (迭代次數)                       │
//! │ 17         │ 4    │ Argon2 p_cost (平行度)                         │
//! │ 21         │ 1    │ Salt 長度 (= 16)                               │
//! │ 22         │ 16   │ Salt                                           │
//! │ 38         │ 7    │ STREAM nonce 前綴 (12 - 5)                     │
//! │ 45         │ ...  │ 加密後分塊（每塊 = 明文塊 + 16 位元組驗證標籤）│
//! └────────────┴──────┴───────────────────────────────────────────────┘
//!
//! - 整段標頭（位移 0–44）作為每個分塊的 AAD，竄改任一位元組都會解密失敗。
//! - 加密前的明文串流 = 原始檔名長度 (u16) + 原始檔名 (UTF-8) + 檔案內容，
//!   因此原始檔名也經過加密，解密前無法得知。
//!
//! 舊版 v1 仍可解密：v1 在 nonce 前綴之後以明文存放「檔名長度 (u16) + 檔名」，
//! 分塊不帶 AAD，明文串流只有檔案內容。

use std::fs::File;
use std::io::{self, BufReader, BufWriter, Cursor, Read, Write};
use std::ops::RangeInclusive;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::stream::{DecryptorBE32, EncryptorBE32};
use aes_gcm::aead::Payload;
use aes_gcm::{Aes256Gcm, KeyInit};
use anyhow::{anyhow, bail, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use blake2::{Blake2b512, Digest};
use rand::RngCore;
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

const MAGIC: &[u8; 6] = b"RFENC1";
const VERSION: u8 = 2;
const VERSION_V1: u8 = 1;
const ALG_AES256GCM: u8 = 1;

/// 金鑰來源代碼（記錄在標頭，決定解密時如何從使用者輸入產生 Argon2 的輸入）。
pub const KEY_SOURCE_PASSWORD: u8 = 0;
/// 舊式金鑰檔（≤ v1.1.0）：直接以整個金鑰檔內容作為 Argon2 輸入，需整檔讀入記憶體。
pub const KEY_SOURCE_KEYFILE: u8 = 1;
/// 金鑰檔（v1.2.0 起）：以 BLAKE2b-512 串流雜湊金鑰檔，雜湊值作為 Argon2 輸入。
pub const KEY_SOURCE_KEYFILE_HASH: u8 = 2;

/// 標頭內的檔名不可用時，改用這個名稱。
pub const FALLBACK_NAME: &str = "decrypted";

/// 明文分塊大小（1 MiB）。密文塊會多出 16 位元組的驗證標籤。
const PLAIN_CHUNK: usize = 1024 * 1024;
const TAG_LEN: usize = 16;
const ENC_CHUNK: usize = PLAIN_CHUNK + TAG_LEN;

// Argon2id 參數（可視安全需求調整）
const ARGON_M_COST: u32 = 64 * 1024; // 64 MiB
const ARGON_T_COST: u32 = 3;
const ARGON_P_COST: u32 = 1;
const SALT_LEN: usize = 16;

// 解密時接受的標頭參數範圍。標頭來自不可信的檔案，
// 不設上限的話，惡意檔案可以讓程式配置數 TiB 記憶體或永遠算不完。
const ALLOWED_M_COST: RangeInclusive<u32> = 8..=1024 * 1024; // 最多 1 GiB
const ALLOWED_T_COST: RangeInclusive<u32> = 1..=16;
const ALLOWED_P_COST: RangeInclusive<u32> = 1..=16;
const ALLOWED_SALT_LEN: RangeInclusive<usize> = 16..=64;

/// 自動命名時，同名檔案已存在最多嘗試加到幾號。
const MAX_NAME_SUFFIX: u32 = 999;

const DECRYPT_FAILED: &str = "解密失敗：密碼/金鑰檔錯誤，或檔案已損毀/被竄改";

/// 進度與取消旗標，於 GUI 執行緒與工作執行緒間共享。
#[derive(Default)]
pub struct Progress {
    pub processed: AtomicU64,
    pub total: AtomicU64,
    pub cancel: AtomicBool,
}

impl Progress {
    pub fn fraction(&self) -> f32 {
        let total = self.total.load(Ordering::Relaxed).max(1);
        let done = self.processed.load(Ordering::Relaxed);
        (done as f32 / total as f32).clamp(0.0, 1.0)
    }
    fn reset(&self, total: u64) {
        self.processed.store(0, Ordering::Relaxed);
        self.total.store(total.max(1), Ordering::Relaxed);
        self.cancel.store(false, Ordering::Relaxed);
    }
    fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }
}

/// 解密前先讀取標頭，供 GUI 顯示原始檔名等資訊。
pub struct HeaderInfo {
    pub version: u8,
    /// 已淨化、只剩單純檔名的原始檔名，可安全地 join 到輸出目錄。
    /// v2 起檔名經過加密，解密前無法得知，此時為 None。
    pub original_name: Option<String>,
    pub key_source: u8,
}

/// 使用者提供的金鑰來源。
pub enum Secret<'a> {
    Password(&'a [u8]),
    Keyfile(&'a Path),
}

/// 解密輸出位置。
#[derive(Clone)]
pub enum Output {
    /// 寫到指定檔案。
    File(PathBuf),
    /// 寫到指定資料夾，檔名使用加密檔內記錄的原始檔名；同名檔案已存在時自動加編號，絕不覆蓋。
    AutoName(PathBuf),
}

impl Output {
    /// 指定的檔案，或自動命名時的目標資料夾。
    pub fn path(&self) -> &Path {
        match self {
            Output::File(p) | Output::AutoName(p) => p,
        }
    }
}

/// 解析後的完整標頭。
struct Header {
    version: u8,
    key_source: u8,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    salt: Vec<u8>,
    nonce_prefix: [u8; 7],
    /// 只有 v1 才有：以明文存放在標頭裡的原始檔名。
    v1_name: Option<String>,
    /// 標頭的原始位元組；密文從這之後開始，v2 也以它作為 AAD。
    raw: Vec<u8>,
}

impl Header {
    fn aad(&self) -> &[u8] {
        if self.version == VERSION_V1 {
            &[]
        } else {
            &self.raw
        }
    }
}

/// 組出 v2 標頭。
fn build_header(key_source: u8, salt: &[u8], nonce_prefix: &[u8; 7]) -> Vec<u8> {
    let mut h = Vec::with_capacity(45);
    h.extend_from_slice(MAGIC);
    h.extend_from_slice(&[VERSION, ALG_AES256GCM, key_source]);
    h.extend_from_slice(&ARGON_M_COST.to_le_bytes());
    h.extend_from_slice(&ARGON_T_COST.to_le_bytes());
    h.extend_from_slice(&ARGON_P_COST.to_le_bytes());
    h.push(salt.len() as u8);
    h.extend_from_slice(salt);
    h.extend_from_slice(nonce_prefix);
    h
}

/// 以 Argon2id 從密碼/金鑰檔內容衍生出 32 位元組金鑰。
fn derive_key(material: &[u8], salt: &[u8], m: u32, t: u32, p: u32) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(m, t, p, Some(32)).map_err(|e| anyhow!("Argon2 參數錯誤: {e}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(material, salt, key.as_mut())
        .map_err(|e| anyhow!("金鑰衍生失敗: {e}"))?;
    Ok(key)
}

/// 盡可能讀滿 buf，回傳實際讀取的位元組數（0 代表 EOF）。
fn read_up_to<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        match r.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(total)
}

fn read_array<const N: usize, R: Read>(r: &mut R) -> io::Result<[u8; N]> {
    let mut buf = [0u8; N];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

/// 讀取時順便記下讀到的位元組，用來取得標頭原文。
struct Recorder<'a, R> {
    inner: &'a mut R,
    bytes: Vec<u8>,
}

impl<R: Read> Read for Recorder<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.bytes.extend_from_slice(&buf[..n]);
        Ok(n)
    }
}

/// 讀取並驗證標頭。所有欄位都來自不可信的檔案，數值參數必須先檢查範圍。
fn read_header<R: Read>(inner: &mut R) -> Result<Header> {
    let mut r = Recorder {
        inner,
        bytes: Vec::new(),
    };
    let magic: [u8; 6] = read_array(&mut r)?;
    if &magic != MAGIC {
        bail!("這不是本工具產生的加密檔（Magic 不符）");
    }
    let [version, alg, key_source] = read_array(&mut r)?;
    if version != VERSION && version != VERSION_V1 {
        bail!("不支援的檔案版本: {version}（請更新本工具）");
    }
    if alg != ALG_AES256GCM {
        bail!("不支援的演算法代碼: {alg}");
    }
    if !matches!(
        key_source,
        KEY_SOURCE_PASSWORD | KEY_SOURCE_KEYFILE | KEY_SOURCE_KEYFILE_HASH
    ) {
        bail!("不支援的金鑰來源代碼: {key_source}（請更新本工具）");
    }
    let m_cost = u32::from_le_bytes(read_array(&mut r)?);
    let t_cost = u32::from_le_bytes(read_array(&mut r)?);
    let p_cost = u32::from_le_bytes(read_array(&mut r)?);
    let [salt_len] = read_array(&mut r)?;
    let salt_len = salt_len as usize;
    if !ALLOWED_M_COST.contains(&m_cost)
        || !ALLOWED_T_COST.contains(&t_cost)
        || !ALLOWED_P_COST.contains(&p_cost)
        || !ALLOWED_SALT_LEN.contains(&salt_len)
    {
        bail!("標頭參數超出允許範圍（檔案可能已損毀或遭惡意竄改）");
    }
    let mut salt = vec![0u8; salt_len];
    r.read_exact(&mut salt)?;
    let nonce_prefix = read_array(&mut r)?;

    let v1_name = if version == VERSION_V1 {
        let fname_len = u16::from_le_bytes(read_array(&mut r)?) as usize;
        let mut fname = vec![0u8; fname_len];
        r.read_exact(&mut fname)?;
        Some(String::from_utf8_lossy(&fname).into_owned())
    } else {
        None
    };

    Ok(Header {
        version,
        key_source,
        m_cost,
        t_cost,
        p_cost,
        salt,
        nonce_prefix,
        v1_name,
        raw: r.bytes,
    })
}

/// 從 v2 第一個明文分塊的開頭取出原始檔名，回傳（檔名, 其餘的檔案內容）。
fn split_name(plain: &[u8]) -> Result<(String, &[u8])> {
    let malformed = || anyhow!("加密內容格式錯誤");
    let len_bytes = plain.get(..2).ok_or_else(malformed)?;
    let end = 2 + u16::from_le_bytes([len_bytes[0], len_bytes[1]]) as usize;
    let name = plain.get(2..end).ok_or_else(malformed)?;
    Ok((String::from_utf8_lossy(name).into_owned(), &plain[end..]))
}

/// 把原始檔名淨化成「單純的檔名」。
/// 檔名來自不可信的檔案，攻擊者可以塞入 `..\..\x` 或 `C:\...` 讓輸出寫到任意位置，
/// 所以只保留最後一段，並拒絕 Windows 上不合法或有特殊意義的名稱。
fn sanitize_file_name(raw: &str) -> String {
    let last = raw.rsplit(['/', '\\']).next().unwrap_or("");
    // Windows 會忽略結尾的點與空白，".." 也會因此變成空字串
    let name = last.trim_end_matches(['.', ' ']);
    let has_bad_char = name
        .chars()
        .any(|c| c.is_control() || matches!(c, ':' | '*' | '?' | '"' | '<' | '>' | '|'));
    let stem = name
        .split('.')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_uppercase();
    let is_reserved = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.as_bytes()[3].is_ascii_digit());
    if name.trim().is_empty() || has_bad_char || is_reserved {
        FALLBACK_NAME.to_owned()
    } else {
        name.to_owned()
    }
}

/// 檢查指定的輸出檔：不可是輸入檔本身；已存在時必須允許覆蓋。
fn check_output_path(input: &Path, output: &Path, overwrite: bool) -> Result<()> {
    if output.exists() {
        if std::fs::canonicalize(input)? == std::fs::canonicalize(output)? {
            bail!("輸出檔不可與輸入檔相同");
        }
        if !overwrite {
            bail!("輸出檔已存在：{}", output.display());
        }
    }
    Ok(())
}

fn parent_dir(path: &Path) -> &Path {
    match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    }
}

/// 在輸出目錄建立暫存檔。
/// 內容全部寫進暫存檔，成功後才改名成正式檔名；
/// 任何錯誤或取消時暫存檔會在 drop 時自動刪除，既有的輸出檔完全不會被動到。
fn temp_in(dir: &Path) -> Result<NamedTempFile> {
    Ok(tempfile::Builder::new()
        .prefix(".file-crypto-")
        .suffix(".partial")
        .tempfile_in(dir)?)
}

/// 把完成的暫存檔寫入磁碟並改名成正式輸出檔。
fn commit_output(tmp: NamedTempFile, output: &Path, overwrite: bool) -> Result<()> {
    tmp.as_file().sync_all()?;
    let persisted = if overwrite {
        tmp.persist(output)
    } else {
        tmp.persist_noclobber(output)
    };
    persisted.map_err(|e| anyhow!("無法寫入輸出檔 {}: {}", output.display(), e.error))?;
    Ok(())
}

/// 把完成的暫存檔改名為 `dir/name`；已存在時依序嘗試「名稱 (1).副檔名」…，絕不覆蓋。
fn commit_unique(tmp: NamedTempFile, dir: &Path, name: &str) -> Result<PathBuf> {
    tmp.as_file().sync_all()?;
    let (stem, ext) = match name.rfind('.') {
        Some(i) if i > 0 => name.split_at(i),
        _ => (name, ""),
    };
    let mut tmp = tmp;
    for n in 0..=MAX_NAME_SUFFIX {
        let candidate = if n == 0 {
            dir.join(name)
        } else {
            dir.join(format!("{stem} ({n}){ext}"))
        };
        match tmp.persist_noclobber(&candidate) {
            Ok(_) => return Ok(candidate),
            Err(e) if e.error.kind() == io::ErrorKind::AlreadyExists => tmp = e.file,
            Err(e) => bail!("無法寫入輸出檔 {}: {}", candidate.display(), e.error),
        }
    }
    bail!("找不到可用的輸出檔名（{name} 已有太多同名檔案）")
}

/// 加密單一檔案。`overwrite` 為 false 時，輸出檔已存在就會失敗。
pub fn encrypt_file(
    input: &Path,
    output: &Path,
    secret: &Secret,
    overwrite: bool,
    progress: &Progress,
) -> Result<()> {
    let name = input
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("output");
    encrypt_with_name(input, output, name, secret, overwrite, progress)
}

/// 加密單一檔案，並把 `name` 當作原始檔名加密存入。
fn encrypt_with_name(
    input: &Path,
    output: &Path,
    name: &str,
    secret: &Secret,
    overwrite: bool,
    progress: &Progress,
) -> Result<()> {
    let key_source = match secret {
        Secret::Password(_) => KEY_SOURCE_PASSWORD,
        Secret::Keyfile(_) => KEY_SOURCE_KEYFILE_HASH,
    };
    let material = key_material(key_source, secret)?;
    if name.len() > u16::MAX as usize {
        bail!("檔名過長");
    }
    // 明文串流 = 檔名長度 + 檔名 + 檔案內容
    let mut meta = Vec::with_capacity(2 + name.len());
    meta.extend_from_slice(&(name.len() as u16).to_le_bytes());
    meta.extend_from_slice(name.as_bytes());
    let plain_size = std::fs::metadata(input)?.len() + meta.len() as u64;
    progress.reset(plain_size);

    check_output_path(input, output, overwrite)?;
    let mut tmp = temp_in(parent_dir(output))?;

    // 產生隨機 salt 與 nonce 前綴
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_prefix = [0u8; 7];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut nonce_prefix);

    let key = derive_key(&material, &salt, ARGON_M_COST, ARGON_T_COST, ARGON_P_COST)?;
    let header = build_header(key_source, &salt, &nonce_prefix);

    let mut writer = BufWriter::new(tmp.as_file_mut());
    writer.write_all(&header)?;

    // 建立 STREAM 加密器
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| anyhow!("金鑰長度錯誤"))?;
    let nonce = GenericArray::from_slice(&nonce_prefix);
    let mut enc = Some(EncryptorBE32::from_aead(cipher, nonce));

    let mut reader = Cursor::new(meta).chain(BufReader::new(File::open(input)?));
    let n_chunks = plain_size.div_ceil(PLAIN_CHUNK as u64).max(1);
    let mut buf = Zeroizing::new(vec![0u8; PLAIN_CHUNK]);
    let mut processed: u64 = 0;

    for i in 0..n_chunks {
        if progress.is_cancelled() {
            bail!("使用者已取消");
        }
        let read_n = read_up_to(&mut reader, &mut buf)?;
        let payload = Payload {
            msg: &buf[..read_n],
            aad: &header,
        };
        let ciphertext = if i + 1 == n_chunks {
            enc.take().unwrap().encrypt_last(payload)
        } else {
            enc.as_mut().unwrap().encrypt_next(payload)
        }
        .map_err(|_| anyhow!("加密失敗"))?;
        writer.write_all(&ciphertext)?;
        processed += read_n as u64;
        progress.processed.store(processed, Ordering::Relaxed);
    }

    writer.flush()?;
    drop(writer);
    commit_output(tmp, output, overwrite)
}

/// 讀取標頭資訊（不解密內容）。
pub fn peek_header(input: &Path) -> Result<HeaderInfo> {
    let header = read_header(&mut BufReader::new(File::open(input)?))?;
    Ok(HeaderInfo {
        version: header.version,
        original_name: header.v1_name.as_deref().map(sanitize_file_name),
        key_source: header.key_source,
    })
}

/// 解密單一檔案，回傳實際寫出的檔案路徑。
/// `overwrite` 只對 `Output::File` 有意義：為 false 時，輸出檔已存在就會失敗。
pub fn decrypt_file(
    input: &Path,
    output: &Output,
    secret: &Secret,
    overwrite: bool,
    progress: &Progress,
) -> Result<PathBuf> {
    let mut r = BufReader::new(File::open(input)?);
    let header = read_header(&mut r)?;

    let file_size = std::fs::metadata(input)?.len();
    let cipher_size = file_size.saturating_sub(header.raw.len() as u64);
    progress.reset(cipher_size);

    let out_dir = match output {
        Output::File(path) => {
            check_output_path(input, path, overwrite)?;
            parent_dir(path)
        }
        Output::AutoName(dir) => dir.as_path(),
    };
    let mut tmp = temp_in(out_dir)?;

    let material = key_material(header.key_source, secret)?;
    let key = derive_key(
        &material,
        &header.salt,
        header.m_cost,
        header.t_cost,
        header.p_cost,
    )?;
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| anyhow!("金鑰長度錯誤"))?;
    let nonce = GenericArray::from_slice(&header.nonce_prefix);
    let mut dec = Some(DecryptorBE32::from_aead(cipher, nonce));

    let mut writer = BufWriter::new(tmp.as_file_mut());
    let n_chunks = cipher_size.div_ceil(ENC_CHUNK as u64).max(1);
    let mut buf = vec![0u8; ENC_CHUNK];
    let mut processed: u64 = 0;
    let mut original_name = header.v1_name.clone();

    for i in 0..n_chunks {
        if progress.is_cancelled() {
            bail!("使用者已取消");
        }
        let read_n = read_up_to(&mut r, &mut buf)?;
        let payload = Payload {
            msg: &buf[..read_n],
            aad: header.aad(),
        };
        let plaintext = Zeroizing::new(
            if i + 1 == n_chunks {
                dec.take().unwrap().decrypt_last(payload)
            } else {
                dec.as_mut().unwrap().decrypt_next(payload)
            }
            .map_err(|_| anyhow!(DECRYPT_FAILED))?,
        );
        let mut body: &[u8] = &plaintext;
        if i == 0 && header.version != VERSION_V1 {
            let (name, rest) = split_name(body)?;
            original_name = Some(name);
            body = rest;
        }
        writer.write_all(body)?;
        processed += read_n as u64;
        progress.processed.store(processed, Ordering::Relaxed);
    }

    writer.flush()?;
    drop(writer);
    match output {
        Output::File(path) => {
            commit_output(tmp, path, overwrite)?;
            Ok(path.clone())
        }
        Output::AutoName(dir) => {
            let name = sanitize_file_name(original_name.as_deref().unwrap_or(""));
            commit_unique(tmp, dir, &name)
        }
    }
}

/// 以 BLAKE2b-512 串流雜湊金鑰檔，不論金鑰檔多大都只佔用固定記憶體。
fn hash_keyfile(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let mut file = File::open(path).map_err(|e| anyhow!("讀取金鑰檔失敗: {e}"))?;
    let mut hasher = Blake2b512::new();
    let mut buf = Zeroizing::new(vec![0u8; PLAIN_CHUNK]);
    let mut total: u64 = 0;
    loop {
        let n = read_up_to(&mut file, &mut buf).map_err(|e| anyhow!("讀取金鑰檔失敗: {e}"))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    if total == 0 {
        bail!("金鑰檔是空的，請選擇其他檔案");
    }
    Ok(Zeroizing::new(hasher.finalize().to_vec()))
}

/// 依標頭記錄的金鑰來源，把使用者輸入轉成 Argon2 的輸入。
fn key_material(key_source: u8, secret: &Secret) -> Result<Zeroizing<Vec<u8>>> {
    match (key_source, secret) {
        (KEY_SOURCE_PASSWORD, Secret::Password(p)) => Ok(Zeroizing::new(p.to_vec())),
        (KEY_SOURCE_KEYFILE_HASH, Secret::Keyfile(path)) => hash_keyfile(path),
        (KEY_SOURCE_KEYFILE, Secret::Keyfile(path)) => Ok(Zeroizing::new(
            std::fs::read(path).map_err(|e| anyhow!("讀取金鑰檔失敗: {e}"))?,
        )),
        (KEY_SOURCE_PASSWORD, Secret::Keyfile(_)) => bail!("此檔案是用密碼加密的，請改輸入密碼"),
        (_, Secret::Password(_)) => bail!("此檔案是用金鑰檔加密的，請改選擇金鑰檔"),
        _ => bail!("不支援的金鑰來源代碼: {key_source}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const PW: &[u8] = "正確的密碼".as_bytes();

    fn write(dir: &Path, name: &str, data: &[u8]) -> PathBuf {
        let p = dir.join(name);
        fs::write(&p, data).unwrap();
        p
    }

    fn encrypt(input: &Path, output: &Path) {
        encrypt_file(
            input,
            output,
            &Secret::Password(PW),
            false,
            &Progress::default(),
        )
        .unwrap();
    }

    fn decrypt_to(input: &Path, output: &Path, pw: &[u8], overwrite: bool) -> Result<PathBuf> {
        decrypt_file(
            input,
            &Output::File(output.to_path_buf()),
            &Secret::Password(pw),
            overwrite,
            &Progress::default(),
        )
    }

    fn decrypt_auto(input: &Path, dir: &Path) -> Result<PathBuf> {
        decrypt_file(
            input,
            &Output::AutoName(dir.to_path_buf()),
            &Secret::Password(PW),
            false,
            &Progress::default(),
        )
    }

    /// 手工組出只有 v1 標頭的加密檔，用來模擬惡意／損毀的檔案。
    fn craft_header(dir: &Path, name: &str, m: u32, t: u32, p: u32, salt_len: u8) -> PathBuf {
        let mut h = Vec::new();
        h.extend_from_slice(MAGIC);
        h.extend_from_slice(&[1, ALG_AES256GCM, KEY_SOURCE_PASSWORD]);
        h.extend_from_slice(&m.to_le_bytes());
        h.extend_from_slice(&t.to_le_bytes());
        h.extend_from_slice(&p.to_le_bytes());
        h.push(salt_len);
        h.extend(std::iter::repeat_n(7u8, salt_len as usize));
        h.extend_from_slice(&[0u8; 7]);
        h.extend_from_slice(&(name.len() as u16).to_le_bytes());
        h.extend_from_slice(name.as_bytes());
        h.extend_from_slice(&[0u8; 32]); // 假的密文
        write(dir, "crafted.enc", &h)
    }

    /// 把 repo 內的 v1 範例檔複製到暫存目錄（由 v1.0.1 產生，原始檔名「v1 範例.txt」）。
    fn v1_fixture(dir: &Path) -> PathBuf {
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v1_sample.enc");
        let dst = dir.join("v1_sample.enc");
        fs::copy(src, &dst).unwrap();
        dst
    }
    const V1_CONTENT: &str = "這是 v1 格式的範例內容。\n";

    fn roundtrip(data: &[u8]) {
        let dir = tempfile::tempdir().unwrap();
        let input = write(dir.path(), "plain.bin", data);
        let enc = dir.path().join("plain.bin.enc");
        let out = dir.path().join("out.bin");
        encrypt(&input, &enc);
        decrypt_to(&enc, &out, PW, false).unwrap();
        assert_eq!(fs::read(&out).unwrap(), data);
    }

    #[test]
    fn roundtrip_small_file() {
        roundtrip(b"hello, world");
    }

    #[test]
    fn roundtrip_empty_file() {
        roundtrip(b"");
    }

    #[test]
    fn roundtrip_exact_chunk_multiple() {
        roundtrip(&vec![0xAB; PLAIN_CHUNK * 2]);
    }

    #[test]
    fn roundtrip_chunk_plus_one() {
        roundtrip(&vec![0xCD; PLAIN_CHUNK + 1]);
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let dir = tempfile::tempdir().unwrap();
        let input = write(dir.path(), "a.txt", b"secret data");
        let enc = dir.path().join("a.txt.enc");
        encrypt(&input, &enc);
        let mut bytes = fs::read(&enc).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        fs::write(&enc, bytes).unwrap();
        assert!(decrypt_to(&enc, &dir.path().join("out.txt"), PW, false).is_err());
    }

    #[test]
    fn truncated_at_chunk_boundary_fails() {
        let dir = tempfile::tempdir().unwrap();
        let input = write(dir.path(), "a.bin", &vec![1u8; PLAIN_CHUNK * 3]);
        let enc = dir.path().join("a.bin.enc");
        encrypt(&input, &enc);
        let bytes = fs::read(&enc).unwrap();
        fs::write(&enc, &bytes[..bytes.len() - ENC_CHUNK]).unwrap();
        assert!(decrypt_to(&enc, &dir.path().join("out.bin"), PW, false).is_err());
    }

    // ---- 失敗時不可破壞既有檔案 ----

    #[test]
    fn wrong_password_keeps_existing_output_file() {
        let dir = tempfile::tempdir().unwrap();
        let input = write(dir.path(), "report.docx", b"v1 content");
        let enc = dir.path().join("report.docx.enc");
        encrypt(&input, &enc);
        // 使用者保留了原檔（甚至已經改過），然後用錯密碼解密到同一個路徑
        fs::write(&input, b"newer content").unwrap();
        assert!(decrypt_to(&enc, &input, b"wrong", true).is_err());
        assert_eq!(fs::read(&input).unwrap(), b"newer content");
    }

    #[test]
    fn refuses_to_overwrite_without_permission() {
        let dir = tempfile::tempdir().unwrap();
        let input = write(dir.path(), "a.txt", b"data");
        let enc = write(dir.path(), "a.txt.enc", b"existing, unrelated");
        let res = encrypt_file(
            &input,
            &enc,
            &Secret::Password(PW),
            false,
            &Progress::default(),
        );
        assert!(res.is_err());
        assert_eq!(fs::read(&enc).unwrap(), b"existing, unrelated");
    }

    #[test]
    fn overwrite_replaces_existing_output_on_success() {
        let dir = tempfile::tempdir().unwrap();
        let input = write(dir.path(), "a.txt", b"data");
        let enc = dir.path().join("a.txt.enc");
        encrypt(&input, &enc);
        let out = write(dir.path(), "out.txt", b"old");
        assert_eq!(decrypt_to(&enc, &out, PW, true).unwrap(), out);
        assert_eq!(fs::read(&out).unwrap(), b"data");
    }

    #[test]
    fn output_same_as_input_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let input = write(dir.path(), "a.txt", b"precious");
        let res = encrypt_file(
            &input,
            &input,
            &Secret::Password(PW),
            true,
            &Progress::default(),
        );
        assert!(res.is_err());
        assert_eq!(fs::read(&input).unwrap(), b"precious");
    }

    #[test]
    fn failed_decrypt_leaves_no_files_behind() {
        let dir = tempfile::tempdir().unwrap();
        let input = write(dir.path(), "a.txt", b"data");
        let enc = dir.path().join("a.txt.enc");
        encrypt(&input, &enc);
        fs::remove_file(&input).unwrap();
        assert!(decrypt_to(&enc, &dir.path().join("a.txt"), b"wrong", false).is_err());
        let names: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("a.txt.enc")]);
    }

    // ---- 標頭檔名不可跳出目錄 ----

    fn peeked_name(name: &str) -> String {
        let dir = tempfile::tempdir().unwrap();
        let f = craft_header(
            dir.path(),
            name,
            ARGON_M_COST,
            ARGON_T_COST,
            ARGON_P_COST,
            16,
        );
        peek_header(&f).unwrap().original_name.unwrap()
    }

    #[test]
    fn header_name_with_parent_dirs_is_reduced_to_file_name() {
        assert_eq!(peeked_name(r"..\..\evil.txt"), "evil.txt");
        assert_eq!(peeked_name("../../evil.txt"), "evil.txt");
    }

    #[test]
    fn header_name_with_absolute_path_is_reduced_to_file_name() {
        assert_eq!(peeked_name(r"C:\Users\x\Startup\evil.exe"), "evil.exe");
        assert_eq!(peeked_name("C:evil.exe"), FALLBACK_NAME);
    }

    #[test]
    fn header_name_that_is_not_a_file_name_falls_back() {
        for bad in ["", "..", ".", "   ", "CON", "nul.txt", "a\u{0}b"] {
            assert_eq!(peeked_name(bad), FALLBACK_NAME, "name {bad:?}");
        }
    }

    #[test]
    fn normal_header_name_is_kept() {
        assert_eq!(peeked_name("報告 v2.docx"), "報告 v2.docx");
    }

    // ---- 標頭參數上限 ----

    fn decrypt_crafted(m: u32, t: u32, p: u32, salt_len: u8) -> Result<PathBuf> {
        let dir = tempfile::tempdir().unwrap();
        let f = craft_header(dir.path(), "x", m, t, p, salt_len);
        decrypt_to(&f, &dir.path().join("out"), PW, false)
    }

    #[test]
    fn rejects_excessive_memory_cost() {
        let err = decrypt_crafted(u32::MAX, 3, 1, 16).unwrap_err();
        assert!(err.to_string().contains("超出允許範圍"), "{err}");
    }

    #[test]
    fn rejects_excessive_time_cost() {
        let err = decrypt_crafted(ARGON_M_COST, u32::MAX, 1, 16).unwrap_err();
        assert!(err.to_string().contains("超出允許範圍"), "{err}");
    }

    #[test]
    fn rejects_excessive_parallelism() {
        let err = decrypt_crafted(ARGON_M_COST, 3, u32::MAX, 16).unwrap_err();
        assert!(err.to_string().contains("超出允許範圍"), "{err}");
    }

    #[test]
    fn rejects_bad_salt_length() {
        for len in [0u8, 255] {
            let err = decrypt_crafted(ARGON_M_COST, 3, 1, len).unwrap_err();
            assert!(err.to_string().contains("超出允許範圍"), "len {len}: {err}");
        }
    }

    #[test]
    fn peek_header_also_rejects_bad_params() {
        let dir = tempfile::tempdir().unwrap();
        let f = craft_header(dir.path(), "x", u32::MAX, 3, 1, 16);
        assert!(peek_header(&f).is_err());
    }

    // ---- v2：標頭受驗證保護 ----

    #[test]
    fn new_files_use_version_2() {
        let dir = tempfile::tempdir().unwrap();
        let input = write(dir.path(), "a.txt", b"data");
        let enc = dir.path().join("a.txt.enc");
        encrypt(&input, &enc);
        let info = peek_header(&enc).unwrap();
        assert_eq!(info.version, 2);
        assert_eq!(info.key_source, KEY_SOURCE_PASSWORD);
    }

    #[test]
    fn tampered_header_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let input = write(dir.path(), "a.txt", b"data");
        let enc = dir.path().join("a.txt.enc");
        encrypt(&input, &enc);
        let mut bytes = fs::read(&enc).unwrap();
        bytes[8] = KEY_SOURCE_KEYFILE; // 竄改「金鑰來源」欄位
        fs::write(&enc, bytes).unwrap();
        assert!(decrypt_to(&enc, &dir.path().join("out.txt"), PW, false).is_err());
    }

    // ---- v2：原始檔名經過加密 ----

    #[test]
    fn original_name_is_not_stored_in_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let input = write(dir.path(), "2025薪資明細.xlsx", b"data");
        let enc = dir.path().join("x.enc");
        encrypt(&input, &enc);
        let bytes = fs::read(&enc).unwrap();
        let name = "2025薪資明細".as_bytes();
        assert!(!bytes.windows(name.len()).any(|w| w == name));
        assert_eq!(peek_header(&enc).unwrap().original_name, None);
    }

    #[test]
    fn auto_name_restores_original_name_after_rename() {
        let dir = tempfile::tempdir().unwrap();
        let src = tempfile::tempdir().unwrap();
        let input = write(src.path(), "報告.docx", b"report body");
        let enc = dir.path().join("renamed.enc");
        encrypt(&input, &enc);
        let out = decrypt_auto(&enc, dir.path()).unwrap();
        assert_eq!(out, dir.path().join("報告.docx"));
        assert_eq!(fs::read(&out).unwrap(), b"report body");
    }

    #[test]
    fn auto_name_never_overwrites_existing_files() {
        let dir = tempfile::tempdir().unwrap();
        let input = write(dir.path(), "報告.docx", b"new");
        let enc = dir.path().join("報告.docx.enc");
        encrypt(&input, &enc);
        write(dir.path(), "報告 (1).docx", b"also existing");

        let out = decrypt_auto(&enc, dir.path()).unwrap();
        assert_eq!(out, dir.path().join("報告 (2).docx"));
        assert_eq!(fs::read(&out).unwrap(), b"new");
        assert_eq!(fs::read(dir.path().join("報告.docx")).unwrap(), b"new");
        assert_eq!(
            fs::read(dir.path().join("報告 (1).docx")).unwrap(),
            b"also existing"
        );
    }

    #[test]
    fn auto_name_sanitizes_decrypted_name() {
        let dir = tempfile::tempdir().unwrap();
        let input = write(dir.path(), "a.txt", b"payload");
        let enc = dir.path().join("a.enc");
        // 持有金鑰的人仍可能在加密內容裡塞入惡意檔名
        encrypt_with_name(
            &input,
            &enc,
            r"..\..\evil.txt",
            &Secret::Password(PW),
            false,
            &Progress::default(),
        )
        .unwrap();
        let out = decrypt_auto(&enc, dir.path()).unwrap();
        assert_eq!(out, dir.path().join("evil.txt"));
    }

    #[test]
    fn auto_name_failure_leaves_no_files_behind() {
        let dir = tempfile::tempdir().unwrap();
        let input = write(dir.path(), "a.txt", b"data");
        let enc = dir.path().join("a.txt.enc");
        encrypt(&input, &enc);
        fs::remove_file(&input).unwrap();
        let res = decrypt_file(
            &enc,
            &Output::AutoName(dir.path().into()),
            &Secret::Password(b"wrong"),
            false,
            &Progress::default(),
        );
        assert!(res.is_err());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    // ---- v1 相容性 ----

    #[test]
    fn v1_file_still_decrypts() {
        let dir = tempfile::tempdir().unwrap();
        let enc = v1_fixture(dir.path());
        let out = dir.path().join("out.txt");
        decrypt_to(&enc, &out, PW, false).unwrap();
        assert_eq!(fs::read_to_string(&out).unwrap(), V1_CONTENT);
    }

    #[test]
    fn v1_header_name_is_visible_before_decrypting() {
        let dir = tempfile::tempdir().unwrap();
        let info = peek_header(&v1_fixture(dir.path())).unwrap();
        assert_eq!(info.version, 1);
        assert_eq!(info.original_name.as_deref(), Some("v1 範例.txt"));
    }

    #[test]
    fn v1_file_auto_name_uses_header_name() {
        let dir = tempfile::tempdir().unwrap();
        let enc = v1_fixture(dir.path());
        let out = decrypt_auto(&enc, dir.path()).unwrap();
        assert_eq!(out, dir.path().join("v1 範例.txt"));
        assert_eq!(fs::read_to_string(&out).unwrap(), V1_CONTENT);
    }

    // ---- 金鑰檔 ----

    fn fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name)
    }

    fn encrypt_with_keyfile(dir: &Path, keyfile: &Path) -> PathBuf {
        let input = write(dir, "a.txt", b"keyfile protected");
        let enc = dir.join("a.txt.enc");
        encrypt_file(
            &input,
            &enc,
            &Secret::Keyfile(keyfile),
            false,
            &Progress::default(),
        )
        .unwrap();
        fs::remove_file(&input).unwrap();
        enc
    }

    #[test]
    fn keyfile_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let kf = write(dir.path(), "key.jpg", &vec![0x5A; PLAIN_CHUNK * 2 + 123]);
        let enc = encrypt_with_keyfile(dir.path(), &kf);
        let out = decrypt_file(
            &enc,
            &Output::AutoName(dir.path().into()),
            &Secret::Keyfile(&kf),
            false,
            &Progress::default(),
        )
        .unwrap();
        assert_eq!(fs::read(out).unwrap(), b"keyfile protected");
    }

    #[test]
    fn new_keyfile_encryption_uses_hashed_key_source() {
        let dir = tempfile::tempdir().unwrap();
        let kf = write(dir.path(), "key.bin", b"some key material");
        let enc = encrypt_with_keyfile(dir.path(), &kf);
        assert_eq!(
            peek_header(&enc).unwrap().key_source,
            KEY_SOURCE_KEYFILE_HASH
        );
    }

    #[test]
    fn keyfile_digest_matches_blake2b_of_whole_file() {
        use blake2::{Blake2b512, Digest};
        let dir = tempfile::tempdir().unwrap();
        let data: Vec<u8> = (0..PLAIN_CHUNK * 3 + 7).map(|i| (i % 251) as u8).collect();
        let kf = write(dir.path(), "big.bin", &data);
        assert_eq!(
            hash_keyfile(&kf).unwrap().as_slice(),
            Blake2b512::digest(&data).as_slice()
        );
    }

    #[test]
    fn different_keyfile_fails() {
        let dir = tempfile::tempdir().unwrap();
        let kf = write(dir.path(), "key.bin", b"original key");
        let enc = encrypt_with_keyfile(dir.path(), &kf);
        let other = write(dir.path(), "other.bin", b"original kez");
        let res = decrypt_file(
            &enc,
            &Output::AutoName(dir.path().into()),
            &Secret::Keyfile(&other),
            false,
            &Progress::default(),
        );
        assert!(res.is_err());
    }

    #[test]
    fn empty_keyfile_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let kf = write(dir.path(), "empty.bin", b"");
        let input = write(dir.path(), "a.txt", b"data");
        let err = encrypt_file(
            &input,
            &dir.path().join("a.enc"),
            &Secret::Keyfile(&kf),
            false,
            &Progress::default(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("金鑰檔是空的"), "{err}");
    }

    #[test]
    fn legacy_raw_keyfile_file_still_decrypts() {
        // 由 v1.1.0 以「金鑰來源 = 1（直接使用金鑰檔內容）」產生
        let dir = tempfile::tempdir().unwrap();
        let enc = dir.path().join("legacy.enc");
        fs::copy(fixture("v2_keyfile_legacy.enc"), &enc).unwrap();
        assert_eq!(peek_header(&enc).unwrap().key_source, KEY_SOURCE_KEYFILE);
        let kf = fixture("keyfile.bin");
        let out = decrypt_file(
            &enc,
            &Output::AutoName(dir.path().into()),
            &Secret::Keyfile(&kf),
            false,
            &Progress::default(),
        )
        .unwrap();
        assert_eq!(out, dir.path().join("v2 金鑰檔範例.txt"));
        assert_eq!(
            fs::read_to_string(out).unwrap(),
            "這是用金鑰檔加密的 v2 範例內容。\n"
        );
    }

    #[test]
    fn password_given_for_keyfile_encrypted_file_explains_why() {
        let dir = tempfile::tempdir().unwrap();
        let kf = write(dir.path(), "key.bin", b"k");
        let enc = encrypt_with_keyfile(dir.path(), &kf);
        let err = decrypt_file(
            &enc,
            &Output::AutoName(dir.path().into()),
            &Secret::Password(PW),
            false,
            &Progress::default(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("請改選擇金鑰檔"), "{err}");
    }

    #[test]
    fn keyfile_given_for_password_encrypted_file_explains_why() {
        let dir = tempfile::tempdir().unwrap();
        let input = write(dir.path(), "a.txt", b"data");
        let enc = dir.path().join("a.txt.enc");
        encrypt(&input, &enc);
        let kf = write(dir.path(), "key.bin", b"k");
        let err = decrypt_file(
            &enc,
            &Output::AutoName(dir.path().into()),
            &Secret::Keyfile(&kf),
            false,
            &Progress::default(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("請改輸入密碼"), "{err}");
    }

    #[test]
    fn unknown_key_source_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let input = write(dir.path(), "a.txt", b"data");
        let enc = dir.path().join("a.txt.enc");
        encrypt(&input, &enc);
        let mut bytes = fs::read(&enc).unwrap();
        bytes[8] = 99;
        fs::write(&enc, bytes).unwrap();
        let err = peek_header(&enc).err().expect("應該失敗");
        assert!(err.to_string().contains("不支援的金鑰來源"), "{err}");
    }
}
