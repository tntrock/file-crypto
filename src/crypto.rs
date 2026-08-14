//! 核心密碼學模組
//!
//! 檔案格式（自訂容器，小端序）：
//! ┌────────────┬──────┬───────────────────────────────────────────────┐
//! │ 位移       │ 長度 │ 欄位                                           │
//! ├────────────┼──────┼───────────────────────────────────────────────┤
//! │ 0          │ 6    │ Magic  = b"RFENC1"                             │
//! │ 6          │ 1    │ 版本   (VERSION = 1)                           │
//! │ 7          │ 1    │ 演算法 (1 = AES-256-GCM / STREAM BE32)         │
//! │ 8          │ 1    │ 金鑰來源 (0 = 密碼, 1 = 金鑰檔)                │
//! │ 9          │ 4    │ Argon2 m_cost (KiB)                            │
//! │ 13         │ 4    │ Argon2 t_cost (迭代次數)                       │
//! │ 17         │ 4    │ Argon2 p_cost (平行度)                         │
//! │ 21         │ 1    │ Salt 長度 (= 16)                               │
//! │ 22         │ 16   │ Salt                                           │
//! │ 38         │ 7    │ STREAM nonce 前綴 (12 - 5)                     │
//! │ 45         │ 2    │ 原始檔名長度 (u16)                             │
//! │ 47         │ N    │ 原始檔名 (UTF-8)                               │
//! │ 47+N       │ ...  │ 加密後分塊（每塊 = 明文塊 + 16 位元組驗證標籤）│
//! └────────────┴──────┴───────────────────────────────────────────────┘

use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::stream::{DecryptorBE32, EncryptorBE32};
use aes_gcm::{Aes256Gcm, KeyInit};
use anyhow::{anyhow, bail, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use zeroize::Zeroize;

const MAGIC: &[u8; 6] = b"RFENC1";
const VERSION: u8 = 1;
const ALG_AES256GCM: u8 = 1;

pub const KEY_SOURCE_PASSWORD: u8 = 0;
pub const KEY_SOURCE_KEYFILE: u8 = 1;

/// 明文分塊大小（1 MiB）。密文塊會多出 16 位元組的驗證標籤。
const PLAIN_CHUNK: usize = 1024 * 1024;
const TAG_LEN: usize = 16;
const ENC_CHUNK: usize = PLAIN_CHUNK + TAG_LEN;

// Argon2id 參數（可視安全需求調整）
const ARGON_M_COST: u32 = 64 * 1024; // 64 MiB
const ARGON_T_COST: u32 = 3;
const ARGON_P_COST: u32 = 1;

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
    pub original_name: String,
    pub key_source: u8,
}

/// 以 Argon2id 從密碼/金鑰檔內容衍生出 32 位元組金鑰。
fn derive_key(material: &[u8], salt: &[u8], m: u32, t: u32, p: u32) -> Result<[u8; 32]> {
    let params = Params::new(m, t, p, Some(32)).map_err(|e| anyhow!("Argon2 參數錯誤: {e}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon
        .hash_password_into(material, salt, &mut key)
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

/// 加密單一檔案。
pub fn encrypt_file(
    input: &Path,
    output: &Path,
    material: &[u8],
    key_source: u8,
    progress: &Progress,
) -> Result<()> {
    let plain_size = std::fs::metadata(input)?.len();
    progress.reset(plain_size);

    // 產生隨機 salt 與 nonce 前綴
    let mut salt = [0u8; 16];
    let mut nonce_prefix = [0u8; 7];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut nonce_prefix);

    let mut key = derive_key(material, &salt, ARGON_M_COST, ARGON_T_COST, ARGON_P_COST)?;

    let fname = input
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("output")
        .as_bytes();
    if fname.len() > u16::MAX as usize {
        key.zeroize();
        bail!("檔名過長");
    }

    let mut writer = BufWriter::new(File::create(output)?);
    // 寫入標頭
    writer.write_all(MAGIC)?;
    writer.write_all(&[VERSION, ALG_AES256GCM, key_source])?;
    writer.write_all(&ARGON_M_COST.to_le_bytes())?;
    writer.write_all(&ARGON_T_COST.to_le_bytes())?;
    writer.write_all(&ARGON_P_COST.to_le_bytes())?;
    writer.write_all(&[salt.len() as u8])?;
    writer.write_all(&salt)?;
    writer.write_all(&nonce_prefix)?;
    writer.write_all(&(fname.len() as u16).to_le_bytes())?;
    writer.write_all(fname)?;

    // 建立 STREAM 加密器
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| anyhow!("金鑰長度錯誤"))?;
    let nonce = GenericArray::from_slice(&nonce_prefix);
    let mut enc = Some(EncryptorBE32::from_aead(cipher, nonce));

    let mut reader = BufReader::new(File::open(input)?);
    let n_chunks = plain_size.div_ceil(PLAIN_CHUNK as u64).max(1);
    let mut buf = vec![0u8; PLAIN_CHUNK];
    let mut processed: u64 = 0;

    for i in 0..n_chunks {
        if progress.is_cancelled() {
            key.zeroize();
            bail!("使用者已取消");
        }
        let read_n = read_up_to(&mut reader, &mut buf)?;
        let chunk = &buf[..read_n];
        let ciphertext = if i + 1 == n_chunks {
            enc.take()
                .unwrap()
                .encrypt_last(chunk)
                .map_err(|_| anyhow!("加密失敗"))?
        } else {
            enc.as_mut()
                .unwrap()
                .encrypt_next(chunk)
                .map_err(|_| anyhow!("加密失敗"))?
        };
        writer.write_all(&ciphertext)?;
        processed += read_n as u64;
        progress.processed.store(processed, Ordering::Relaxed);
    }

    writer.flush()?;
    buf.zeroize();
    key.zeroize();
    Ok(())
}

/// 讀取標頭資訊（不解密內容）。
pub fn peek_header(input: &Path) -> Result<HeaderInfo> {
    let mut r = BufReader::new(File::open(input)?);

    let mut magic = [0u8; 6];
    r.read_exact(&mut magic)?;
    if &magic != MAGIC {
        bail!("這不是本工具產生的加密檔（Magic 不符）");
    }
    let mut meta = [0u8; 3];
    r.read_exact(&mut meta)?;
    let (version, alg, key_source) = (meta[0], meta[1], meta[2]);
    if version != VERSION {
        bail!("不支援的檔案版本: {version}");
    }
    if alg != ALG_AES256GCM {
        bail!("不支援的演算法代碼: {alg}");
    }
    let mut u32buf = [0u8; 4];
    r.read_exact(&mut u32buf)?; // m_cost
    r.read_exact(&mut u32buf)?; // t_cost
    r.read_exact(&mut u32buf)?; // p_cost
    let mut one = [0u8; 1];
    r.read_exact(&mut one)?;
    let salt_len = one[0] as usize;
    let mut salt = vec![0u8; salt_len];
    r.read_exact(&mut salt)?;
    let mut nonce = [0u8; 7];
    r.read_exact(&mut nonce)?;
    let mut fl = [0u8; 2];
    r.read_exact(&mut fl)?;
    let fname_len = u16::from_le_bytes(fl) as usize;
    let mut fname = vec![0u8; fname_len];
    r.read_exact(&mut fname)?;

    let original_name = String::from_utf8_lossy(&fname).to_string();
    Ok(HeaderInfo {
        original_name,
        key_source,
    })
}

/// 解密單一檔案。
pub fn decrypt_file(
    input: &Path,
    output: &Path,
    material: &[u8],
    progress: &Progress,
) -> Result<()> {
    // 先解析標頭以取得參數
    let mut r = BufReader::new(File::open(input)?);

    let mut magic = [0u8; 6];
    r.read_exact(&mut magic)?;
    if &magic != MAGIC {
        bail!("這不是本工具產生的加密檔（Magic 不符）");
    }
    let mut meta = [0u8; 3];
    r.read_exact(&mut meta)?;
    let (version, alg, _key_source) = (meta[0], meta[1], meta[2]);
    if version != VERSION {
        bail!("不支援的檔案版本: {version}");
    }
    if alg != ALG_AES256GCM {
        bail!("不支援的演算法代碼: {alg}");
    }
    let mut u32buf = [0u8; 4];
    r.read_exact(&mut u32buf)?;
    let m_cost = u32::from_le_bytes(u32buf);
    r.read_exact(&mut u32buf)?;
    let t_cost = u32::from_le_bytes(u32buf);
    r.read_exact(&mut u32buf)?;
    let p_cost = u32::from_le_bytes(u32buf);
    let mut one = [0u8; 1];
    r.read_exact(&mut one)?;
    let salt_len = one[0] as usize;
    let mut salt = vec![0u8; salt_len];
    r.read_exact(&mut salt)?;
    let mut nonce_prefix = [0u8; 7];
    r.read_exact(&mut nonce_prefix)?;
    let mut fl = [0u8; 2];
    r.read_exact(&mut fl)?;
    let fname_len = u16::from_le_bytes(fl) as usize;
    let mut fname = vec![0u8; fname_len];
    r.read_exact(&mut fname)?;

    let header_len = (6 + 3 + 12 + 1 + salt_len + 7 + 2 + fname_len) as u64;
    let file_size = std::fs::metadata(input)?.len();
    let cipher_size = file_size.saturating_sub(header_len);
    progress.reset(cipher_size);

    let mut key = derive_key(material, &salt, m_cost, t_cost, p_cost)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| anyhow!("金鑰長度錯誤"))?;
    let nonce = GenericArray::from_slice(&nonce_prefix);
    let mut dec = Some(DecryptorBE32::from_aead(cipher, nonce));

    let mut writer = BufWriter::new(File::create(output)?);
    let n_chunks = cipher_size.div_ceil(ENC_CHUNK as u64).max(1);
    let mut buf = vec![0u8; ENC_CHUNK];
    let mut processed: u64 = 0;

    for i in 0..n_chunks {
        if progress.is_cancelled() {
            key.zeroize();
            bail!("使用者已取消");
        }
        let read_n = read_up_to(&mut r, &mut buf)?;
        let chunk = &buf[..read_n];
        let plaintext = if i + 1 == n_chunks {
            dec.take()
                .unwrap()
                .decrypt_last(chunk)
                .map_err(|_| anyhow!("解密失敗：密碼/金鑰檔錯誤，或檔案已損毀/被竄改"))?
        } else {
            dec.as_mut()
                .unwrap()
                .decrypt_next(chunk)
                .map_err(|_| anyhow!("解密失敗：密碼/金鑰檔錯誤，或檔案已損毀/被竄改"))?
        };
        writer.write_all(&plaintext)?;
        processed += read_n as u64;
        progress.processed.store(processed, Ordering::Relaxed);
    }

    writer.flush()?;
    buf.zeroize();
    key.zeroize();
    Ok(())
}
