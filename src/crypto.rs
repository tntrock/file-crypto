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
use std::ops::RangeInclusive;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::stream::{DecryptorBE32, EncryptorBE32};
use aes_gcm::{Aes256Gcm, KeyInit};
use anyhow::{anyhow, bail, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

const MAGIC: &[u8; 6] = b"RFENC1";
const VERSION: u8 = 1;
const ALG_AES256GCM: u8 = 1;

pub const KEY_SOURCE_PASSWORD: u8 = 0;
pub const KEY_SOURCE_KEYFILE: u8 = 1;

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
    /// 已淨化、只剩單純檔名的原始檔名，可安全地 join 到輸出目錄。
    pub original_name: String,
    pub key_source: u8,
}

/// 解析後的完整標頭。
struct Header {
    key_source: u8,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    salt: Vec<u8>,
    nonce_prefix: [u8; 7],
    original_name: String,
    /// 標頭總長度（位元組），密文從這裡開始。
    len: u64,
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

/// 讀取並驗證標頭。所有欄位都來自不可信的檔案，數值參數必須先檢查範圍。
fn read_header<R: Read>(r: &mut R) -> Result<Header> {
    let magic: [u8; 6] = read_array(r)?;
    if &magic != MAGIC {
        bail!("這不是本工具產生的加密檔（Magic 不符）");
    }
    let [version, alg, key_source] = read_array(r)?;
    if version != VERSION {
        bail!("不支援的檔案版本: {version}");
    }
    if alg != ALG_AES256GCM {
        bail!("不支援的演算法代碼: {alg}");
    }
    let m_cost = u32::from_le_bytes(read_array(r)?);
    let t_cost = u32::from_le_bytes(read_array(r)?);
    let p_cost = u32::from_le_bytes(read_array(r)?);
    let [salt_len] = read_array(r)?;
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
    let nonce_prefix = read_array(r)?;
    let fname_len = u16::from_le_bytes(read_array(r)?) as usize;
    let mut fname = vec![0u8; fname_len];
    r.read_exact(&mut fname)?;

    Ok(Header {
        key_source,
        m_cost,
        t_cost,
        p_cost,
        salt,
        nonce_prefix,
        original_name: String::from_utf8_lossy(&fname).into_owned(),
        len: (6 + 3 + 12 + 1 + salt_len + 7 + 2 + fname_len) as u64,
    })
}

/// 把標頭裡的原始檔名淨化成「單純的檔名」。
/// 標頭沒有經過驗證，攻擊者可以塞入 `..\..\x` 或 `C:\...` 讓輸出寫到任意位置，
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

/// 檢查輸出路徑，並在同一目錄建立暫存檔。
/// 內容全部寫進暫存檔，成功後才改名成正式檔名（見 `commit_output`）；
/// 任何錯誤或取消時暫存檔會在 drop 時自動刪除，既有的輸出檔完全不會被動到。
fn create_temp_output(input: &Path, output: &Path, overwrite: bool) -> Result<NamedTempFile> {
    if output.exists() {
        if std::fs::canonicalize(input)? == std::fs::canonicalize(output)? {
            bail!("輸出檔不可與輸入檔相同");
        }
        if !overwrite {
            bail!("輸出檔已存在：{}", output.display());
        }
    }
    let dir = match output.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
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

/// 加密單一檔案。`overwrite` 為 false 時，輸出檔已存在就會失敗。
pub fn encrypt_file(
    input: &Path,
    output: &Path,
    material: &[u8],
    key_source: u8,
    overwrite: bool,
    progress: &Progress,
) -> Result<()> {
    let plain_size = std::fs::metadata(input)?.len();
    progress.reset(plain_size);

    let fname = input
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("output")
        .as_bytes();
    if fname.len() > u16::MAX as usize {
        bail!("檔名過長");
    }

    let mut tmp = create_temp_output(input, output, overwrite)?;

    // 產生隨機 salt 與 nonce 前綴
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_prefix = [0u8; 7];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut nonce_prefix);

    let key = derive_key(material, &salt, ARGON_M_COST, ARGON_T_COST, ARGON_P_COST)?;

    let mut writer = BufWriter::new(tmp.as_file_mut());
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
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| anyhow!("金鑰長度錯誤"))?;
    let nonce = GenericArray::from_slice(&nonce_prefix);
    let mut enc = Some(EncryptorBE32::from_aead(cipher, nonce));

    let mut reader = BufReader::new(File::open(input)?);
    let n_chunks = plain_size.div_ceil(PLAIN_CHUNK as u64).max(1);
    let mut buf = Zeroizing::new(vec![0u8; PLAIN_CHUNK]);
    let mut processed: u64 = 0;

    for i in 0..n_chunks {
        if progress.is_cancelled() {
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
    drop(writer);
    commit_output(tmp, output, overwrite)
}

/// 讀取標頭資訊（不解密內容）。
pub fn peek_header(input: &Path) -> Result<HeaderInfo> {
    let header = read_header(&mut BufReader::new(File::open(input)?))?;
    Ok(HeaderInfo {
        original_name: sanitize_file_name(&header.original_name),
        key_source: header.key_source,
    })
}

/// 解密單一檔案。`overwrite` 為 false 時，輸出檔已存在就會失敗。
pub fn decrypt_file(
    input: &Path,
    output: &Path,
    material: &[u8],
    overwrite: bool,
    progress: &Progress,
) -> Result<()> {
    let mut r = BufReader::new(File::open(input)?);
    let header = read_header(&mut r)?;

    let file_size = std::fs::metadata(input)?.len();
    let cipher_size = file_size.saturating_sub(header.len);
    progress.reset(cipher_size);

    let mut tmp = create_temp_output(input, output, overwrite)?;

    let key = derive_key(
        material,
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

    for i in 0..n_chunks {
        if progress.is_cancelled() {
            bail!("使用者已取消");
        }
        let read_n = read_up_to(&mut r, &mut buf)?;
        let chunk = &buf[..read_n];
        let plaintext = Zeroizing::new(if i + 1 == n_chunks {
            dec.take()
                .unwrap()
                .decrypt_last(chunk)
                .map_err(|_| anyhow!(DECRYPT_FAILED))?
        } else {
            dec.as_mut()
                .unwrap()
                .decrypt_next(chunk)
                .map_err(|_| anyhow!(DECRYPT_FAILED))?
        });
        writer.write_all(&plaintext)?;
        processed += read_n as u64;
        progress.processed.store(processed, Ordering::Relaxed);
    }

    writer.flush()?;
    drop(writer);
    commit_output(tmp, output, overwrite)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

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
            PW,
            KEY_SOURCE_PASSWORD,
            false,
            &Progress::default(),
        )
        .unwrap();
    }

    /// 手工組出只有標頭的加密檔，用來模擬惡意／損毀的檔案。
    fn craft_header(dir: &Path, name: &str, m: u32, t: u32, p: u32, salt_len: u8) -> PathBuf {
        let mut h = Vec::new();
        h.extend_from_slice(MAGIC);
        h.extend_from_slice(&[VERSION, ALG_AES256GCM, KEY_SOURCE_PASSWORD]);
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

    fn roundtrip(data: &[u8]) {
        let dir = tempfile::tempdir().unwrap();
        let input = write(dir.path(), "plain.bin", data);
        let enc = dir.path().join("plain.bin.enc");
        let out = dir.path().join("out.bin");
        encrypt(&input, &enc);
        decrypt_file(&enc, &out, PW, false, &Progress::default()).unwrap();
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
        let out = dir.path().join("out.txt");
        assert!(decrypt_file(&enc, &out, PW, false, &Progress::default()).is_err());
    }

    #[test]
    fn truncated_at_chunk_boundary_fails() {
        let dir = tempfile::tempdir().unwrap();
        let input = write(dir.path(), "a.bin", &vec![1u8; PLAIN_CHUNK * 2]);
        let enc = dir.path().join("a.bin.enc");
        encrypt(&input, &enc);
        let bytes = fs::read(&enc).unwrap();
        fs::write(&enc, &bytes[..bytes.len() - ENC_CHUNK]).unwrap();
        let out = dir.path().join("out.bin");
        assert!(decrypt_file(&enc, &out, PW, false, &Progress::default()).is_err());
    }

    // ---- 第 1 點：失敗時不可破壞既有檔案 ----

    #[test]
    fn wrong_password_keeps_existing_output_file() {
        let dir = tempfile::tempdir().unwrap();
        let input = write(dir.path(), "report.docx", b"v1 content");
        let enc = dir.path().join("report.docx.enc");
        encrypt(&input, &enc);
        // 使用者保留了原檔（甚至已經改過），然後用錯密碼解密到同一個路徑
        fs::write(&input, b"newer content").unwrap();
        let res = decrypt_file(&enc, &input, b"wrong", true, &Progress::default());
        assert!(res.is_err());
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
            PW,
            KEY_SOURCE_PASSWORD,
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
        decrypt_file(&enc, &out, PW, true, &Progress::default()).unwrap();
        assert_eq!(fs::read(&out).unwrap(), b"data");
    }

    #[test]
    fn output_same_as_input_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let input = write(dir.path(), "a.txt", b"precious");
        let res = encrypt_file(
            &input,
            &input,
            PW,
            KEY_SOURCE_PASSWORD,
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
        let out = dir.path().join("a.txt");
        assert!(decrypt_file(&enc, &out, b"wrong", false, &Progress::default()).is_err());
        let names: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("a.txt.enc")]);
    }

    // ---- 第 2 點：標頭檔名不可跳出目錄 ----

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
        peek_header(&f).unwrap().original_name
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

    // ---- 第 3 點：標頭參數上限 ----

    fn decrypt_crafted(m: u32, t: u32, p: u32, salt_len: u8) -> Result<()> {
        let dir = tempfile::tempdir().unwrap();
        let f = craft_header(dir.path(), "x", m, t, p, salt_len);
        decrypt_file(&f, &dir.path().join("out"), PW, false, &Progress::default())
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
}
