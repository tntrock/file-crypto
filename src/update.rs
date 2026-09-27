//! 檢查 GitHub 上是否有新版本，以及保存「啟動時自動檢查」設定。
//!
//! 只負責提示，不會自動下載或執行任何檔案：下載頁網址由程式自行組出，
//! 不使用 API 回傳的連結。

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};

use crate::project;

/// 目前程式版本（取自 Cargo.toml）。
pub const CURRENT_VERSION: &str = project::VERSION;

const SETTINGS_KEY_AUTO_CHECK: &str = "auto_check_updates";

/// GitHub 上的新版本。
#[derive(Clone, Debug, PartialEq)]
pub struct Release {
    /// 不含開頭 v 的版本號，例如 "1.3.0"。
    pub version: String,
}

impl Release {
    pub fn page_url(&self) -> String {
        project::release_page_url(&self.version)
    }
}

/// 解析 "1.2.3" 或 "v1.2.3"。
fn parse_version(s: &str) -> Option<[u64; 3]> {
    let s = s.strip_prefix('v').unwrap_or(s);
    let mut parts = s.split('.').map(|p| p.parse::<u64>().ok());
    let v = [parts.next()??, parts.next()??, parts.next()??];
    parts.next().is_none().then_some(v)
}

/// 從 GitHub `releases/latest` API 的回應判斷是否有比 `current` 更新的版本。
fn newer_release(json: &str, current: &str) -> Result<Option<Release>> {
    let value: serde_json::Value = serde_json::from_str(json).context("無法解析 GitHub 回應")?;
    let tag = value["tag_name"]
        .as_str()
        .ok_or_else(|| anyhow!("GitHub 回應中沒有版本資訊"))?;
    let latest = parse_version(tag).ok_or_else(|| anyhow!("無法辨識的版本號：{tag}"))?;
    let current =
        parse_version(current).ok_or_else(|| anyhow!("無法辨識目前的版本號：{current}"))?;
    Ok((latest > current).then(|| Release {
        version: format!("{}.{}.{}", latest[0], latest[1], latest[2]),
    }))
}

/// 連線到 GitHub 查詢最新版本。
pub fn check_latest() -> Result<Option<Release>> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(10)))
        .user_agent(format!("file-crypto/{CURRENT_VERSION}"))
        .build()
        .into();
    let json = agent
        .get(project::latest_release_api_url())
        .header("Accept", "application/vnd.github+json")
        .call()
        .context("無法連線到 GitHub")?
        .body_mut()
        .read_to_string()
        .context("讀取 GitHub 回應失敗")?;
    newer_release(&json, CURRENT_VERSION)
}

/// 使用者設定。
#[derive(Clone, Debug, PartialEq)]
pub struct Settings {
    pub auto_check_updates: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            auto_check_updates: true,
        }
    }
}

impl Settings {
    /// 解析 `key = value` 格式的設定；無法辨識的行會被忽略。
    fn parse(text: &str) -> Self {
        let mut settings = Self::default();
        for line in text.lines() {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            if key.trim() == SETTINGS_KEY_AUTO_CHECK {
                match value.trim() {
                    "true" => settings.auto_check_updates = true,
                    "false" => settings.auto_check_updates = false,
                    _ => {}
                }
            }
        }
        settings
    }

    fn to_text(&self) -> String {
        format!(
            "# 檔案加解密工具設定\n{SETTINGS_KEY_AUTO_CHECK} = {}\n",
            self.auto_check_updates
        )
    }

    /// `%APPDATA%\file-crypto\settings.ini`
    fn path() -> Option<PathBuf> {
        let appdata = std::env::var_os("APPDATA")?;
        Some(
            PathBuf::from(appdata)
                .join("file-crypto")
                .join("settings.ini"),
        )
    }

    /// 讀取設定；檔案不存在或無法讀取時使用預設值。
    pub fn load() -> Self {
        Self::path()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .map(|text| Self::parse(&text))
            .unwrap_or_default()
    }

    /// 保存設定。
    pub fn save(&self) -> Result<()> {
        let path = Self::path().ok_or_else(|| anyhow!("找不到 APPDATA 資料夾"))?;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(&path, self.to_text())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn latest_json(tag: &str) -> String {
        format!(r#"{{"tag_name":"{tag}","html_url":"https://evil.example/x","draft":false}}"#)
    }

    #[test]
    fn parses_versions_with_or_without_v() {
        assert_eq!(parse_version("v1.2.0"), Some([1, 2, 0]));
        assert_eq!(parse_version("1.10.3"), Some([1, 10, 3]));
    }

    #[test]
    fn rejects_malformed_versions() {
        for bad in ["Appliction", "v1.2", "1.2.3.4", "v1.x.0", "", "v"] {
            assert_eq!(parse_version(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn detects_newer_release() {
        let r = newer_release(&latest_json("v1.3.0"), "1.2.0").unwrap();
        assert_eq!(
            r,
            Some(Release {
                version: "1.3.0".into()
            })
        );
    }

    #[test]
    fn compares_numerically_not_as_text() {
        let r = newer_release(&latest_json("v1.10.0"), "1.9.9").unwrap();
        assert_eq!(r.map(|r| r.version), Some("1.10.0".into()));
    }

    #[test]
    fn same_or_older_release_is_not_newer() {
        assert_eq!(
            newer_release(&latest_json("v1.2.0"), "1.2.0").unwrap(),
            None
        );
        assert_eq!(
            newer_release(&latest_json("v1.1.0"), "1.2.0").unwrap(),
            None
        );
    }

    #[test]
    fn malformed_response_is_an_error() {
        assert!(newer_release("not json", "1.2.0").is_err());
        assert!(newer_release(r#"{"name":"x"}"#, "1.2.0").is_err());
        assert!(newer_release(&latest_json("Appliction"), "1.2.0").is_err());
    }

    #[test]
    fn download_page_is_built_locally_not_taken_from_response() {
        let r = newer_release(&latest_json("v1.3.0"), "1.2.0")
            .unwrap()
            .unwrap();
        assert_eq!(
            r.page_url(),
            "https://github.com/tntrock/file-crypto/releases/tag/v1.3.0"
        );
    }

    #[test]
    fn current_version_is_valid() {
        assert!(parse_version(CURRENT_VERSION).is_some());
    }

    #[test]
    fn settings_default_to_auto_check() {
        assert_eq!(Settings::parse(""), Settings::default());
        assert!(Settings::default().auto_check_updates);
    }

    #[test]
    fn settings_parse_disabled_auto_check() {
        let s = Settings::parse("# comment\nauto_check_updates = false\nunknown=1\n");
        assert!(!s.auto_check_updates);
    }

    #[test]
    fn settings_roundtrip() {
        let s = Settings {
            auto_check_updates: false,
        };
        assert_eq!(Settings::parse(&s.to_text()), s);
    }
}
