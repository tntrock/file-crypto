//! 專案資訊（版本、作者、授權、官方網址）。
//! 全部取自 Cargo.toml，程式內只有這一個來源，避免各處網址不一致。

/// 目前程式版本。
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// 作者（Cargo.toml 的 authors）。
pub const AUTHORS: &str = env!("CARGO_PKG_AUTHORS");
/// 作者網站（Cargo.toml 沒有對應欄位，故在此定義）。
pub const AUTHOR_URL: &str = "https://allenyen.net";
/// 授權（Cargo.toml 的 license）。
pub const LICENSE: &str = env!("CARGO_PKG_LICENSE");
/// 官方原始碼網址（Cargo.toml 的 repository）。
pub const REPO_URL: &str = env!("CARGO_PKG_REPOSITORY");

/// 官方下載頁。
pub fn releases_url() -> String {
    format!("{REPO_URL}/releases")
}

/// 指定版本的 Release 頁面。
pub fn release_page_url(version: &str) -> String {
    format!("{REPO_URL}/releases/tag/v{version}")
}

/// 問題回報頁。
pub fn issues_url() -> String {
    format!("{REPO_URL}/issues")
}

/// GitHub API：最新正式版。
pub fn latest_release_api_url() -> String {
    let repo = REPO_URL.trim_start_matches("https://github.com/");
    format!("https://api.github.com/repos/{repo}/releases/latest")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn official_repository_is_on_github() {
        assert_eq!(REPO_URL, "https://github.com/tntrock/file-crypto");
    }

    #[test]
    fn download_and_issue_pages_are_under_the_official_repository() {
        assert_eq!(
            releases_url(),
            "https://github.com/tntrock/file-crypto/releases"
        );
        assert_eq!(
            issues_url(),
            "https://github.com/tntrock/file-crypto/issues"
        );
        assert_eq!(
            release_page_url("1.3.0"),
            "https://github.com/tntrock/file-crypto/releases/tag/v1.3.0"
        );
    }

    #[test]
    fn api_url_points_to_the_same_repository() {
        assert_eq!(
            latest_release_api_url(),
            "https://api.github.com/repos/tntrock/file-crypto/releases/latest"
        );
    }

    #[test]
    fn author_and_license_are_filled_in() {
        assert_eq!(AUTHORS, "Allen Yen");
        assert_eq!(LICENSE, "MIT");
    }

    #[test]
    fn author_website() {
        assert_eq!(AUTHOR_URL, "https://allenyen.net");
    }
}
