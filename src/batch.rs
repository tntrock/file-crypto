//! 批次處理：用同一組密碼／金鑰檔，逐一加解密多個檔案。
//!
//! 每個檔案各自產生獨立的加密檔（格式與單檔相同）。一律使用自動命名、絕不覆蓋；
//! 單一檔案失敗時繼續處理其餘檔案，最後回報每個檔案的結果。

use std::path::{Path, PathBuf};

use crate::crypto::{self, Output, Progress, Secret};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Operation {
    Encrypt,
    Decrypt,
}

/// 批次輸出位置。
#[derive(Clone, Debug, PartialEq)]
pub enum Destination {
    /// 輸出到每個檔案各自所在的資料夾。
    SameAsInput,
    /// 全部輸出到指定資料夾。
    Folder(PathBuf),
}

/// 單一檔案的處理結果。
pub struct FileOutcome {
    pub input: PathBuf,
    /// 成功時為實際寫出的檔案；失敗時為錯誤訊息。
    pub result: Result<PathBuf, String>,
}

/// 整批的處理結果。
pub struct Report {
    pub outcomes: Vec<FileOutcome>,
    /// 使用者是否中途取消（取消後剩下的檔案不會出現在 outcomes 中）。
    pub cancelled: bool,
}

impl Report {
    pub fn succeeded(&self) -> usize {
        self.outcomes.iter().filter(|o| o.result.is_ok()).count()
    }

    pub fn failures(&self) -> impl Iterator<Item = &FileOutcome> {
        self.outcomes.iter().filter(|o| o.result.is_err())
    }

    /// 給使用者看的結果摘要，回傳（文字, 是否需以錯誤顏色顯示）。
    /// `total` 為這批原本要處理的檔案數。
    pub fn summary(&self, op: Operation, total: usize) -> (String, bool) {
        const MAX_LISTED: usize = 10;
        let verb = match op {
            Operation::Encrypt => "加密",
            Operation::Decrypt => "解密",
        };
        let ok = self.succeeded();
        let failures: Vec<&FileOutcome> = self.failures().collect();
        if failures.is_empty() && !self.cancelled {
            return (format!("完成！共 {ok} 個檔案已{verb}。"), false);
        }

        let mut text = if self.cancelled {
            let skipped = total.saturating_sub(self.outcomes.len());
            format!(
                "已取消：成功 {ok} 個，失敗 {} 個，未處理 {skipped} 個。",
                failures.len()
            )
        } else {
            format!("完成：成功 {ok} 個，失敗 {} 個。", failures.len())
        };
        for f in failures.iter().take(MAX_LISTED) {
            let name = f
                .input
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| f.input.display().to_string());
            let reason = f.result.as_ref().err().map(String::as_str).unwrap_or("");
            text.push_str(&format!("\n• {name}：{reason}"));
        }
        if failures.len() > MAX_LISTED {
            text.push_str(&format!("\n…另有 {} 個", failures.len() - MAX_LISTED));
        }
        (text, true)
    }
}

/// 逐一處理 `inputs`。每開始一個檔案前會呼叫 `on_start(索引)`，供 GUI 顯示目前進度。
pub fn run(
    op: Operation,
    inputs: &[PathBuf],
    dest: &Destination,
    secret: &Secret,
    progress: &Progress,
    mut on_start: impl FnMut(usize),
) -> Report {
    let mut outcomes = Vec::with_capacity(inputs.len());
    for (i, input) in inputs.iter().enumerate() {
        if progress.is_cancelled() {
            return Report {
                outcomes,
                cancelled: true,
            };
        }
        on_start(i);
        let output = Output::AutoName(output_dir(input, dest).to_path_buf());
        let result = match op {
            Operation::Encrypt => crypto::encrypt_to(input, &output, secret, false, progress),
            Operation::Decrypt => crypto::decrypt_file(input, &output, secret, false, progress),
        };
        let cancelled = progress.is_cancelled();
        // 因取消而中斷的檔案視為「未處理」，不列入結果；取消前已完成的仍算成功
        if !(cancelled && result.is_err()) {
            outcomes.push(FileOutcome {
                input: input.clone(),
                result: result.map_err(|e| format!("{e:#}")),
            });
        }
        if cancelled {
            return Report {
                outcomes,
                cancelled: true,
            };
        }
    }
    Report {
        outcomes,
        cancelled: false,
    }
}

fn output_dir<'a>(input: &'a Path, dest: &'a Destination) -> &'a Path {
    match dest {
        Destination::Folder(dir) => dir,
        Destination::SameAsInput => match input.parent() {
            Some(d) if !d.as_os_str().is_empty() => d,
            _ => Path::new("."),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::Ordering;

    const PW: &[u8] = b"batch password";

    fn write(dir: &Path, name: &str, data: &[u8]) -> PathBuf {
        let p = dir.join(name);
        fs::write(&p, data).unwrap();
        p
    }

    fn run_pw(op: Operation, inputs: &[PathBuf], dest: &Destination) -> Report {
        run(
            op,
            inputs,
            dest,
            &Secret::Password(PW),
            &Progress::default(),
            |_| {},
        )
    }

    #[test]
    fn encrypts_each_file_next_to_its_input() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let inputs = vec![
            write(a.path(), "one.txt", b"1"),
            write(b.path(), "two.txt", b"2"),
        ];
        let report = run_pw(Operation::Encrypt, &inputs, &Destination::SameAsInput);
        assert_eq!(report.succeeded(), 2);
        assert!(!report.cancelled);
        assert!(a.path().join("one.txt.enc").exists());
        assert!(b.path().join("two.txt.enc").exists());
    }

    #[test]
    fn encrypts_into_chosen_folder() {
        let src = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        let inputs = vec![
            write(src.path(), "one.txt", b"1"),
            write(src.path(), "two.txt", b"2"),
        ];
        let report = run_pw(
            Operation::Encrypt,
            &inputs,
            &Destination::Folder(out.path().into()),
        );
        assert_eq!(report.succeeded(), 2);
        assert!(out.path().join("one.txt.enc").exists());
        assert!(out.path().join("two.txt.enc").exists());
    }

    #[test]
    fn same_name_from_different_folders_does_not_collide() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        let inputs = vec![
            write(a.path(), "報告.docx", b"A"),
            write(b.path(), "報告.docx", b"B"),
        ];
        let report = run_pw(
            Operation::Encrypt,
            &inputs,
            &Destination::Folder(out.path().into()),
        );
        assert_eq!(report.succeeded(), 2);
        assert!(out.path().join("報告.docx.enc").exists());
        assert!(out.path().join("報告.docx (1).enc").exists());
    }

    #[test]
    fn decrypt_batch_restores_original_names() {
        let src = tempfile::tempdir().unwrap();
        let inputs = vec![
            write(src.path(), "one.txt", b"first"),
            write(src.path(), "two.txt", b"second"),
        ];
        let enc = run_pw(Operation::Encrypt, &inputs, &Destination::SameAsInput);
        let encrypted: Vec<PathBuf> = enc
            .outcomes
            .iter()
            .map(|o| o.result.clone().unwrap())
            .collect();

        let out = tempfile::tempdir().unwrap();
        let dec = run_pw(
            Operation::Decrypt,
            &encrypted,
            &Destination::Folder(out.path().into()),
        );
        assert_eq!(dec.succeeded(), 2);
        assert_eq!(fs::read(out.path().join("one.txt")).unwrap(), b"first");
        assert_eq!(fs::read(out.path().join("two.txt")).unwrap(), b"second");
    }

    #[test]
    fn continues_after_a_failure_and_reports_it() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("不存在.txt");
        let inputs = vec![
            write(dir.path(), "ok1.txt", b"1"),
            missing.clone(),
            write(dir.path(), "ok2.txt", b"2"),
        ];
        let report = run_pw(Operation::Encrypt, &inputs, &Destination::SameAsInput);
        assert_eq!(report.outcomes.len(), 3);
        assert_eq!(report.succeeded(), 2);
        let failed: Vec<_> = report.failures().map(|o| o.input.clone()).collect();
        assert_eq!(failed, vec![missing]);
        assert!(dir.path().join("ok2.txt.enc").exists());
    }

    #[test]
    fn cancel_stops_remaining_files() {
        let dir = tempfile::tempdir().unwrap();
        let inputs = vec![
            write(dir.path(), "a.txt", b"a"),
            write(dir.path(), "b.txt", b"b"),
        ];
        let progress = Progress::default();
        let mut started = Vec::new();
        let report = run(
            Operation::Encrypt,
            &inputs,
            &Destination::SameAsInput,
            &Secret::Password(PW),
            &progress,
            |i| {
                started.push(i);
                // 在第一個檔案開始時按下取消
                progress.cancel.store(true, Ordering::Relaxed);
            },
        );
        assert!(report.cancelled);
        assert_eq!(started, vec![0]);
        assert_eq!(report.succeeded(), 0);
        // 被取消而中斷的檔案不算「失敗」
        assert_eq!(report.failures().count(), 0);
        assert!(!dir.path().join("a.txt.enc").exists());
        assert!(!dir.path().join("b.txt.enc").exists());
    }

    #[test]
    fn reports_start_of_each_file_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let inputs = vec![
            write(dir.path(), "a.txt", b"a"),
            write(dir.path(), "b.txt", b"b"),
        ];
        let mut started = Vec::new();
        run(
            Operation::Encrypt,
            &inputs,
            &Destination::SameAsInput,
            &Secret::Password(PW),
            &Progress::default(),
            |i| started.push(i),
        );
        assert_eq!(started, vec![0, 1]);
    }

    fn outcome(name: &str, result: Result<&str, &str>) -> FileOutcome {
        FileOutcome {
            input: PathBuf::from(name),
            result: result.map(PathBuf::from).map_err(str::to_owned),
        }
    }

    #[test]
    fn summary_when_everything_succeeded() {
        let report = Report {
            outcomes: vec![
                outcome("a.txt", Ok("a.txt.enc")),
                outcome("b.txt", Ok("b.txt.enc")),
            ],
            cancelled: false,
        };
        assert_eq!(
            report.summary(Operation::Encrypt, 2),
            ("完成！共 2 個檔案已加密。".to_owned(), false)
        );
    }

    #[test]
    fn summary_lists_failed_files_with_reasons() {
        let report = Report {
            outcomes: vec![
                outcome("a.enc", Ok("a.txt")),
                outcome("x/b.enc", Err("密碼錯誤")),
            ],
            cancelled: false,
        };
        let (text, is_error) = report.summary(Operation::Decrypt, 2);
        assert!(is_error);
        assert!(text.contains("成功 1 個，失敗 1 個"), "{text}");
        assert!(text.contains("b.enc：密碼錯誤"), "{text}");
    }

    #[test]
    fn summary_after_cancel_counts_unprocessed_files() {
        let report = Report {
            outcomes: vec![outcome("a.txt", Ok("a.txt.enc"))],
            cancelled: true,
        };
        let (text, is_error) = report.summary(Operation::Encrypt, 3);
        assert!(is_error);
        assert!(text.contains("已取消"), "{text}");
        assert!(text.contains("成功 1 個"), "{text}");
        assert!(text.contains("未處理 2 個"), "{text}");
    }

    #[test]
    fn summary_truncates_long_failure_lists() {
        let outcomes = (0..15)
            .map(|i| outcome(&format!("f{i}.enc"), Err("錯誤")))
            .collect();
        let report = Report {
            outcomes,
            cancelled: false,
        };
        let (text, _) = report.summary(Operation::Decrypt, 15);
        assert!(text.contains("f9.enc"), "{text}");
        assert!(!text.contains("f10.enc"), "{text}");
        assert!(text.contains("另有 5 個"), "{text}");
    }
}
