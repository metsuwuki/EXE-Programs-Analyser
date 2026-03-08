use super::*;
use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum PreflightError {
    #[error("file not found")]
    FileNotFound,
    #[error("metadata failed")]
    Metadata,
    #[error("not regular file")]
    NotAFile,
    #[error("empty file")]
    EmptyFile,
    #[error("read failed")]
    ReadFailed,
}

pub(crate) fn preflight_and_load(
    path: &Path,
    target_kind: TargetKind,
    findings: &mut Vec<Finding>,
) -> Result<Vec<u8>, PreflightError> {
    if !path.exists() {
        findings.push(finding(
            Severity::Fail,
            "FILE_NOT_FOUND",
            "preflight",
            50,
            format!("Target file not found: {}", path.display()),
        ));
        return Err(PreflightError::FileNotFound);
    }

    match target_kind {
        TargetKind::Executable => {
            let ext_is_exe = path
                .extension()
                .and_then(|x| x.to_str())
                .map(|x| x.eq_ignore_ascii_case("exe"))
                == Some(true);
            if !ext_is_exe {
                findings.push(finding(
                    Severity::Warn,
                    "EXTENSION_NOT_EXE",
                    "preflight",
                    8,
                    "File extension is not .exe (still trying PE parse).",
                ));
            }
        }
        TargetKind::Source(lang) => {
            findings.push(finding(
                Severity::Pass,
                "SOURCE_TARGET_DETECTED",
                "preflight",
                0,
                format!("Source target detected: {}", lang.as_str()),
            ));
        }
        TargetKind::Unknown => {
            findings.push(finding(
                Severity::Warn,
                "UNKNOWN_TARGET_EXTENSION",
                "preflight",
                5,
                "Target extension is not recognized; running generic source checks.",
            ));
        }
    }

    let meta = match fs::metadata(path) {
        Ok(m) => m,
        Err(e) => {
            findings.push(finding(
                Severity::Fail,
                "METADATA_ERROR",
                "preflight",
                40,
                format!("Cannot read metadata: {}", e),
            ));
            return Err(PreflightError::Metadata);
        }
    };

    if !meta.is_file() {
        findings.push(finding(
            Severity::Fail,
            "NOT_A_FILE",
            "preflight",
            40,
            "Target path is not a regular file.",
        ));
        return Err(PreflightError::NotAFile);
    }

    if meta.len() == 0 {
        findings.push(finding(
            Severity::Fail,
            "EMPTY_FILE",
            "preflight",
            45,
            "File is empty.",
        ));
        return Err(PreflightError::EmptyFile);
    }

    if target_kind == TargetKind::Executable && meta.len() < 2048 {
        findings.push(finding(
            Severity::Warn,
            "VERY_SMALL_FILE",
            "preflight",
            6,
            format!("Suspiciously small executable: {} bytes", meta.len()),
        ));
    }

    if target_kind != TargetKind::Executable && meta.len() < 16 {
        findings.push(finding(
            Severity::Warn,
            "VERY_SMALL_SOURCE",
            "preflight",
            3,
            format!("Very small source/unknown file: {} bytes", meta.len()),
        ));
    }

    let bytes = match fs::read(path) {
        Ok(data) => data,
        Err(e) => {
            findings.push(finding(
                Severity::Fail,
                "READ_FAILED",
                "preflight",
                40,
                format!("Cannot read file bytes: {}", e),
            ));
            return Err(PreflightError::ReadFailed);
        }
    };

    Ok(bytes)
}
