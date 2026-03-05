use super::*;

pub(crate) struct DebugDiagnosis {
    pub(crate) verdict_ok: bool,
    pub(crate) expected: String,
    pub(crate) got: String,
    pub(crate) failure_point: String,
    pub(crate) root_cause: String,
}

pub(crate) struct DebugSourceLocation {
    pub(crate) path: String,
    pub(crate) line: usize,
}

pub(crate) fn build_debug_diagnosis(
    lang: UiLanguage,
    expected_exit: &str,
    expected_exception: bool,
    expected_stdout_contains: &str,
    expected_stderr_contains: &str,
    got_exit: Option<i32>,
    got_timed_out: bool,
    got_exception: bool,
    got_stdout: &str,
    got_stderr: &str,
) -> DebugDiagnosis {
    let expected_exit_value = expected_exit.trim().parse::<i32>().ok();
    let mut mismatches = Vec::new();

    if let Some(exp) = expected_exit_value {
        if got_exit != Some(exp) {
            mismatches.push(format!(
                "{} {}, {:?}",
                lpick(
                    lang,
                    "код выхода ожидался",
                    "exit expected",
                    "erwarteter Exit",
                    "код виходу очiкувався"
                ),
                exp,
                got_exit
            ));
        }
    }

    if expected_exception != got_exception {
        mismatches.push(format!(
            "{} {}, {}",
            lpick(
                lang,
                "исключение ожидалось",
                "exception expected",
                "Exception erwartet",
                "виняток очiкувався"
            ),
            expected_exception, got_exception
        ));
    }

    let stdout_expect = expected_stdout_contains.trim();
    if !stdout_expect.is_empty() && !got_stdout.contains(stdout_expect) {
        mismatches.push(format!(
            "{} '{}'",
            lpick(
                lang,
                "stdout не содержит",
                "stdout does not contain",
                "stdout enthaelt nicht",
                "stdout не мiстить"
            ),
            stdout_expect
        ));
    }

    let stderr_expect = expected_stderr_contains.trim();
    if !stderr_expect.is_empty() && !got_stderr.contains(stderr_expect) {
        mismatches.push(format!(
            "{} '{}'",
            lpick(
                lang,
                "stderr не содержит",
                "stderr does not contain",
                "stderr enthaelt nicht",
                "stderr не мiстить"
            ),
            stderr_expect
        ));
    }

    if got_timed_out {
        mismatches.push(
            lpick(
                lang,
                "превышен таймаут выполнения",
                "execution timed out",
                "Zeitlimit ueberschritten",
                "перевищено таймаут виконання",
            )
            .to_string(),
        );
    }

    if mismatches.is_empty() && got_exit.is_none() {
        mismatches.push(
            lpick(
                lang,
                "процесс завершился без кода выхода",
                "process ended without exit code",
                "Prozess endete ohne Exit-Code",
                "процес завершився без коду виходу",
            )
            .to_string(),
        );
    }

    let verdict_ok = mismatches.is_empty();
    let expected = format!(
        "{}={}, {}={}, stdout~'{}', stderr~'{}'",
        lpick(lang, "код_выхода", "exit", "exit", "код_виходу"),
        if expected_exit.trim().is_empty() {
            "<any>".to_string()
        } else {
            expected_exit.trim().to_string()
        },
        lpick(lang, "исключение", "exception", "Exception", "виняток"),
        expected_exception,
        if stdout_expect.is_empty() {
            "<not set>"
        } else {
            stdout_expect
        },
        if stderr_expect.is_empty() {
            "<not set>"
        } else {
            stderr_expect
        }
    );

    let got = format!(
        "{}={:?}, {}={}, stdout={} {}, stderr={} {}",
        lpick(lang, "код_выхода", "exit", "exit", "код_виходу"),
        got_exit,
        lpick(lang, "исключение", "exception", "Exception", "виняток"),
        got_exception,
        got_stdout.chars().count(),
        lpick(lang, "символов", "chars", "Zeichen", "символiв"),
        got_stderr.chars().count(),
        lpick(lang, "символов", "chars", "Zeichen", "символiв")
    );

    let failure_point = if verdict_ok {
        lpick(
            lang,
            "не обнаружено (ожидания совпали)",
            "not detected (expectations matched)",
            "nicht erkannt (Erwartung erfuellt)",
            "не виявлено (очiкування спiвпали)",
        )
        .to_string()
    } else {
        detect_failure_point(lang, got_stderr, got_stdout)
    };

    let root_cause = if verdict_ok {
        lpick(
            lang,
            "расхождений нет",
            "no mismatch",
            "keine Abweichung",
            "розбiжностей немає",
        )
        .to_string()
    } else {
        mismatches.join("; ")
    };

    DebugDiagnosis {
        verdict_ok,
        expected,
        got,
        failure_point,
        root_cause,
    }
}

pub(crate) fn truncate_debug_text(text: &str, max_chars: usize) -> String {
    let chars = text.chars().count();
    if chars <= max_chars {
        return text.replace('\n', "\\n");
    }

    let mut truncated = text.chars().take(max_chars).collect::<String>();
    truncated = truncated.replace('\n', "\\n");
    format!("{}...", truncated)
}

pub(crate) fn infer_debug_exception(exit_code: Option<i32>, timed_out: bool, stderr: &str) -> bool {
    if timed_out {
        return true;
    }

    if let Some(code) = exit_code {
        if code != 0 {
            return true;
        }
    }

    let lower = stderr.to_ascii_lowercase();
    ["exception", "traceback", "panic", "fatal", "unhandled", "error:"]
        .iter()
        .any(|marker| lower.contains(marker))
}

pub(crate) fn analyze_crash_signature(exit_code: Option<i32>, stderr: &str, stdout: &str) -> String {
    let err = stderr.to_ascii_lowercase();
    let out = stdout.to_ascii_lowercase();

    if err.contains("traceback") {
        return "python traceback detected".to_string();
    }
    if err.contains("panicked at") || out.contains("panicked at") {
        return "rust panic signature detected".to_string();
    }
    if err.contains("segmentation fault") || err.contains("access violation") {
        return "segfault/access violation signature detected".to_string();
    }
    if let Some(code) = exit_code {
        let raw = code as u32;
        if matches!(raw, 0xC0000005 | 0xC0000409 | 0xC00000FD | 0x80000003) {
            return format!("ntstatus crash code {:#X}", raw);
        }
    }

    "no explicit crash signature".to_string()
}

pub(crate) fn unified_diff(left: &str, right: &str, left_name: &str, right_name: &str) -> String {
    let left_lines: Vec<&str> = left.lines().collect();
    let right_lines: Vec<&str> = right.lines().collect();

    let mut out = String::new();
    out.push_str(&format!("--- {}\n", left_name));
    out.push_str(&format!("+++ {}\n", right_name));

    let max_len = left_lines.len().max(right_lines.len());
    for idx in 0..max_len {
        let l = left_lines.get(idx).copied();
        let r = right_lines.get(idx).copied();
        match (l, r) {
            (Some(a), Some(b)) if a == b => {
                out.push_str(&format!(" {}\n", a));
            }
            (Some(a), Some(b)) => {
                out.push_str(&format!("-{}\n", a));
                out.push_str(&format!("+{}\n", b));
            }
            (Some(a), None) => {
                out.push_str(&format!("-{}\n", a));
            }
            (None, Some(b)) => {
                out.push_str(&format!("+{}\n", b));
            }
            (None, None) => {}
        }
    }

    out
}

fn detect_failure_point(lang: UiLanguage, stderr: &str, stdout: &str) -> String {
    for line in stderr.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("File \"") {
            return trimmed.to_string();
        }
        if trimmed.contains("panicked at")
            || trimmed.starts_with("panic:")
            || trimmed.starts_with("Exception in thread")
            || trimmed.starts_with("Traceback")
            || trimmed.starts_with("at ")
        {
            return trimmed.to_string();
        }
    }

    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Traceback") || trimmed.contains("Exception") {
            return trimmed.to_string();
        }
    }

    if let Some(line) = stderr.lines().find(|line| !line.trim().is_empty()) {
        return line.trim().to_string();
    }

    lpick(
        lang,
        "не удалось локализовать место ошибки по выводу",
        "unable to localize failure point from output",
        "Fehlerstelle konnte nicht aus der Ausgabe lokalisiert werden",
        "не вдалося локалiзувати мiсце помилки з виводу",
    )
    .to_string()
}

fn lpick<'a>(lang: UiLanguage, ru: &'a str, en: &'a str, de: &'a str, uk: &'a str) -> &'a str {
    match lang {
        UiLanguage::Ru => ru,
        UiLanguage::En => en,
        UiLanguage::De => de,
        UiLanguage::Uk => uk,
    }
}

pub(crate) fn parse_debug_source_location(line: &str) -> Option<DebugSourceLocation> {
    let trimmed = line.trim();

    if let Some(loc) = parse_pdb_prompt_location(trimmed) {
        return Some(loc);
    }

    parse_traceback_location(trimmed)
}

fn parse_pdb_prompt_location(line: &str) -> Option<DebugSourceLocation> {
    if !line.starts_with('>') {
        return None;
    }

    let open = line.find('(')?;
    let close = line[open + 1..].find(')')? + open + 1;
    if close <= open + 1 {
        return None;
    }

    let path = line[1..open].trim();
    if path.is_empty() {
        return None;
    }

    let line_num = line[open + 1..close].trim().parse::<usize>().ok()?;
    if line_num == 0 {
        return None;
    }

    Some(DebugSourceLocation {
        path: path.to_string(),
        line: line_num,
    })
}

fn parse_traceback_location(line: &str) -> Option<DebugSourceLocation> {
    if !line.starts_with("File \"") {
        return None;
    }

    let start = 6;
    let end_rel = line[start..].find('"')?;
    let end = start + end_rel;
    let path = line[start..end].trim();
    if path.is_empty() {
        return None;
    }

    let marker = ", line ";
    let marker_pos = line[end..].find(marker)? + end + marker.len();
    let line_part = &line[marker_pos..];
    let digits: String = line_part.chars().take_while(|c| c.is_ascii_digit()).collect();
    let line_num = digits.parse::<usize>().ok()?;
    if line_num == 0 {
        return None;
    }

    Some(DebugSourceLocation {
        path: path.to_string(),
        line: line_num,
    })
}
