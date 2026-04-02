# Report Format

Current public report metadata:

- `schema_version`: `2.3`
- `report_version`: `2026-04`
- `checks_catalog_version`: `2026-04`

Top-level JSON structure:

```json
{
  "schema_version": "2.3",
  "report_version": "2026-04",
  "checks_catalog_version": "2026-04",
  "known_check_ids": ["..."],
  "target": "path/to/target.exe",
  "generated_unix": 0,
  "analysis_mode": "MIN",
  "mode": "BALANCED",
  "score": 0,
  "final_status": "PASS",
  "summary": {
    "severity": {
      "pass": 0,
      "warn": 0,
      "fail": 0,
      "total": 0
    },
    "runtime": {
      "runs": 0,
      "timeout_count": 0,
      "non_zero_exit_count": 0,
      "unique_exit_codes": [],
      "total_duration_ms": 0,
      "min_duration_ms": 0,
      "max_duration_ms": 0,
      "p50_duration_ms": 0,
      "p95_duration_ms": 0,
      "flaky": false,
      "flakiness_percent": 0,
      "stability_percent": 0
    }
  },
  "artifacts": {
    "target_kind": "Executable",
    "file_size_bytes": 0,
    "static_analysis": {}
  },
  "findings": [],
  "runtime": [],
  "telemetry": {}
}
```

Finding row shape:

```json
{
  "severity": "WARN",
  "code": "SUSPICIOUS_IMPORTS",
  "category": "pe",
  "points": 12,
  "message": "Executable imports several APIs often seen in suspicious launch chains."
}
```

Runtime row shape:

```json
{
  "scenario": "argv-unicode",
  "exit_code": 0,
  "timed_out": false,
  "duration_ms": 182,
  "stdout_len": 12,
  "stderr_len": 0,
  "failure_reason": "clean exit code 0",
  "trace": {
    "scenario_kind": "runtime",
    "sandbox_profile": "limited",
    "env_policy": "redirected",
    "working_dir": "logs/run_01",
    "started_unix": 0,
    "finished_unix": 0,
    "events": [],
    "stdout_preview": "",
    "stderr_preview": ""
  }
}
```

Compatibility rules:

- consumers should read `report_version` first
- if unavailable, fall back to `schema_version`
- consumers should tolerate missing optional fields under `artifacts.static_analysis`
- `known_check_ids` should be treated as the bundled catalog snapshot for that report
