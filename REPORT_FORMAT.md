# Report Format

Current report metadata:

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
    "static_analysis": {
      "pe": {},
      "strings": {}
    }
  },
  "findings": [],
  "runtime": [],
  "telemetry": {}
}
```

Top-level field notes:

- `analysis_mode`: high-level execution mode such as `MIN` or `PENTEST`
- `mode`: verdict mode such as `BALANCED` or `STRICT`
- `score`: numeric score used by the UI KPI and exports
- `final_status`: final severity enum value `PASS`, `WARN`, or `FAIL`
- `known_check_ids`: bundled check catalog snapshot for downstream tooling

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
    "events": [
      {
        "at_ms": 0,
        "stage": "spawn",
        "detail": "process launched"
      }
    ],
    "stdout_preview": "",
    "stderr_preview": ""
  }
}
```

Artifact notes:

- `artifacts.static_analysis.pe` is present for executable targets
- `artifacts.static_analysis.strings` contains suspicious string hits
- `artifacts.static_analysis.source` may appear for source-like inputs in internal or legacy flows
- `telemetry` contains security-lab module state and runtime coverage details

Stable `CHECK_ID` catalog is sourced from `src/report_schema.rs`.

Recent catalog entries include:

- `SOURCE_UNSANITIZED_INPUT`
- `SOURCE_HARDCODED_SECRET`
- `SANDBOX_ENFORCEMENT_FAILED`
- `LIBAFL_FEATURE_DISABLED`

Expected compatibility rule:

- consumers should read `report_version` first
- if unavailable, fall back to `schema_version`
- UI and exporters should rely on `known_check_ids` for the bundled catalog snapshot
- consumers should tolerate missing optional sub-objects under `artifacts.static_analysis`
