# Security Policy

EXE Analyzer is intended for defensive executable analysis in controlled environments.

## Supported Versions

- Current release branch: `0.4.x`
- Older versions: best effort only

## Reporting A Security Issue

Report vulnerabilities privately through the repository security advisory channel.

Include:

- affected version
- reproduction steps
- expected behavior and actual behavior
- impact assessment
- sanitized logs or report snippets

## Release Integrity Checklist

1. Build release artifacts with `release_artifacts.cmd`.
2. Verify `dist/EXE_Analyzer/SHA256SUMS.txt`.
3. Review `dist/EXE_Analyzer/SECURITY_PRECHECK.txt`.
4. Publish hashes together with the release assets.
5. Distribute only binaries that match the published hashes.

## Runtime Isolation Notes

- `limited` and `isolated` are local runtime harness profiles, not full VM or container sandboxes.
- Runtime runs redirect `TEMP`, `HOME`, `APPDATA`, and related paths into the analysis workspace.
- `isolated` adds Windows Job Object limits such as kill-on-close, process cap, and memory caps.
- Highly sensitive samples should still be analyzed in a dedicated VM or external lab.

## False Positives And Endpoint Security

This project launches local executables, captures runtime evidence, exports reports, and bundles repro material. Some endpoint products may still flag it because of that behavior.

If endpoint protection flags the app:

1. Validate the file hash against `SHA256SUMS.txt`.
2. Reproduce in a clean VM or dedicated test environment.
3. Allowlist by hash, path, or signer in enterprise policy.
4. Submit the sample and hash to the AV vendor if needed.

## Vendor Submission Template

- Product: EXE Analyzer
- Version: `0.5.0`
- SHA256: `<hash>`
- Detection: `<vendor detection name>`
- Detection time (UTC): `<timestamp>`
- Package source: `<release artifact source>`
- Reproduction: launch `exe_analyzer.exe` from the package root
- Expected behavior: local EXE analysis, runtime diagnostics, report generation, and report comparison
