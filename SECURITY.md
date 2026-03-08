# Security and False-Positive Handling

This project is intended for defensive executable analysis in controlled environments.

## Pre-Release Checklist

1. Build package with `release_artifacts.cmd`.
2. Archive `dist/EXE_Analyzer/SHA256SUMS.txt` and `dist/EXE_Analyzer/SECURITY_PRECHECK.txt`.
3. Distribute only binaries that match published SHA256 values.

## If Endpoint Security Blocks Execution

1. Confirm the file hash against `SHA256SUMS.txt`.
2. Run the app in a sandbox/VM first to validate expected behavior.
3. Ask SOC/IT to allowlist by hash/path or signer policy.
4. Submit sample/hash to AV vendor as false positive.

## Vendor Submission Template

- Product: Metsuki EXE Analyzer
- Version: <version>
- SHA256: <hash>
- Detection Name: <vendor detection>
- Detection Time (UTC): <timestamp>
- Acquisition Source: Internal release package
- Reproduction: Launch `exe_tester_gui.exe` from package root
- Expected Behavior: Local executable analysis and report generation only
