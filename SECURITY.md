# Security Policy

Metsuki EXE Analyzer is intended for defensive executable analysis in controlled environments.

## Supported Versions

- Current release branch: `0.1.x`
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

## False Positives And Endpoint Security

This project is an EXE triage and diagnostics tool. Some endpoint products may still flag it because it launches local executables, gathers runtime evidence, and packages analysis components.

If endpoint protection flags the app:

1. Validate the file hash against `SHA256SUMS.txt`.
2. Reproduce in a clean VM or sandbox.
3. Allowlist by hash, path, or signer in enterprise policy.
4. Submit the sample and hash to the AV vendor if needed.

## Vendor Submission Template

- Product: Metsuki EXE Analyzer
- Version: `<version>`
- SHA256: `<hash>`
- Detection: `<vendor detection name>`
- Detection time (UTC): `<timestamp>`
- Package source: `<release artifact source>`
- Reproduction: launch `exe_tester_web_gui.exe` from the package root
- Expected behavior: local EXE analysis and report generation
