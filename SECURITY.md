<<<<<<< HEAD
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
=======
# Security Policy

Metsuki EXE Analyzer is intended for defensive executable analysis in controlled environments.

## Supported versions

- Current release branch: `0.1.x`
- Older versions: best effort only

## Reporting a security issue

Please report vulnerabilities privately through your repository security channel (for example: Security Advisories).

Include:

- affected version
- reproduction steps
- expected and actual behavior
- impact assessment
- logs or report snippets (sanitized)

## Release integrity checklist

1. Build artifacts with `release_artifacts.cmd`.
2. Verify generated `SHA256SUMS.txt` and `SECURITY_PRECHECK.txt`.
3. Publish hashes with the release.
4. Distribute only binaries matching published hashes.

## Endpoint security and false positives

If endpoint protection flags the app:

1. Validate hash against `SHA256SUMS.txt`.
2. Reproduce in a clean VM/sandbox.
3. Allowlist by hash/path/signer in enterprise policy.
4. Submit the sample and hash to the AV vendor.

## Vendor submission template

- Product: Metsuki EXE Analyzer
- Version: `<version>`
- SHA256: `<hash>`
- Detection: `<vendor detection name>`
- Detection time (UTC): `<timestamp>`
- Package source: `<release artifact source>`
- Reproduction: launch `exe_tester_web_gui.exe` from package root
- Expected behavior: local executable analysis and report generation
>>>>>>> 4eb762c97ad4a0321ba84566b2eef38064581585
