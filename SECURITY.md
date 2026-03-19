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
