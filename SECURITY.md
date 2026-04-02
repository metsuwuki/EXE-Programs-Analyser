# Security Policy

Metsuki EXE Analyzer is intended for defensive executable analysis in controlled environments.

## Supported Versions

- Current public release line: `0.4.x`
- Older versions: best effort only

## Reporting A Security Issue

Report vulnerabilities privately through the repository security advisory channel or a private maintainer contact.

Include:

- affected version
- reproduction steps
- expected behavior and actual behavior
- impact assessment
- sanitized logs or report snippets

## Release Integrity Checklist

1. Publish binaries only from a trusted release build.
2. Publish SHA256 hashes with each release.
3. Keep a copy of the release notes and changelog for each public version.
4. Distribute only binaries that match the published hashes.
5. If a binary is replaced, publish a new version and new hashes instead of silently overwriting files.

## Runtime Isolation Notes

- `limited` and `isolated` are local runtime harness profiles, not full VM or container sandboxes.
- Runtime runs redirect `TEMP`, `HOME`, `APPDATA`, and related paths into the analysis workspace.
- `isolated` adds stronger local process restrictions compared to `limited`.
- Highly sensitive samples should still be analyzed in a dedicated VM or external lab.

## False Positives And Endpoint Security

This project launches local executables, captures runtime evidence, exports reports, and can package repro material. Some endpoint products may still flag it because of that behavior.

If endpoint protection flags the app:

1. Validate the file hash against the published SHA256 value.
2. Reproduce in a clean VM or dedicated test environment.
3. Allowlist by hash, path, or signer in enterprise policy.
4. Submit the sample and hash to the AV vendor if needed.

## Vendor Submission Template

- Product: Metsuki EXE Analyzer
- Version: `0.4.0`
- SHA256: `<hash>`
- Detection: `<vendor detection name>`
- Detection time (UTC): `<timestamp>`
- Package source: `<release artifact source>`
- Reproduction: launch `exe_tester_web_gui.exe` from the package root
- Expected behavior: local EXE analysis, runtime diagnostics, report generation, and optional debugger preparation
