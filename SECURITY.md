# Security Policy

<p align="center">
	Metsuki EXE Analyzer is intended for defensive executable analysis in controlled environments.
</p>

<p align="center">
	<img alt="Policy" src="https://img.shields.io/badge/Policy-Security%20First-1F8B4C">
	<img alt="Reporting" src="https://img.shields.io/badge/Reporting-Private%20Channel-1E3A8A">
	<img alt="Integrity" src="https://img.shields.io/badge/Release-Hash%20Verified-374151">
</p>

---

## ✅ Supported Versions

- Current release branch: `0.1.x`
- Older versions: best effort only

---

## 📬 Reporting A Security Issue

Report vulnerabilities privately via your repository security channel (for example, Security Advisories).

Include in the report:

- affected version
- reproduction steps
- expected behavior and actual behavior
- impact assessment
- logs or report snippets (sanitized)

---

## 🔐 Release Integrity Checklist

1. Build release artifacts with `release_artifacts.cmd`.
2. Verify generated `SHA256SUMS.txt` and `SECURITY_PRECHECK.txt`.
3. Publish hashes together with release assets.
4. Distribute only binaries that match published hashes.

---

## 🛡 Endpoint Security And False Positives

If endpoint protection flags the app:

1. Validate file hash against `SHA256SUMS.txt`.
2. Reproduce in a clean VM or sandbox.
3. Allowlist by hash/path/signer in enterprise policy.
4. Submit sample and hash to the AV vendor.

---

## 🧾 Vendor Submission Template

- Product: Metsuki EXE Analyzer
- Version: `<version>`
- SHA256: `<hash>`
- Detection: `<vendor detection name>`
- Detection time (UTC): `<timestamp>`
- Package source: `<release artifact source>`
- Reproduction: launch `exe_tester_web_gui.exe` from package root
- Expected behavior: local executable analysis and report generation
