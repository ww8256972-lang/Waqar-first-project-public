# Agent Security & Tooling Rules

This repository is security-sensitive. Follow these rules whenever the user requests security work.

## Environment Status (verified 2026-11-26, Termux Android aarch64, Python 3.14.10)

| Tool | Status | Location / Command | Notes |
|------|--------|--------------------|-------|
| Semgrep | **NOT INSTALLED** (install blocked) | Preferred: `semgrep scan --config=auto .`; Fallback: `python3 -m semgrep scan --config=auto .` | `pip install semgrep` failed: `rpds-py` build dependency needs maturin/rust; rustup does not support target `aarch64-unknown-linux-android`. Termux `pkg install rust` was attempted during setup; after rust is available, retry with `CARGO_BUILD_TARGET=aarch64-linux-android pip install semgrep` or install a compatible prebuilt wheel if available. Do not claim a Semgrep scan was run unless the command actually executed. |
| CAI (aliasrobotics/cai) | **CLONED, NOT INSTALLED** | Repo: `/data/user/0/ai.antigem/files/home/tools/cai`; Intended CLI: `cai` (`cai.cli:main`) | `pip install -e .` failed with same maturin/rust Android target issue while building `cryptography`. Requires Python >=3.10 (OK). After rust/toolchain is fixed, retry `PIP_DISABLE_PIP_VERSION_CHECK=1 pip install -e /data/user/0/ai.antigem/files/home/tools/cai`. If install is impossible on Termux, document blocker and use available local security tooling/manual analysis; do not fake CAI output. |
| MobSF | **CLONED, NOT INSTALLED** | Repo: `/data/user/0/ai.antigem/files/home/tools/Mobile-Security-Framework-MobSF`; Intended: `python3 -m mobsf`, `mobsf` script, or `bash run.sh 127.0.0.1:8000` | Setup blocked on this environment: `pyproject.toml` requires Python `^3.12` and `setup.sh` enforces Python 3.12-3.13; current env is Python 3.14.10. Dependencies also include heavy/native packages (frida, mitmproxy, lief, psycopg2-binary, etc.) that may be unsupported on Termux Android. Do not claim MobSF analysis ran unless it actually ran. For APK static analysis fallback, use available tools (`apktool`, `jadx`, `aapt2`, `strings`, `rg`, semgrep when available) and report the limitation explicitly. |

## 1) Security Audit / Leak Check / Bug Fix (Semgrep Required)

**Trigger:** Whenever the user asks for a **security audit**, **leak/secret check**, **vulnerability scan**, **SAST review**, or **bug fix** with security implications.

**Required workflow:**
1. **Run Semgrep immediately** from the project root before proposing fixes:
   ```bash
   semgrep scan --config=auto .
   ```
   - If Semgrep is unavailable, report the exact blocker and verification evidence, then use the closest available SAST/manual checks; do not fabricate scan results.
   - If a narrower scope is requested, scan that scope, but prefer a full codebase scan for audits.
   - Capture and report real findings (rule id, file, line, severity, message).
2. **Triage findings** - confirm real vulnerabilities vs. false positives. Do not invent findings.
3. **Patch real vulnerabilities** with secure, production-ready logic.
   - No dummy placeholders, no `TODO: fix later`, no fake/mock security controls.
   - Preserve behavior unless behavior is insecure.
   - Add/adjust input validation, authz/authn checks, secret handling, output encoding, parameterized queries, safe crypto, etc., as appropriate.
4. **Re-run Semgrep** (and relevant tests/lints when available) after patching. Report residual findings honestly.
5. **Deliver evidence**: commands run, key findings, files changed, and verification results.

**Semgrep install/location (this environment):**
- Preferred command: `semgrep`
- Fallback: `python3 -m semgrep`
- Termux Android blocker: `pip install semgrep` currently fails building `rpds-py` (maturin/rustup target `aarch64-unknown-linux-android` unsupported). Revisit after installing Termux `rust` and confirming cargo/rustc can build Python extensions.

## 2) Offensive Security / Exploit Simulation / APK Analysis (CAI + MobSF Required)

**Trigger:** Whenever the user asks for **offensive security testing**, **penetration testing**, **exploit simulation**, **red-team validation**, **APK analysis**, or **mobile app security assessment**.

**Required workflow:**
1. **Use the appropriate tool immediately:**
   - **CAI (Cybersecurity AI)** for offensive security testing/exploit simulation/task-driven security analysis.
   - **MobSF (Mobile-Security-Framework-MobSF)** for APK/IPA/mobile app static/dynamic analysis where applicable.
2. **Run real scans/analysis** - do not simulate results. If a tool cannot run due to environment limits, report the exact blocker and use the closest available CLI/MCP workflow.
3. **Identify real leaks/vulnerabilities** from tool output and manual verification.
4. **Patch with working production logic** - no dummy placeholders, no stubbed fixes, no commented-out vulnerable code as the "solution".
5. **Re-test/verify** after fixes and report evidence.

**Tool locations (this environment):**
- CAI repo: `/data/user/0/ai.antigem/files/home/tools/cai`
  - Intended CLI: `cai` (entrypoint `cai.cli:main`)
  - Setup command to retry: `PIP_DISABLE_PIP_VERSION_CHECK=1 pip install -e /data/user/0/ai.antigem/files/home/tools/cai`
  - Current blocker: dependency build fails on Termux Android (maturin/rust target unsupported by rustup for `aarch64-unknown-linux-android` during `cryptography` build deps).
- MobSF repo: `/data/user/0/ai.antigem/files/home/tools/Mobile-Security-Framework-MobSF`
  - Intended CLI: `mobsf` / `python3 -m mobsf` / `bash run.sh 127.0.0.1:8000`
  - Current blocker: requires Python 3.12-3.13 per project constraints; environment runs Python 3.14.10. Native deps may also be incompatible on Termux Android.

## 3) General Security Rules

- Never hardcode secrets, tokens, private keys, or credentials.
- Treat user input, file uploads, webhooks, IPC, and external API data as untrusted.
- Prefer least privilege, explicit authz checks, and secure defaults.
- Avoid insecure crypto, weak randomness, SQL/command injection sinks, path traversal, SSRF, XSS, and unsafe deserialization.
- When fixing, explain the root cause and the security property restored.
- Never report a tool as installed/configured/running unless verified by command output.
