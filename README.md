<p align="center">
  <img src="https://github.com/user-attachments/assets/e4809ee3-a647-4120-8309-b7d928346a23" alt="Nutcracker logo" width="360">
</p>

<p align="center">
  <a href="https://github.com/drneox/nutcracker/stargazers">
    <img src="https://img.shields.io/github/stars/drneox/nutcracker?style=for-the-badge&logo=github&logoColor=F3F4F6&labelColor=0B0F14&color=2F3742" alt="GitHub stars">
  </a>
  <a href="https://github.com/drneox/nutcracker/network/members">
    <img src="https://img.shields.io/github/forks/drneox/nutcracker?style=for-the-badge&logo=github&logoColor=F3F4F6&labelColor=0B0F14&color=3C4654" alt="GitHub forks">
  </a>
  <a href="https://github.com/drneox/nutcracker/issues">
    <img src="https://img.shields.io/github/issues/drneox/nutcracker?style=for-the-badge&logo=github&logoColor=F3F4F6&labelColor=0B0F14&color=C1121F" alt="GitHub issues">
  </a>
  <a href="https://github.com/drneox/nutcracker/commits/main">
    <img src="https://img.shields.io/github/last-commit/drneox/nutcracker?style=for-the-badge&logo=github&logoColor=F3F4F6&labelColor=0B0F14&color=5A6472" alt="GitHub last commit">
  </a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=F3F4F6&labelColor=0B0F14" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/platform-Android-3FA34D?style=for-the-badge&logo=android&logoColor=F3F4F6&labelColor=0B0F14" alt="Android platform">
  <img src="https://img.shields.io/badge/dynamic%20analysis-Frida-B4232C?style=for-the-badge&labelColor=0B0F14" alt="Frida dynamic analysis">
</p>

# nutcracker v0.1 — Mobile Security & Offensive Threat Intelligence

Android application analysis tool aimed at security researchers.
Downloads apps directly from Google Play, detects and attempts to bypass
anti-root/RASP protections (DexGuard, Arxan, Appdome, Promon, RootBeer), decompiles them, extracts hardcoded secrets and endpoints,
analyzes insecure manifest configurations, and launches OSINT reconnaissance on the package ID,
domains, endpoints and extracted secrets (subdomains via crt.sh, public leaks on GitHub/Postman/FOFA/Wayback and optional web searches).
All findings are consolidated into a technical PDF report ready for reporting.

---

## Key Features

- Downloads APKs from Google Play (via apkeep + AAS token), APKPure or direct URL
- App Bundle (AAB) support: split detection and `adb install-multiple`
- Static protection detection: DexGuard, Arxan, Appdome, RootBeer, Promon Shield, etc.
- Smart analytics SDK filtering (AppMetrica, AppsFlyer, etc.) to avoid false positives
- Dynamic deobfuscation via `frida_server`, `gadget` or `fart`, depending on the configured pipeline
- Optional Frida Gadget instrumentation as an embedded fallback path
- Vulnerability scanner: semgrep (OWASP MASTG) + 38 internal regex rules
- Configurable leak/secret search: internal HC rules + apkleaks + gitleaks on decompiled code and original APK
- Optional OSINT module: subdomains via crt.sh, public leaks on GitHub/Postman/FOFA/Wayback, false-positive filter and optional web searches via DuckDuckGo
- AndroidManifest.xml analysis: dangerous permissions, exported components, `network security config` and insecure configurations
- Complete PDF report: cover page, executive summary, anti-root, RASP bypass, insecure configurations, leaks, OSINT and vulnerabilities
- Batch mode to scan multiple apps in sequence
- Modules controllable via feature flags in `config.yaml`

---

## System Requirements

### macOS (install with Homebrew)

```bash
brew install apkeep       # download APKs from Google Play / APKPure
brew install jadx         # decompile APKs to Java + XML
brew install apktool      # unpack/repack APKs (required for gadget_inject)
brew install semgrep      # static analysis (OWASP MASTG rules)
brew install android-platform-tools  # adb
```

### Linux (Ubuntu/Debian)

```bash
# Base tools
sudo apt update
sudo apt install -y openjdk-21-jre-headless jadx apktool adb curl

# semgrep (via pipx recommended)
python3 -m pip install --user pipx
python3 -m pipx ensurepath
pipx install semgrep

# apkeep (official binary)
APKEEP_VERSION="0.18.0"
curl -L -o /tmp/apkeep.tgz \
  "https://github.com/EFForg/apkeep/releases/download/v${APKEEP_VERSION}/apkeep-x86_64-unknown-linux-musl.tar.gz"
tar -xzf /tmp/apkeep.tgz -C /tmp
sudo install /tmp/apkeep /usr/local/bin/apkeep
apkeep --version
```

> For other distros (Fedora/Arch), install the equivalent packages for `openjdk`, `jadx`, `apktool` and `adb`,
> and keep `apkeep` from its official release.

### Java (required by jadx and apktool)

```bash
# Java 11+ required. Example with OpenJDK:
brew install openjdk@21
```

Tested version: `openjdk 23.0.1`

### Android SDK (required for emulator and APK signing)

Install from [Android Studio](https://developer.android.com/studio) or with `sdkmanager`.
The tool automatically detects the SDK at `~/Library/Android/sdk` (macOS).

Required components:

```bash
# From Android Studio → SDK Manager, or with sdkmanager:
sdkmanager "platform-tools"                     # adb
sdkmanager "emulator"                           # AVD emulator
sdkmanager "build-tools;34.0.0"                 # apksigner, zipalign
sdkmanager "system-images;android-34;google_apis;arm64-v8a"  # AVD image
avdmanager create avd -n nutcracker_avd -k "system-images;android-34;google_apis;arm64-v8a"
```

> `apksigner` and `zipalign` are required for APK Bundle patching and for
> Frida Gadget injection. They can be found at `~/Library/Android/sdk/build-tools/<ver>/`.

---

## Python Installation

```bash
git clone <repo>
cd nutcracker
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Python Dependencies (requirements.txt)

| Package | Purpose |
|---|---|
| `androguard` | Static APK analysis (DEX, manifest, strings) |
| `click` | CLI |
| `rich` | Terminal output with colors and spinners |
| `pyyaml` | Read `config.yaml` |
| `fpdf2` | PDF report generation |
| `loguru` | Structured logging |
| `requests` | HTTP (download frida-server, internal communication) |

> **Note:** `frida`, `frida-tools`, `frida-dexdump`, `semgrep` and `apkleaks` are
> system tools (pip or Homebrew), not project dependencies.
> They are validated with `shutil.which()` before use; if not installed,
> the corresponding module is skipped with a warning.

---

## Docker Usage (hybrid)

This mode runs `nutcracker` inside Docker and uses an emulator/device connected on the host.
This is the recommended option for Windows + WSL.

### 1) Build and open a container shell

```bash
docker compose build
docker compose run --rm nutcracker
```

### 2) Verify that the container's ADB can see the host

Inside the container:

```bash
adb devices
frida-ls-devices
```

If nothing appears, restart ADB on the host (Windows/Linux/macOS):

```bash
adb kill-server
adb start-server
adb devices
```

### 3) Run analysis from the container

```bash
python nutcracker.py analyze downloads/app.apk
```

### Notes for Windows + WSL

- The emulator typically runs on Windows, not inside WSL.
- The container connects to the host's `adb server` via `ADB_SERVER_SOCKET=tcp:host.docker.internal:5037`.
- If Frida cannot resolve `-D emulator-xxxx`, use `-U` (the project pipeline already handles this for emulators).

---

## Static Analysis Rules (semgrep)

OWASP MASTG rules for jadx-decompiled code come from:
[mindedsecurity/semgrep-rules-android-security](https://github.com/mindedsecurity/semgrep-rules-android-security)

```bash
git clone https://github.com/mindedsecurity/semgrep-rules-android-security \
    semgrep_rules_android

# To update:
git -C ./semgrep_rules_android pull
```

The path is configured in `config.yaml`:
```yaml
strategies:
  scanner_config: "p/secrets ./semgrep_rules_android/rules"
```

> **Note:** The `p/android`, `p/secrets` and `p/owasp-top-ten` profiles are no longer
> available in the semgrep public registry (HTTP 404 since ~2025). Use the local rules instead.

---

## Obtaining the Google Play AAS Token

apkeep requires a long-lived AAS token to download from Google Play.

```bash
# Interactive assistant (step-by-step guided on the device):
python nutcracker.py setup-token

# Optional: choose device and method
python nutcracker.py setup-token --serial emulator-5554 --method auto
```

---

## Basic Usage

```bash
source .venv/bin/activate

# Analyze a local APK:
python nutcracker.py analyze downloads/app.apk

# Download and analyze from Google Play (URL or package ID):
python nutcracker.py scan 'https://play.google.com/store/apps/details?id=com.example.app'
python nutcracker.py analyze com.example.app

# Batch scan from a package list:
python nutcracker.py batch packages.txt
```

### `launch` command — manual Frida bypass

Launches an already-installed app using the last bypass script generated for that package:

```bash
# Use the most recent bypass script for the package:
python nutcracker.py launch com.example.app

# Specify a particular emulator:
python nutcracker.py launch com.example.app --serial emulator-5554

# Specify a script manually:
python nutcracker.py launch com.example.app --script frida_scripts/bypass_com.example.app_....js

# Pass the APK path directly (extracts the package from the filename):
python nutcracker.py launch downloads/com.example.app/com.example.app.apk
```

The command:
1. Restarts frida-server on the device (kills any existing process).
2. Runs `adb root` to obtain context `u:r:su:s0` — **required on Android 14** so frida-server can read `/sys/fs/selinux/policy`.
3. Launches the app via `frida -f <package> -l <script>` with the bypass script.

---

## Configuration (`config.yaml` / `config.yaml.example`)

Use [config.yaml.example](config.yaml.example) as the source of truth.
The recommended practice is to copy that file to `config.yaml` and adjust only the values you need.

```yaml
google_play:
  email: "you@gmail.com"
  aas_token: "aas_et/..."

downloader:
  output_dir: "./downloads"
  keep_apk: true

reports:
  output_dir: "./reports"
  save_json: false
  save_pdf: true

features:                       # Feature flags: enable or disable modules
  anti_root_analysis: true      # Anti-root protection detection
  decompilation: true           # Decompilation (jadx or runtime, depending on pipeline)
  manifest_scan: true           # Insecure manifest configuration analysis
  vuln_scan: false              # Vulnerability scanner (regex + semgrep)
  leak_scan: true               # Leak/secret scanner
  osint_scan: true              # OSINT: subdomains and public leaks
  report_pdf: true              # Generate PDF report
  report_json: false            # Generate JSON report

leak_scan:
  native: true                  # Internal HC rules on decompiled code
  apkleaks: true                # apkleaks on the original APK
  gitleaks: true                # gitleaks on decompiled code

osint:
  crt_sh: true                  # Subdomain enumeration via crt.sh
  github_search: true           # Search for public leaks on GitHub
  github_token: ''              # Optional PAT for the Code Search API
  fofa_search: false            # Search for exposed assets on FOFA
  fofa_key: ''                  # FOFA API key for search/all
  postman_search: true          # Search for public Postman collections
  execute_dorks: false          # Optional web searches via DuckDuckGo
  dork_engines:
    - duckduckgo
  dork_max_per_engine: 5        # Maximum web queries per engine
  dork_max_results_per_dork: 5  # Maximum results per query
  wayback_search: true          # Search historical URLs on archive.org
  wayback_limit_per_domain: 200 # Maximum archived URLs per domain
  wayback_filter_interesting: true  # Filter to sensitive paths/queries

strategies:
  anti_root_engine: native      # Anti-root detection engine
  scanner_engine: auto          # auto | semgrep | regex | none
  scanner_config: "p/secrets ./semgrep_rules_android/rules"
  show_emulator: true
  runtime_target: emulator      # auto | emulator | device
  default_emulator_avd: ""
  default_device_id: ""
  frida_host: ""               # host:port for Frida TCP
  frida_server_version: ""     # explicit frida-server version

pipelines:
  protected:                    # Apps with detected protection
    decompilation: runtime      # Runtime decompilation (frida-dexdump)
    fallback_jadx: true         # If runtime fails, try jadx
    runtime_methods:            # Executed in the order listed below
    # - frida_server: runtime extraction using Frida with frida-server on the device or emulator
    # - gadget: instrumentation via Frida Gadget embedded in the APK
    # - fart: alternative runtime DEX extraction flow
    - frida_server
    - gadget
    - fart
  unprotected:                  # Apps without protection
    decompilation_jadx: true    # Direct static decompilation

auto:
  unattended: true              # Unattended mode (no manual intervention)

batch:
  list_file: ""                # Optional list file for batch mode
  stop_on_error: false
```

---

## Dynamic Analysis Flow

```
APK
 └─► Install on AVD emulator
      ├─► frida-dexdump        (primary strategy: dumps DEX from memory)
      │    └─► fails →
      ├─► Frida Gadget inject   (if pipeline.protected includes gadget)
      │    └─► fails →
      └─► FART (classloader hook via Frida script)
               └─► jadx → scan → PDF
```

### PDF Report Sections

| Section | Description |
|---|---|
| Cover | Binary protection verdict (NO PROTECTION / PROTECTION BROKEN / PROTECTED) and APK metadata |
| Executive Summary | Executive summary with app data and risk per module |
| Anti-Root Analysis | Detected vs bypassed protections (5 detectors) |
| Bypass RASP | Bypass techniques for each found protection |
| Misconfigurations | AndroidManifest.xml analysis: `debuggable`, `allowBackup`, `cleartext`, exported components and dangerous permissions |
| Leaks | Hardcoded secrets: API keys, tokens, AWS/Firebase credentials |
| Vulnerabilities | semgrep + regex findings classified by severity |

### False Positive Reduction

Detectors implement multiple filtering layers:

- **Anti-root**: Whitelist of 30+ analytics SDK namespaces (AppMetrica, AppsFlyer, Adjust, etc.). Root-check strings from SDKs are not counted as app-level protection.
- **DexGuard**: Requires vendor signature (guardsquare, arxan) as mandatory evidence. Multidex + high entropy without vendor sig is not reported.
- **Leaks (regex)**: Ignore patterns for HC002 (passwords), HC006 (crypto keys), AUTH001 (tokens in logs) that filter framework constants.
- **Leaks (apkleaks)**: Post-filtering of noisy categories and FP patterns (JWT versions, X.509, Facebook SDK signatures).

### App Bundle (AAB) Support

When apkeep downloads only the base split (`base.apk`), the tool:
1. Detects additional splits in the same package folder
2. Uses `adb install-multiple` with all splits (excludes `_patched`, `_unsigned`, `_resign` artifacts)
3. If no local splits exist: patches the binary `AndroidManifest.xml` to override
   `requiredSplitTypes` and reinstalls

### Android 14 and SELinux

On Android 14 (API 34), frida-server needs SELinux context `u:r:su:s0` to read
`/sys/fs/selinux/policy` during spawn. Without this context, frida throws `InvocationTargetException`.

The `launch` command and the automatic pipeline run `adb root` before starting frida-server.
Requires an AVD with a `google_apis` image (not `google_play`) or root access on a physical device.

### Fallbacks in `launch_with_dexdump`

When the app doesn't start with `monkey` (native-level anti-tampering, emulator detection), the system automatically tries:

1. **`am start`** — more reliable alternative to monkey for apps with restrictions in the intent handler
2. **`frida-dexdump -f` (spawn mode)** — pauses the app before any code runs, including anti-tampering. Requires an active frida-server.

---

## Roadmap

See [ROADMAP.md](ROADMAP.md) for pending tasks: OSINT improvements, iOS/IPA support and partial migration to Go.

---

## Project Structure

```
nutcracker/
├── nutcracker.py                   # Main CLI (click)
├── config.yaml                     # Local configuration
├── config.yaml.example             # Configuration template
├── setup.sh                        # Quick install script
├── requirements.txt                # Python dependencies
├── docker-compose.yml              # Docker environment for hybrid execution
├── Dockerfile                      # Project base image
├── docs/assets/                    # Logo and README assets
├── downloads/                      # Downloaded APKs
├── decompiled/                     # Code decompiled by jadx / frida-dexdump
├── frida_scripts/                  # Generated Frida bypass scripts
├── reports/                        # Generated PDFs and JSON reports
├── semgrep_rules_android/          # OWASP MASTG rules
├── tools/                          # Auxiliary utilities
└── nutcracker_core/
  ├── __init__.py                 # Main package
    ├── analyzer.py                 # Main static analysis (androguard)
  ├── apk_tools.py                # APK manipulation and installation utilities
  ├── config.py                   # config.yaml loading and access
  ├── device.py                   # Devices, SDK, Frida and adb utilities
    ├── downloader.py               # Download APKs (Google Play / APKPure / direct URL)
    ├── decompiler.py               # jadx interface
    ├── deobfuscator.py             # FART flow for physical device
  ├── frida_bypass.py             # Frida scripts (bypass, FART)
    ├── manifest_analyzer.py        # AndroidManifest.xml and insecure configuration analysis
  ├── osint.py                    # Subdomains, public leaks, Wayback and optional web searches
    ├── pdf_reporter.py             # PDF report generation (fpdf2)
    ├── pipeline.py                 # End-to-end analysis pipeline
  ├── reporter.py                 # JSON reports and console output
  ├── runtime.py                  # Dynamic analysis orchestration
    ├── string_extractor.py         # APK string extraction
  ├── vuln_scanner.py             # Semgrep + regex + apkleaks + gitleaks
    └── detectors/
    ├── __init__.py             # Detectors subpackage export
    ├── appdome.py              # Appdome detector
    ├── base.py                 # Common base for detectors
        ├── dexguard.py             # DexGuard / Arxan detector (requires vendor signature)
        ├── libraries.py            # Anti-root library detector (classes only, no strings)
        ├── magisk.py               # Magisk / SuperSU / KernelSU / Frida detector
        ├── safetynet.py            # SafetyNet / Play Integrity API detector
        └── manual_checks.py        # Manual checks (with analytics SDK filtering)
```
