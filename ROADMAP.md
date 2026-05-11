# Roadmap — nutcracker

`[ ]` pending · `[~]` in progress · `[x]` completed

## OSINT
- [ ] **GitHub Search with token** — the current HTML scraping fails without login. Read `GITHUB_TOKEN` from the environment and use the REST code search API; fall back to scraping as a fallback.
- [ ] **BuildConfig secrets in the PDF** — extracted internally but not shown in the report. Add a subsection in `_osint_section`.

## Platforms
- [ ] **iOS / IPA support** — download with `ipatool`, static Mach-O analysis with `jtool2`/`class-dump`, secrets in `.plist`/`.strings`, `Info.plist` analysis (permissions, ATS), jailbreak check detection. MVP static only; dynamic requires jailbreak.

## Reporting
- [ ] **Differentiate runtime bypass vs DEX extraction in reports** — The current verdict only distinguishes `PROTECTED` from `PROTECTION BROKEN`, where `PROTECTION BROKEN` requires a successful in-memory DEX dump (`dex_count > 0`). This is misleading: the FridaAgent can bypass all anti-root protections and run the app on a rooted device without ever dumping DEX (e.g. apps with aggressive native anti-root that kill the process before FART hooks run). Proposed fix — two independent verdicts:
  - **Static protection** (`PROTECTED` / `UNPROTECTED`): driven by the existing static detectors.
  - **Dynamic analysis** (`BYPASS CONFIRMED` / `DEX EXTRACTED` / `NOT ATTEMPTED`): fed by the FridaAgent result (`report_success`) and the FART/dexdump pipeline respectively. 
  Implementation touch-points:
  1. Add `aipwn_bypass_confirmed: bool` field to `AnalysisResult` (set by `aipwn.py` after `report_success`).
  2. Change `build_masvs_report()` in `masvs.py`: replace `bypass_confirmed = analysis.protection_broken` with `bypass_confirmed = analysis.protection_broken or analysis.aipwn_bypass_confirmed`. This makes `MASVS-RESILIENCE-*` controls flip to `bypass` status and apply the `_BYPASS_PENALTY` even when DEX extraction failed.
  3. Update `reporter.py` to show a separate dynamic analysis banner alongside the static verdict.
  4. Update the PDF report with a new dynamic analysis section.

## Architecture
- [ ] **Split `vuln_scanner.py`** — 1400+ lines with three responsibilities. Split into `scan_types.py` (dataclasses), `vuln_scanner.py` (regex + semgrep) and `leak_scanner.py` (apkleaks, gitleaks). Do this before adding new leak sources or porting to Go.
- [ ] **Port secret scanner to Go** — `string_extractor.py` and the HC* rules are the slowest steps. Go binary `nutcracker-strings` that takes a directory and patterns and returns JSON. Python invokes it as a subprocess, the same way it does semgrep. Prerequisite: split modules first.
