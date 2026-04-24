# Roadmap — nutcracker

`[ ]` pending · `[~]` in progress · `[x]` completed

## OSINT
- [ ] **GitHub Search with token** — the current HTML scraping fails without login. Read `GITHUB_TOKEN` from the environment and use the REST code search API; fall back to scraping as a fallback.
- [ ] **BuildConfig secrets in the PDF** — extracted internally but not shown in the report. Add a subsection in `_osint_section`.

## Platforms
- [ ] **iOS / IPA support** — download with `ipatool`, static Mach-O analysis with `jtool2`/`class-dump`, secrets in `.plist`/`.strings`, `Info.plist` analysis (permissions, ATS), jailbreak check detection. MVP static only; dynamic requires jailbreak.

## Architecture
- [ ] **Split `vuln_scanner.py`** — 1400+ lines with three responsibilities. Split into `scan_types.py` (dataclasses), `vuln_scanner.py` (regex + semgrep) and `leak_scanner.py` (apkleaks, gitleaks). Do this before adding new leak sources or porting to Go.
- [ ] **Port secret scanner to Go** — `string_extractor.py` and the HC* rules are the slowest steps. Go binary `nutcracker-strings` that takes a directory and patterns and returns JSON. Python invokes it as a subprocess, the same way it does semgrep. Prerequisite: split modules first.
