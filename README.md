# 🔥 FWRAX — Firewall Rule Review Audit X

> **Upload firewall rules → Python audits them → Download the report.**
> Runs entirely in your browser. No server. No VPC. No data ever leaves your machine.

## 🌐 Live Web Tool
**[https://inarhsec.github.io/FWRAX/](https://inarhsec.github.io/FWRAX/)**

Upload a `.json` or `.csv` rules file → click **Run Audit** → download PDF / JSON / CSV report.

---

## What's in this repo

```
FWRAX/
│
├── index.html          ← 🌐 GitHub Pages web GUI (single file, runs Python in browser)
│
├── cli.py              ← 💻 Command-line interface (original + enhanced)
├── server.py           ← 🖥️  FastAPI web server (run locally or on a server)
├── requirements.txt    ← Python dependencies
├── rules.json          ← Sample rules file
│
├── core/               ← Audit engine (auditor, shadow detector, reporter, config)
├── models/             ← Shared data models
├── services/           ← Orchestration layer
├── utils/              ← Shared helpers
├── web/                ← FastAPI routes + HTML templates
├── tests/              ← 33 unit tests
│
├── sample_data/        ← Real sample rule exports (Palo Alto, FortiGate)
│   └── RDCC/
│
└── .github/
    └── workflows/
        └── deploy.yml  ← Auto-deploys index.html to GitHub Pages on every push
```

---

## Features

| Feature | Web (GitHub Pages) | CLI / Server |
|---|---|---|
| JSON rules upload | ✅ | ✅ |
| CSV rules upload | ✅ | ✅ |
| Any-to-any detection | ✅ | ✅ |
| Blocked port detection | ✅ | ✅ |
| Shadow rule detection | ✅ | ✅ |
| Duplicate detection | ✅ | ✅ |
| Stale rule detection | ✅ | ✅ |
| Disabled rule recognition | ✅ | ✅ |
| Fake compliance mode | ✅ | ✅ |
| Strict / Relaxed modes | ✅ | ✅ |
| JSON report download | ✅ | ✅ |
| CSV report download | ✅ | — |
| PDF report | Print-to-PDF | ReportLab native |
| Excel (.xlsx) | — | ✅ |
| Server required | ❌ Never | ✅ Optional |

---

## Web GUI (GitHub Pages) — No install needed

Just visit **[https://inarhsec.github.io/FWRAX/](https://inarhsec.github.io/FWRAX/)**

- Python 3.11 runs inside your browser via [Pyodide](https://pyodide.org) (WebAssembly)
- First load ~5 seconds (downloads Pyodide from CDN, cached after that)
- Your firewall data **never leaves your browser**

---

## CLI — Local usage

```bash
# Install dependencies
pip install -r requirements.txt

# Basic audit (interactive)
python cli.py

# Audit a specific file
python cli.py --rules rules.json --out-pdf report.pdf

# CSV input
python cli.py --rules sample_data/RDCC/RDCC_PA_DC_POLICY.csv --out-pdf report.pdf

# Non-interactive with all outputs
python cli.py --rules rules.json --no-prompt --shadow-detection \
  --out-pdf report.pdf --out-json report.json --out-xlsx report.xlsx

# Relaxed mode
python cli.py --rules rules.json --mode relaxed --out-pdf report.pdf
```

### CLI flags

| Flag | Default | Description |
|---|---|---|
| `--rules FILE` | `rules.json` | Path to `.json` or `.csv` rules file |
| `--mode` | `strict` | `strict` or `relaxed` |
| `--no-prompt` | off | Skip all interactive prompts |
| `--organization NAME` | `the Organization` | Name used in report |
| `--out-pdf FILE` | — | Write PDF report |
| `--out-json FILE` | — | Write JSON report |
| `--out-xlsx FILE` | — | Write Excel report |
| `--shadow-detection` | prompted | Force-enable shadow detection |
| `--no-shadow-detection` | prompted | Disable shadow detection |
| `--no-console` | off | Suppress console output |
| `--log-level` | `INFO` | `DEBUG` / `INFO` / `WARNING` |

---

## Local web server (FastAPI)

```bash
pip install -r requirements.txt
python server.py
# Opens at http://localhost:8000
```

---

## Run tests

```bash
python -m pytest tests/ -v
# 33 tests — all should pass
```

---

## Supported input formats

### JSON
```json
[
  {"rule_name": "WEB-HTTPS", "source": "10.0.0.0/8", "destination": "203.0.113.50", "port": 443, "action": "allow"},
  {"rule_name": "DENY-ALL",  "source": "any",         "destination": "any",          "port": "any", "action": "deny"}
]
```

### CSV
```csv
rule_name,source,destination,port,action
WEB-HTTPS,10.0.0.0/8,203.0.113.50,443,allow
DENY-ALL,any,any,any,deny
```

Also accepts Palo Alto exports (`Name`, `Source Address`, `Destination Address`, `Service`, `Action`) and FortiGate JSON.

---

## Privacy

The GitHub Pages version is entirely client-side.
When you upload a file it is read by your browser, processed by Python in WebAssembly, and never sent anywhere.
The only external request is the initial Pyodide download from `cdn.jsdelivr.net`.
