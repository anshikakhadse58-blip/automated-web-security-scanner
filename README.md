# Automated Web Security Header Scanner

A beginner-friendly Python project that checks a website's HTTP response for common security headers and provides a basic CORS configuration review.

## Features
- Checks six common security headers.
- Reports the HTTP status and final URL after redirects.
- Notes whether the final URL uses HTTPS.
- Reviews `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials`.
- Prints results in the terminal and can save a JSON report.
- Makes a normal GET request only; it does not exploit vulnerabilities.

## Requirements
- Python 3.9 or newer
- Internet access to the authorized target
- Packages listed in `requirements.txt`

## Setup
```bash
python -m venv .venv
```

Activate the environment:

**Windows**
```bash
.venv\Scripts\activate
```

**macOS / Linux**
```bash
source .venv/bin/activate
```

Install dependencies:
```bash
pip install -r requirements.txt
```

## Run
```bash
python scanner.py https://example.com
```

Save machine-readable output:
```bash
python scanner.py https://example.com --json report.json
```

Set a timeout:
```bash
python scanner.py https://example.com --timeout 15
```

Use only against websites you own or have explicit permission to assess. Replace `https://example.com` with an approved target.

## How to understand results
- **PRESENT** means the response included that header; it does not guarantee the value is secure.
- **MISSING** means the header was not observed on this response; it is a prompt for review, not proof of a vulnerability.
- A wildcard CORS origin may be appropriate for public resources, but should be reviewed for sensitive endpoints.
- The tool inspects a single GET response. CORS and header behavior can differ across routes and request types.

## Project files
- `scanner.py` — scanner source code
- `requirements.txt` — Python dependency list
- `Project_Report.pdf` — project documentation
