#!/usr/bin/env python3
"""
Automated Web Security Header Scanner
A small, passive scanner for checking HTTP security headers and CORS configuration.

Use only on websites you own or have explicit permission to assess.
This tool makes ordinary HTTP requests; it does not exploit vulnerabilities.
"""
import argparse
import json
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

SECURITY_HEADERS = {
    "Content-Security-Policy": "Helps reduce the impact of cross-site scripting and content injection.",
    "Strict-Transport-Security": "Tells browsers to use HTTPS for future connections.",
    "X-Content-Type-Options": "Prevents MIME-type sniffing when set to nosniff.",
    "X-Frame-Options": "Helps control whether the page can be embedded in frames.",
    "Referrer-Policy": "Controls how much referrer information browsers send.",
    "Permissions-Policy": "Controls access to selected browser features."
}

def validate_url(url):
    """Require an explicit HTTP(S) URL and a hostname."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("URL must start with http:// or https:// and include a hostname.")
    return url

def scan(url, timeout=10):
    validate_url(url)
    headers = {
        "User-Agent": "EducationalSecurityHeaderScanner/1.0"
    }
    response = requests.get(
        url,
        headers=headers,
        timeout=timeout,
        allow_redirects=True
    )
    received = {key.lower(): value for key, value in response.headers.items()}

    findings = []
    for header, explanation in SECURITY_HEADERS.items():
        value = received.get(header.lower())
        findings.append({
            "header": header,
            "status": "present" if value else "missing",
            "value": value,
            "purpose": explanation
        })

    acao = received.get("access-control-allow-origin")
    acac = received.get("access-control-allow-credentials")
    cors_notes = []
    if acao == "*":
        cors_notes.append(
            "Access-Control-Allow-Origin is '*'. Review whether public cross-origin access is intended."
        )
        if (acac or "").lower() == "true":
            cors_notes.append(
                "The response also advertises credentials. Browsers reject wildcard origin with credentials, "
                "but the combination should still be reviewed."
            )
    elif acao:
        cors_notes.append(f"Access-Control-Allow-Origin is set to: {acao}")
    else:
        cors_notes.append("No Access-Control-Allow-Origin response header was observed on this request.")

    return {
        "scanned_at_utc": datetime.now(timezone.utc).isoformat(),
        "requested_url": url,
        "final_url": response.url,
        "http_status": response.status_code,
        "https_used": urlparse(response.url).scheme == "https",
        "security_headers": findings,
        "cors": {
            "allow_origin": acao,
            "allow_credentials": acac,
            "notes": cors_notes
        },
        "limitations": [
            "A missing header is a review item, not proof of an exploitable vulnerability.",
            "CORS behavior may vary by route, method, request headers, and server configuration.",
            "This tool performs a basic GET request only; it is not a full penetration test."
        ]
    }

def print_report(report):
    print(f"Automated Web Security Header Scanner")
    print(f"URL: {report['requested_url']}")
    print(f"Final URL: {report['final_url']}")
    print(f"HTTP status: {report['http_status']}")
    print(f"HTTPS used: {'yes' if report['https_used'] else 'no'}")
    print("\nSecurity headers:")
    for item in report["security_headers"]:
        value = f" — {item['value']}" if item["value"] else ""
        print(f"  [{item['status'].upper()}] {item['header']}{value}")
    print("\nCORS review:")
    for note in report["cors"]["notes"]:
        print(f"  - {note}")
    print("\nNote: Findings are informational and require manual review.")

def main():
    parser = argparse.ArgumentParser(
        description="Passively inspect common HTTP security headers and CORS response headers."
    )
    parser.add_argument("url", help="Target URL, e.g. https://example.com")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--json", dest="json_path", help="Save complete results as JSON to this file")
    args = parser.parse_args()

    if args.timeout < 1:
        parser.error("--timeout must be at least 1 second")

    try:
        report = scan(args.url, timeout=args.timeout)
        print_report(report)
        if args.json_path:
            with open(args.json_path, "w", encoding="utf-8") as output:
                json.dump(report, output, indent=2, ensure_ascii=False)
                output.write("\n")
            print(f"\nJSON report saved to: {args.json_path}")
    except (ValueError, requests.RequestException) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"Could not write output file: {exc}", file=sys.stderr)
        return 1
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
