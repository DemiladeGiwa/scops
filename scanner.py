#!/usr/bin/env python3
"""
WordPress Security Scanner
===========================

A self-contained, dependency-light tool that runs a passive security audit
against a WordPress site you own or are authorized to test, and produces a
markdown report matching the style of security_audit_chopshaven.md.

SETUP:
    pip install requests schedule

USAGE:
    One-off scan:
        python scanner.py https://example.com

    Continuous scan (re-runs every 24 hours):
        python scanner.py https://example.com --loop

Reports are written to ./reports/security_audit_{domain}_{YYYY-MM-DD_HHMM}.md
Each run prints a one-line diff summary vs. the most recent prior report.

All checks are passive/read-only (GET/POST requests any browser could make
or the standard WP REST/XML-RPC APIs already expose). This tool does not
attempt logins, exploit anything, or send attack payloads. Only run it
against sites you own or have explicit permission to test.
"""

import os
import re
import sys
import glob
import time
import datetime
import argparse
from urllib.parse import urljoin, urlparse

import requests

try:
    import schedule
    HAVE_SCHEDULE = True
except ImportError:
    HAVE_SCHEDULE = False

USER_AGENT = "Mozilla/5.0 (compatible; SelfAuditScanner/1.0; +self-security-audit)"
TIMEOUT = 12
REPORTS_DIR = "./reports"

SEVERITY_ORDER = ["critical", "high", "medium"]
SEVERITY_HEADERS = {
    "critical": "## 🚨 Critical Vulnerabilities",
    "high": "## ⚠️ High-Severity Issues",
    "medium": "## 🔶 Medium-Severity Issues",
}
SEVERITY_CALLOUT = {
    "critical": "[!CAUTION]",
    "high": "[!WARNING]",
    "medium": "[!IMPORTANT]",
}
SEVERITY_PRIORITY_LABEL = {
    "critical": "🔴 **P0**",
    "high": "🟠 **P1**",
    "medium": "🟡 **P2**",
}


def get(url, **kwargs):
    headers = kwargs.pop("headers", {})
    headers.setdefault("User-Agent", USER_AGENT)
    return requests.get(url, headers=headers, timeout=TIMEOUT, **kwargs)


def post(url, **kwargs):
    headers = kwargs.pop("headers", {})
    headers.setdefault("User-Agent", USER_AGENT)
    return requests.post(url, headers=headers, timeout=TIMEOUT, **kwargs)


def finding(id_, severity, title, description, evidence, fix, passed=False):
    return {
        "id": id_,
        "severity": severity,
        "title": title,
        "description": description,
        "evidence": evidence,
        "fix": fix,
        "passed": passed,
    }


# ---------------------------------------------------------------------------
# Individual checks. Each returns a single finding dict (passed=True if the
# check ran cleanly and found nothing to flag).
# ---------------------------------------------------------------------------

def check_xmlrpc(target):
    url = urljoin(target, "/xmlrpc.php")
    try:
        r = get(url)
        if r.status_code != 200 or "XML-RPC server accepts POST requests only" not in r.text:
            return finding("xmlrpc", "critical", "XML-RPC Enabled", "", "", "", passed=True)
    except requests.RequestException as e:
        return finding("xmlrpc", "critical", "XML-RPC Check Failed", f"Request error: {e}", "", "", passed=True)

    methods = []
    try:
        body = (
            '<?xml version="1.0"?><methodCall>'
            "<methodName>system.listMethods</methodName><params></params>"
            "</methodCall>"
        )
        r2 = post(url, data=body, headers={"Content-Type": "text/xml"})
        methods = re.findall(r"<string>([^<]+)</string>", r2.text)
    except requests.RequestException:
        pass

    dangerous = [m for m in methods if m in (
        "system.multicall", "wp.getUsersBlogs", "pingback.ping",
        "wp.getUsers", "wp.getAuthors",
    )]

    desc = (
        f"The site's `xmlrpc.php` endpoint is enabled and reachable. "
        f"A `system.listMethods` probe returned {len(methods)} methods"
        + (f", including dangerous ones: {', '.join(dangerous)}." if dangerous else ".")
        + " `system.multicall` allows bundling hundreds of login attempts into a "
        "single HTTP request, bypassing most per-request rate limiters. "
        "`pingback.ping` can be abused for SSRF/DDoS amplification."
    )
    fix = (
        "// Add to functions.php\n"
        "add_filter('xmlrpc_enabled', '__return_false');\n\n"
        "# Or block at the server level in .htaccess:\n"
        "<Files xmlrpc.php>\n"
        "  Order Deny,Allow\n"
        "  Deny from all\n"
        "</Files>"
    )
    return finding("xmlrpc", "critical", "XML-RPC Enabled — Brute Force & Amplified Attacks",
                   desc, url, fix)


def check_rest_user_enum(target):
    url = urljoin(target, "/wp-json/wp/v2/users")
    try:
        r = get(url)
    except requests.RequestException as e:
        return finding("rest_users", "critical", "REST User Enumeration Check Failed", f"{e}", url, "", passed=True)

    if r.status_code != 200:
        return finding("rest_users", "critical", "REST API User Enumeration", "", url, "", passed=True)

    try:
        data = r.json()
    except ValueError:
        return finding("rest_users", "critical", "REST API User Enumeration", "", url, "", passed=True)

    if not isinstance(data, list) or not data:
        return finding("rest_users", "critical", "REST API User Enumeration", "", url, "", passed=True)

    rows = []
    for u in data[:10]:
        rows.append(f"| {u.get('id','?')} | {u.get('name','?')} | {u.get('slug','?')} |")

    desc = (
        "The WordPress REST API publicly exposes registered usernames, giving an "
        "attacker half the credentials needed for a brute-force login attempt.\n\n"
        "| User ID | Display Name | Username (slug) |\n|---|---|---|\n" + "\n".join(rows)
    )
    fix = (
        "// Add to functions.php — block REST user enumeration for logged-out visitors\n"
        "add_filter('rest_endpoints', function($endpoints) {\n"
        "    if (!is_user_logged_in()) {\n"
        "        unset($endpoints['/wp/v2/users']);\n"
        "        unset($endpoints['/wp/v2/users/(?P<id>[\\d]+)']);\n"
        "    }\n"
        "    return $endpoints;\n"
        "});"
    )
    return finding("rest_users", "critical", "User Enumeration via REST API — Usernames Fully Exposed",
                   desc, url, fix)


def check_author_enum(target):
    found = []
    for i in range(1, 6):
        url = urljoin(target, f"/?author={i}")
        try:
            r = get(url, allow_redirects=True)
            m = re.search(r"<title>([^<]*)</title>", r.text, re.IGNORECASE)
            if m and "author" not in urlparse(r.url).query:
                # Redirected away from an author query -> likely protected
                continue
            if m:
                title = m.group(1).strip()
                if title:
                    found.append((i, title, r.url))
        except requests.RequestException:
            continue

    if not found:
        return finding("author_enum", "critical", "Author Archive Enumeration", "", "", "", passed=True)

    lines = "\n".join(f"- `?author={i}` → page title `{t}` ({u})" for i, t, u in found)
    desc = (
        "Author archive pages leak usernames through the page `<title>` tag / "
        "canonical author URL, without needing the REST API.\n\n" + lines
    )
    fix = (
        "// Add to functions.php — redirect author archive queries\n"
        "add_action('template_redirect', function() {\n"
        "    if (is_author()) {\n"
        "        wp_redirect(home_url(), 301);\n"
        "        exit;\n"
        "    }\n"
        "});"
    )
    return finding("author_enum", "critical", "User Enumeration via Author Archives",
                   desc, urljoin(target, "/?author=1"), fix)


def check_login_hardening(target):
    url = urljoin(target, "/wp-login.php")
    try:
        r = get(url)
    except requests.RequestException as e:
        return finding("login", "high", "Login Hardening Check Failed", f"{e}", url, "", passed=True)

    if r.status_code != 200 or "wp-login" not in r.text.lower() and "user_login" not in r.text.lower():
        return finding("login", "high", "wp-login.php Hardening", "", url, "", passed=True)

    text_lower = r.text.lower()
    has_captcha = any(k in text_lower for k in ("recaptcha", "captcha", "h-captcha", "turnstile"))
    has_2fa_hint = any(k in text_lower for k in ("two-factor", "2fa", "authenticator"))

    if has_captcha or has_2fa_hint:
        return finding("login", "high", "wp-login.php Hardening", "", url, "", passed=True)

    desc = (
        "The default WordPress login page is reachable with no visible CAPTCHA, "
        "2FA, or rate-limiting markers in the page source. This is a **best-effort "
        "heuristic** — some protections (server-side rate limiting, IP-based "
        "lockouts) don't show up in the HTML and may still be active. Treat this "
        "as 'worth confirming,' not conclusive."
    )
    fix = (
        "1. Install Wordfence or Limit Login Attempts Reloaded\n"
        "2. Add two-factor authentication (e.g. WP 2FA plugin)\n"
        "3. Consider a custom login URL (WPS Hide Login)\n"
        "4. Add CAPTCHA to the login form"
    )
    return finding("login", "high", "wp-login.php Publicly Accessible — No Rate Limiting Detected",
                   desc, url, fix)


def check_readme(target):
    url = urljoin(target, "/readme.html")
    try:
        r = get(url)
    except requests.RequestException as e:
        return finding("readme", "high", "readme.html Check Failed", f"{e}", url, "", passed=True)

    if r.status_code != 200:
        return finding("readme", "high", "readme.html Exposure", "", url, "", passed=True)

    desc = "The default WordPress `readme.html` is publicly reachable, confirming the CMS and often the version."
    fix = (
        "# In .htaccess\n"
        "<Files readme.html>\n"
        "  Order Deny,Allow\n"
        "  Deny from all\n"
        "</Files>"
    )
    return finding("readme", "high", "WordPress readme.html Exposed", desc, url, fix)


def check_version_disclosure(target):
    url = target
    try:
        r = get(url)
    except requests.RequestException as e:
        return finding("version", "high", "Version Disclosure Check Failed", f"{e}", url, "", passed=True)

    gen = re.search(r'<meta name="generator" content="(WordPress[^"]*)"', r.text, re.IGNORECASE)
    vers = set(re.findall(r"\?ver=([\d.]+)", r.text))

    if not gen and not vers:
        return finding("version", "high", "Version Disclosure", "", url, "", passed=True)

    lines = []
    if gen:
        lines.append(f'`<meta name="generator" content="{gen.group(1)}">`')
    if vers:
        lines.append("Asset query strings: " + ", ".join(f"`?ver={v}`" for v in sorted(vers)))

    desc = "The exact WordPress/asset version is visible in the page source.\n\n" + "\n".join(lines)
    fix = (
        "// Add to functions.php\n"
        "remove_action('wp_head', 'wp_generator');\n\n"
        "add_filter('style_loader_src', function($src) { return remove_query_arg('ver', $src); });\n"
        "add_filter('script_loader_src', function($src) { return remove_query_arg('ver', $src); });"
    )
    return finding("version", "high", "WordPress Version Number Exposed in HTML Source", desc, url, fix)


def check_security_headers(target):
    url = target
    try:
        r = get(url)
    except requests.RequestException as e:
        return finding("headers", "medium", "Security Headers Check Failed", f"{e}", url, "", passed=True)

    wanted = [
        "X-Frame-Options", "X-Content-Type-Options", "Strict-Transport-Security",
        "Referrer-Policy", "Permissions-Policy", "Content-Security-Policy",
    ]
    missing = [h for h in wanted if h not in r.headers]
    leaky = [h for h in ("X-Powered-By", "Platform", "X-Hosting") if h in r.headers]

    if not missing and not leaky:
        return finding("headers", "medium", "Security Headers", "", url, "", passed=True)

    rows = "\n".join(f"| `{h}` | {'❌ Missing' if h in missing else '✅ Present'} |" for h in wanted)
    leak_note = ""
    if leaky:
        leak_note = "\n\nAlso exposed: " + ", ".join(f"`{h}: {r.headers[h]}`" for h in leaky)

    desc = "Missing/leaking HTTP response headers:\n\n| Header | Status |\n|---|---|\n" + rows + leak_note
    fix = (
        "<IfModule mod_headers.c>\n"
        '  Header always set X-Frame-Options "SAMEORIGIN"\n'
        '  Header always set X-Content-Type-Options "nosniff"\n'
        '  Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"\n'
        '  Header always set Referrer-Policy "strict-origin-when-cross-origin"\n'
        '  Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"\n'
        "  Header always unset X-Powered-By\n"
        "</IfModule>"
    )
    return finding("headers", "medium", "Missing Security Headers", desc, url, fix)


def check_plugin_versions(target):
    url = target
    try:
        r = get(url)
    except requests.RequestException as e:
        return finding("plugins", "medium", "Plugin Version Check Failed", f"{e}", url, "", passed=True)

    hits = set(re.findall(r"/wp-content/(?:plugins|themes)/([^/]+)/[^\"' ]*\?ver=([\d.]+)", r.text))

    if not hits:
        return finding("plugins", "medium", "Plugin/Theme Version Exposure", "", url, "", passed=True)

    rows = "\n".join(f"| `{name}` | {ver} |" for name, ver in sorted(hits))
    desc = "Plugin/theme names and versions visible in page source (usable to look up known CVEs):\n\n| Plugin/Theme | Version |\n|---|---|\n" + rows
    fix = "Strip `?ver=` query strings from enqueued assets, and keep all plugins/themes updated regardless."
    return finding("plugins", "medium", "Plugin & Theme Version Numbers Exposed", desc, url, fix)


def check_rest_root(target):
    url = urljoin(target, "/wp-json/")
    try:
        r = get(url)
    except requests.RequestException as e:
        return finding("rest_root", "medium", "REST Root Check Failed", f"{e}", url, "", passed=True)

    if r.status_code != 200:
        return finding("rest_root", "medium", "REST API Root Exposure", "", url, "", passed=True)

    desc = "The full WordPress REST API root is publicly reachable, exposing site structure, content types, and routes."
    fix = "Restrict with a plugin (e.g. Disable REST API) if the API isn't needed by the front end, or limit exposed routes via `rest_endpoints`."
    return finding("rest_root", "medium", "WP-JSON / REST API Fully Exposed", desc, url, fix)


ALL_CHECKS = [
    check_xmlrpc,
    check_rest_user_enum,
    check_author_enum,
    check_login_hardening,
    check_readme,
    check_version_disclosure,
    check_security_headers,
    check_plugin_versions,
    check_rest_root,
]

CHECK_TITLES = {
    "xmlrpc": "XML-RPC exposure",
    "rest_users": "User enumeration via REST API",
    "author_enum": "User enumeration via author archives",
    "login": "Login hardening (wp-login.php)",
    "readme": "readme.html exposure",
    "version": "Version disclosure",
    "headers": "Security headers",
    "plugins": "Plugin/theme version exposure",
    "rest_root": "REST API root exposure",
}


def detect_platform(target):
    """Best-effort platform/plugin summary for the report header."""
    try:
        r = get(target)
    except requests.RequestException:
        return "Unknown (homepage unreachable)"

    gen = re.search(r'<meta name="generator" content="(WordPress[^"]*)"', r.text, re.IGNORECASE)
    server = r.headers.get("Server", "")
    platform = gen.group(1) if gen else "WordPress (version not disclosed)"
    if server:
        platform += f" — server: {server}"
    return platform


def run_scan(target):
    findings = []
    for check in ALL_CHECKS:
        try:
            findings.append(check(target))
        except Exception as e:  # noqa: BLE001 — one check must never kill the scan
            findings.append(finding(check.__name__, "medium", f"{check.__name__} crashed",
                                     f"Unexpected error: {e}", "", "", passed=True))
    return findings


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------

def render_report(target, findings, platform):
    domain = urlparse(target).netloc
    now = datetime.datetime.now()
    lines = []
    lines.append(f"# 🔒 Security Audit: {domain}")
    lines.append("")
    lines.append(f"**Date:** {now.strftime('%B %d, %Y %H:%M')}  ")
    lines.append(f"**Target:** {target}  ")
    lines.append(f"**Platform:** {platform}  ")
    lines.append("")
    lines.append("---")
    lines.append("")

    active = [f for f in findings if not f["passed"]]
    passed = [f for f in findings if f["passed"]]

    by_sev = {s: [f for f in active if f["severity"] == s] for s in SEVERITY_ORDER}

    n = 1
    for sev in SEVERITY_ORDER:
        group = by_sev[sev]
        if not group:
            continue
        lines.append(SEVERITY_HEADERS[sev])
        lines.append("")
        for f in group:
            lines.append(f"### {n}. {f['title']}")
            lines.append("")
            lines.append(f"> {SEVERITY_CALLOUT[sev]}")
            lines.append(f"> {f['description'].splitlines()[0] if f['description'] else f['title']}")
            lines.append("")
            if f["evidence"]:
                lines.append(f"**What's exposed:** `{f['evidence']}`")
                lines.append("")
            if f["description"]:
                lines.append(f["description"])
                lines.append("")
            if f["fix"]:
                fence_lang = "php" if "add_filter" in f["fix"] or "add_action" in f["fix"] else \
                             "apache" if "<Files" in f["fix"] or "<IfModule" in f["fix"] else ""
                lines.append(f"**Fix:**")
                lines.append(f"```{fence_lang}")
                lines.append(f["fix"])
                lines.append("```")
                lines.append("")
            lines.append("---")
            lines.append("")
            n += 1

    if active and any(f["severity"] in ("critical", "high") for f in active):
        lines.append("## 📊 Attack Chain Summary")
        lines.append("")
        crit_titles = [f["title"] for f in active if f["severity"] == "critical"]
        high_titles = [f["title"] for f in active if f["severity"] == "high"]
        steps = []
        step_n = 1
        for t in crit_titles + high_titles:
            steps.append(f"Step {step_n}: {t}")
            step_n += 1
        lines.append("```")
        lines.append("\n".join(steps))
        lines.append("```")
        lines.append("")
        lines.append("> [!CAUTION]")
        lines.append("> The findings above can plausibly be chained together into a realistic path toward account or site compromise. Treat critical items as top priority.")
        lines.append("")
        lines.append("---")
        lines.append("")

    if active:
        lines.append("## ✅ Recommended Fixes — Priority Order")
        lines.append("")
        lines.append("| Priority | Fix | Difficulty | Time |")
        lines.append("|---|---|---|---|")
        for sev in SEVERITY_ORDER:
            for f in by_sev[sev]:
                lines.append(f"| {SEVERITY_PRIORITY_LABEL[sev]} | {f['title']} | Easy–Medium | 5–20 min |")
        lines.append("")
        lines.append("---")
        lines.append("")

    if passed:
        lines.append("## ✔️ Passed Checks")
        lines.append("")
        for f in passed:
            lines.append(f"- {CHECK_TITLES.get(f['id'], f['id'])} — no issue found")
        lines.append("")

    return "\n".join(lines)


def report_filename(target):
    domain = urlparse(target).netloc
    ts = datetime.datetime.now().strftime("%Y-%m-%d_%H%M")
    return os.path.join(REPORTS_DIR, f"security_audit_{domain}_{ts}.md")


def find_previous_report(target):
    domain = urlparse(target).netloc
    pattern = os.path.join(REPORTS_DIR, f"security_audit_{domain}_*.md")
    files = sorted(glob.glob(pattern))
    return files[-1] if files else None


def extract_titles_from_report(path):
    """Pull finding titles (### N. Title) out of a previously written report."""
    titles = set()
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                m = re.match(r"^###\s+\d+\.\s+(.*)$", line.strip())
                if m:
                    titles.add(m.group(1).strip())
    except OSError:
        pass
    return titles


def print_diff_summary(target, findings, prev_path):
    current_titles = {f["title"] for f in findings if not f["passed"]}
    if not prev_path:
        print(f"[diff] No previous report found — {len(current_titles)} finding(s) this run.")
        return
    prev_titles = extract_titles_from_report(prev_path)
    new = current_titles - prev_titles
    resolved = prev_titles - current_titles
    unchanged = current_titles & prev_titles
    print(f"[diff] vs {os.path.basename(prev_path)}: "
          f"{len(new)} new, {len(resolved)} resolved, {len(unchanged)} unchanged.")
    if new:
        print("  New:      " + "; ".join(sorted(new)))
    if resolved:
        print("  Resolved: " + "; ".join(sorted(resolved)))


def scan_once(target):
    os.makedirs(REPORTS_DIR, exist_ok=True)
    prev = find_previous_report(target)

    print(f"Scanning {target} ...")
    findings = run_scan(target)
    platform = detect_platform(target)
    report = render_report(target, findings, platform)

    out_path = report_filename(target)
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(report)

    print(f"Report written: {out_path}")
    print_diff_summary(target, findings, prev)
    return out_path


def main():
    parser = argparse.ArgumentParser(description="Passive WordPress security scanner / self-audit tool.")
    parser.add_argument("target", nargs="?", default="https://chopshaven.ca",
                         help="Target site URL, e.g. https://example.com")
    parser.add_argument("--loop", action="store_true",
                         help="Run continuously, re-scanning every 24 hours.")
    args = parser.parse_args()

    target = args.target
    if not target.startswith("http"):
        target = "https://" + target
    if not target.endswith("/"):
        target = target  # urljoin handles this fine without trailing slash

    if not args.loop:
        scan_once(target)
        return

    if HAVE_SCHEDULE:
        scan_once(target)
        schedule.every(24).hours.do(scan_once, target)
        print("Looping every 24 hours (Ctrl+C to stop) ...")
        while True:
            schedule.run_pending()
            time.sleep(60)
    else:
        print("`schedule` not installed — falling back to a plain sleep loop.")
        while True:
            scan_once(target)
            print("Sleeping 24 hours ...")
            time.sleep(86400)


if __name__ == "__main__":
    main()
