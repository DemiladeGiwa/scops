#!/usr/bin/env python3
"""
build_site.py
-------------
Reads the reports produced by scanner.py (./reports/security_audit_*.md),
converts the most recent one into a styled index.html, and generates an
archive.html linking to every past report (also rendered as HTML).

Output goes to ./site/ -- this whole folder is what gets pushed to GitHub
and served by Netlify as-is (no build step runs on Netlify's side).

Access control is handled entirely by a Basic Auth edge function at
Netlify's edge (see netlify/edge-functions/basic-auth.js + netlify.toml).
This script no longer embeds any Netlify Identity widget, gating JS, or
login page -- the browser's native Basic Auth prompt handles everything
before this HTML is ever served.

SETUP:
pip install markdown

USAGE:
python3 build_site.py
"""

import os
import re
import glob
import html
import markdown

REPORTS_DIR = "./reports"
SITE_DIR = "./site"
ARCHIVE_SUBDIR = "archive"

PAGE_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex, nofollow">
<title>{title}</title>
<style>
:root {{
  --crit: #b91c1c;
  --high: #c2410c;
  --med: #a16207;
  --bg: #ffffff;
  --text: #1f2937;
  --muted: #6b7280;
  --border: #e5e7eb;
}}
* {{ box-sizing: border-box; }}
body {{
  margin: 0;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  line-height: 1.6;
  color: var(--text);
  background: #f9fafb;
}}
.wrap {{ max-width: 860px; margin: 0 auto; padding: 24px 18px 80px; }}
h1 {{ font-size: 1.6rem; margin-top: 0; }}
h2 {{ font-size: 1.25rem; margin-top: 2.2rem; padding-bottom: 6px; border-bottom: 2px solid var(--border); }}
h3 {{ font-size: 1.05rem; margin-top: 1.6rem; }}
code {{ background: #f1f5f9; padding: 2px 5px; border-radius: 4px; font-size: 0.9em; word-break: break-word; }}
pre {{ background: #0f172a; color: #e2e8f0; padding: 14px; border-radius: 8px; overflow-x: auto; font-size: 0.85rem; }}
pre code {{ background: none; color: inherit; padding: 0; }}
table {{ width: 100%; border-collapse: collapse; margin: 12px 0; font-size: 0.92rem; }}
th, td {{ border: 1px solid var(--border); padding: 6px 10px; text-align: left; }}
th {{ background: #f3f4f6; }}
blockquote {{ margin: 12px 0; padding: 10px 14px; border-left: 4px solid var(--muted); background: #f3f4f6; border-radius: 0 6px 6px 0; }}
section.critical {{ border-left: 5px solid var(--crit); padding-left: 14px; }}
section.critical h2 {{ color: var(--crit); border-color: var(--crit); }}
section.critical blockquote {{ border-left-color: var(--crit); background: #fef2f2; }}
section.high {{ border-left: 5px solid var(--high); padding-left: 14px; }}
section.high h2 {{ color: var(--high); border-color: var(--high); }}
section.high blockquote {{ border-left-color: var(--high); background: #fff7ed; }}
section.medium {{ border-left: 5px solid var(--med); padding-left: 14px; }}
section.medium h2 {{ color: var(--med); border-color: var(--med); }}
section.medium blockquote {{ border-left-color: var(--med); background: #fffbeb; }}
section.other {{ padding-left: 14px; }}
section.ai-summary {{ background: #f8fafc; border: 1px solid #e2e8f0; border-left: 5px solid #6366f1; border-radius: 6px; padding: 16px 18px; margin: 20px 0 26px; }}
section.ai-summary h2 {{ color: #3730a3; border-color: #e0e7ff; margin-top: 0; padding-bottom: 8px; font-size: 1.2rem; }}
section.ai-summary p {{ color: #334155; font-size: 0.96rem; line-height: 1.65; margin-top: 8px; margin-bottom: 0; }}
.top-nav {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 18px; font-size: 0.9rem; }}
.top-nav a {{ color: #2563eb; text-decoration: none; }}
.top-nav a:hover {{ text-decoration: underline; }}
.archive-list {{ list-style: none; padding: 0; }}
.archive-list li {{ padding: 10px 0; border-bottom: 1px solid var(--border); }}
.archive-list a {{ color: #2563eb; text-decoration: none; font-weight: 500; }}
.archive-list a:hover {{ text-decoration: underline; }}
@media (max-width: 600px) {{
  .wrap {{ padding: 16px 12px 60px; }}
  h1 {{ font-size: 1.35rem; }}
  h2 {{ font-size: 1.1rem; }}
  table, th, td {{ font-size: 0.85rem; }}
}}
</style>
</head>
<body>
<div class="wrap">
  <div class="top-nav">
    <span>Private Security Reports</span>
    <a href="{nav_href}">{nav_label}</a>
  </div>
  {body}
</div>
</body>
</html>"""

SEVERITY_CLASS_MAP = [
    (re.compile(r"plain-english summary", re.IGNORECASE), "ai-summary"),
    (re.compile(r"critical", re.IGNORECASE), "critical"),
    (re.compile(r"high-severity", re.IGNORECASE), "high"),
    (re.compile(r"medium-severity", re.IGNORECASE), "medium"),
]

MD_EXTENSIONS = ["extra", "tables", "fenced_code", "sane_lists"]


def classify_heading(heading_text):
    for pattern, css_class in SEVERITY_CLASS_MAP:
        if pattern.search(heading_text):
            return css_class
    return "other"


def split_into_sections(md_text):
    """Split a markdown report on top-level (##) headings.
    Returns a list of (heading_text_or_None, section_markdown) tuples.
    The first chunk before any ## is heading_text=None."""
    lines = md_text.splitlines()
    sections = []
    current_heading = None
    current_lines = []
    for line in lines:
        if line.startswith("## "):
            sections.append((current_heading, "\n".join(current_lines)))
            current_heading = line[3:].strip()
            current_lines = []
        else:
            current_lines.append(line)
    sections.append((current_heading, "\n".join(current_lines)))
    return sections


def render_report_body(md_text):
    sections = split_into_sections(md_text)
    html_chunks = []
    for heading, section_md in sections:
        if not section_md.strip():
            continue
        section_html = markdown.markdown(section_md, extensions=MD_EXTENSIONS)
        if heading is None:
            html_chunks.append(section_html)
        else:
            css_class = classify_heading(heading)
            html_chunks.append(f'<section class="{css_class}">{section_html}</section>')
    return "\n".join(html_chunks)


def wrap_page(title, body_html, nav_href, nav_label):
    return PAGE_TEMPLATE.format(
        title=html.escape(title),
        body=body_html,
        nav_href=nav_href,
        nav_label=nav_label,
    )


def find_reports():
    files = sorted(glob.glob(os.path.join(REPORTS_DIR, "security_audit_*.md")))
    return files


def report_display_name(path):
    # e.g. security_audit_chopshaven.ca_2026-09-13_0300.md -> "chopshaven.ca 2026-09-13 03:00"
    base = os.path.basename(path)
    m = re.match(r"security_audit_(.+)_(\d{4}-\d{2}-\d{2})_(\d{4})\.md", base)
    if not m:
        return base
    domain, date, time_ = m.groups()
    return f"{domain}  {date} {time_[:2]}:{time_[2:]}"


def build():
    os.makedirs(SITE_DIR, exist_ok=True)
    archive_dir = os.path.join(SITE_DIR, ARCHIVE_SUBDIR)
    os.makedirs(archive_dir, exist_ok=True)

    reports = find_reports()
    if not reports:
        raise SystemExit(f"No reports found in {REPORTS_DIR}; run scanner.py first.")

    latest_path = reports[-1]
    with open(latest_path, "r", encoding="utf-8") as fh:
        latest_md = fh.read()

    # ---- index.html (latest report) ----
    body_html = render_report_body(latest_md)
    index_html = wrap_page(
        title=f"Security Report - {report_display_name(latest_path)}",
        body_html=body_html,
        nav_href="archive.html",
        nav_label="View past reports",
    )
    with open(os.path.join(SITE_DIR, "index.html"), "w", encoding="utf-8") as fh:
        fh.write(index_html)

    # ---- one HTML page per historical report ----
    archive_entries = []
    for path in reports:
        with open(path, "r", encoding="utf-8") as fh:
            md_text = fh.read()
        page_body = render_report_body(md_text)
        basename = os.path.splitext(os.path.basename(path))[0] + ".html"
        page_html = wrap_page(
            title=f"Security Report - {report_display_name(path)}",
            body_html=page_body,
            nav_href="../index.html",
            nav_label="Back to latest",
        )
        with open(os.path.join(archive_dir, basename), "w", encoding="utf-8") as fh:
            fh.write(page_html)
        archive_entries.append((report_display_name(path), f"{ARCHIVE_SUBDIR}/{basename}"))

    # ---- archive.html (index of all reports, newest first) ----
    archive_entries.reverse()
    list_items = "\n".join(
        f'<li><a href="{href}">{html.escape(name)}</a></li>' for name, href in archive_entries
    )
    archive_body = f'<h1>Report Archive</h1><ul class="archive-list">{list_items}</ul>'
    archive_html = wrap_page(
        title="Security Report Archive",
        body_html=archive_body,
        nav_href="index.html",
        nav_label="View latest report",
    )
    with open(os.path.join(SITE_DIR, "archive.html"), "w", encoding="utf-8") as fh:
        fh.write(archive_html)

    print(f"Site built in {SITE_DIR} from {len(reports)} reports. Latest: {latest_path}")


if __name__ == "__main__":
    build()
