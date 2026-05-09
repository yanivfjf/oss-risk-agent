#!/usr/bin/env python3
"""
OSS Supply Chain Risk — Executive Slide Deck Generator
======================================================
Companion to oss_risk_agent.py. Produces a 16:9 PowerPoint deck styled to
match the JFrog Security Healthcheck Analysis template — dark navy background,
green section titles, red "Findings - " accent, simple bullet layouts, and
a JFrog wordmark on every content slide.

Slides:
    1. Title                              (JFrog wordmark · customer · date)
    2. Purpose                            (why this analysis)
    3. Process                            (methodology / scope)
    4. Findings - Malicious Package       (only when present)
    5. Findings - Immature Packages
    6. Findings - Critical CVE
    7. Findings - Popular Targeted Packages
       (preserved from previous version — table grouping by attack family)
    8. Summary                            (recommendations / CTA)
"""

import datetime
from pptx import Presentation
from pptx.util import Inches, Pt, Emu
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR


# ─── Palette (JFrog template) ─────────────────────────────────────────────
NAVY        = RGBColor(0x0E, 0x21, 0x40)   # slide background
NAVY_DK     = RGBColor(0x09, 0x18, 0x30)
JFROG_GREEN = RGBColor(0x40, 0xBE, 0x46)   # title accent
RED         = RGBColor(0xE2, 0x4B, 0x4A)   # "- Section" subtitle
RED_DK      = RGBColor(0xA3, 0x2D, 0x2D)
WHITE       = RGBColor(0xFF, 0xFF, 0xFF)
BODY_FG     = RGBColor(0xE6, 0xEA, 0xF0)   # off-white body
MUTED       = RGBColor(0xA9, 0xB3, 0xC2)
LINK_BLUE   = RGBColor(0x6F, 0xC1, 0xFF)
AMBER       = RGBColor(0xF2, 0xA9, 0x4B)
GRAY        = RGBColor(0x88, 0x87, 0x80)


# ─── Compromised package registry ────────────────────────────────────────
# Entry: package_name → (ecosystem, attack_label, severity)
COMPROMISED_REGISTRY = {
    # --- Sept 2025 Qix / debug-chalk maintainer compromise ---
    "chalk":               ("npm", "Qix maintainer compromise (Sept 2025)", "critical"),
    "debug":               ("npm", "Qix maintainer compromise (Sept 2025)", "critical"),
    "ansi-styles":         ("npm", "Qix maintainer compromise (Sept 2025)", "critical"),
    "color-convert":       ("npm", "Qix maintainer compromise (Sept 2025)", "critical"),
    "color-name":          ("npm", "Qix maintainer compromise (Sept 2025)", "critical"),
    "color-string":        ("npm", "Qix maintainer compromise (Sept 2025)", "critical"),
    "error-ex":            ("npm", "Qix maintainer compromise (Sept 2025)", "critical"),
    "has-ansi":            ("npm", "Qix maintainer compromise (Sept 2025)", "critical"),
    "is-arrayish":         ("npm", "Qix maintainer compromise (Sept 2025)", "critical"),
    "simple-swizzle":      ("npm", "Qix maintainer compromise (Sept 2025)", "critical"),
    "slice-ansi":          ("npm", "Qix maintainer compromise (Sept 2025)", "critical"),
    "strip-ansi":          ("npm", "Qix maintainer compromise (Sept 2025)", "critical"),
    "supports-color":      ("npm", "Qix maintainer compromise (Sept 2025)", "critical"),
    "supports-hyperlinks": ("npm", "Qix maintainer compromise (Sept 2025)", "critical"),
    "wrap-ansi":           ("npm", "Qix maintainer compromise (Sept 2025)", "critical"),
    "ms":                  ("npm", "Qix maintainer compromise (Sept 2025)", "high"),
    "backslash":           ("npm", "Qix maintainer compromise (Sept 2025)", "high"),
    "chalk-template":      ("npm", "Qix maintainer compromise (Sept 2025)", "critical"),

    # --- Shai-Hulud worm (Sept 2025) ---
    "@ctrl/tinycolor":             ("npm", "Shai-Hulud worm (patient zero)", "critical"),
    "@ctrl/deluge":                ("npm", "Shai-Hulud worm", "critical"),
    "@ctrl/transmission":          ("npm", "Shai-Hulud worm", "critical"),
    "@ctrl/qbittorrent":           ("npm", "Shai-Hulud worm", "critical"),
    "@ctrl/magnet-link":           ("npm", "Shai-Hulud worm", "critical"),
    "@ctrl/golang-template":       ("npm", "Shai-Hulud worm", "critical"),
    "@ctrl/ngx-codemirror":        ("npm", "Shai-Hulud worm", "critical"),
    "@ctrl/ngx-csv":               ("npm", "Shai-Hulud worm", "critical"),
    "@ctrl/ngx-emoji-mart":        ("npm", "Shai-Hulud worm", "critical"),
    "@ctrl/ngx-rightclick":        ("npm", "Shai-Hulud worm", "critical"),
    "@ctrl/ngx-stripe":            ("npm", "Shai-Hulud worm", "critical"),
    "@ctrl/torrent-file":          ("npm", "Shai-Hulud worm", "critical"),
    "@ctrl/utorrent":              ("npm", "Shai-Hulud worm", "critical"),
    "ngx-bootstrap":               ("npm", "Shai-Hulud worm", "critical"),
    "ngx-toastr":                  ("npm", "Shai-Hulud worm", "critical"),
    "duckdb":                      ("npm", "Shai-Hulud worm", "critical"),
    "@duckdb/node-api":            ("npm", "Shai-Hulud worm", "critical"),
    "@duckdb/node-bindings":       ("npm", "Shai-Hulud worm", "critical"),
    "prettier-plugin-tailwindcss": ("npm", "Shai-Hulud worm", "critical"),
    "prettier-plugin-svelte":      ("npm", "Shai-Hulud worm", "critical"),
    "prettier-plugin-organize-imports": ("npm", "Shai-Hulud worm", "critical"),
    "eslint-config-prettier":      ("npm", "Shai-Hulud worm", "critical"),
    "eslint-plugin-prettier":      ("npm", "Shai-Hulud worm", "critical"),
    "eslint-plugin-react":         ("npm", "Shai-Hulud worm", "critical"),
    "eslint":                      ("npm", "Shai-Hulud worm", "critical"),
    "synckit":                     ("npm", "Shai-Hulud worm", "critical"),
    "@pkgr/core":                  ("npm", "Shai-Hulud worm", "critical"),
    "napi-postinstall":            ("npm", "Shai-Hulud worm (lateral vector)", "critical"),

    # --- Older famous npm compromises ---
    "ua-parser-js":  ("npm", "Maintainer hijack (Oct 2021)", "high"),
    "coa":           ("npm", "Maintainer compromise (Nov 2021)", "high"),
    "rc":            ("npm", "Maintainer compromise (Nov 2021)", "high"),
    "colors":        ("npm", "Marak sabotage (Jan 2022)",         "high"),
    "faker":         ("npm", "Marak sabotage (Jan 2022)",         "high"),
    "event-stream":  ("npm", "flatmap-stream backdoor (Nov 2018)","critical"),
    "node-ipc":      ("npm", "peacenotwar protestware (Mar 2022)","high"),
    "peacenotwar":   ("npm", "protestware (Mar 2022)",            "high"),
    "axios":         ("npm", "Recurring CVE chain (2024–2026)",   "high"),

    # --- PyPI ---
    "ctx":             ("pypi", "Maintainer takeover (May 2022)", "critical"),
    "phpass":          ("pypi", "Maintainer takeover (May 2022)", "critical"),
    "ultralytics":     ("pypi", "GH-action injection (Dec 2024)", "high"),
    "ultralytics-thop":("pypi", "GH-action injection (Dec 2024)", "high"),
    "litellm":         ("pypi", "CVE chain (RCE/SSRF, 2024–2026)","high"),
    "torchtriton":     ("pypi", "Dependency confusion (Dec 2022)","critical"),
    "colorama":        ("pypi", "Typosquat campaigns (ongoing)",  "low"),
}

# Per-malicious-package metadata used by the "Findings - Malicious Package" slide.
# Looked up by exact package name; falls back to generic copy when missing.
MALICIOUS_PACKAGE_META = {
    "sweetalert2": {
        "description": "Widely used JavaScript library for modal dialogs and UI elements",
        "advisory":    "https://github.com/advisories/GHSA-mrr8-v49w-3333",
        "version_published": {
            "11.7.32": "Oct 2023",
        },
    },
}


# ─── Geometry helpers ─────────────────────────────────────────────────────
SLIDE_W   = Inches(13.333)
SLIDE_H   = Inches(7.5)
MARGIN_X  = Inches(0.6)
TITLE_Y   = Inches(0.35)
BODY_Y    = Inches(1.5)
BODY_W    = SLIDE_W - 2 * MARGIN_X


def _set_fill(shape, rgb):
    shape.fill.solid()
    shape.fill.fore_color.rgb = rgb

def _no_line(shape):
    shape.line.fill.background()


def _add_textbox(slide, x, y, w, h, text, *,
                 size=14, bold=False, italic=False,
                 color=BODY_FG, align=PP_ALIGN.LEFT,
                 font="Helvetica", anchor=MSO_ANCHOR.TOP):
    tb = slide.shapes.add_textbox(x, y, w, h)
    tf = tb.text_frame
    tf.word_wrap = True
    tf.margin_left = tf.margin_right = Inches(0.05)
    tf.margin_top  = tf.margin_bottom = Inches(0.02)
    tf.vertical_anchor = anchor
    p = tf.paragraphs[0]
    p.alignment = align
    r = p.add_run()
    r.text = text
    r.font.name = font
    r.font.size = Pt(size)
    r.font.bold = bold
    r.font.italic = italic
    r.font.color.rgb = color
    return tb


def _add_navy_background(slide):
    """Fill the entire slide with the dark navy background."""
    bg = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, SLIDE_W, SLIDE_H)
    _set_fill(bg, NAVY)
    _no_line(bg)
    return bg


def _add_jfrog_wordmark(slide):
    """Bottom-right JFrog wordmark used on every content slide."""
    tb = slide.shapes.add_textbox(SLIDE_W - Inches(1.4), SLIDE_H - Inches(0.55),
                                  Inches(1.0), Inches(0.4))
    tf = tb.text_frame
    tf.margin_left = tf.margin_right = 0
    tf.margin_top  = tf.margin_bottom = 0
    p = tf.paragraphs[0]
    p.alignment = PP_ALIGN.RIGHT
    r = p.add_run()
    r.text = "JFrog"
    r.font.name = "Helvetica"
    r.font.size = Pt(14)
    r.font.bold = True
    r.font.color.rgb = JFROG_GREEN


def _add_title(slide, green_title, red_subtitle=None):
    """Standard slide title — green main + optional red dash subtitle."""
    tb = slide.shapes.add_textbox(MARGIN_X, TITLE_Y, BODY_W, Inches(0.85))
    tf = tb.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.alignment = PP_ALIGN.LEFT
    # green portion
    r = p.add_run()
    r.text = green_title
    r.font.name = "Helvetica"
    r.font.size = Pt(34)
    r.font.color.rgb = JFROG_GREEN
    # red dash subtitle
    if red_subtitle:
        r2 = p.add_run()
        r2.text = " - "
        r2.font.name = "Helvetica"
        r2.font.size = Pt(34)
        r2.font.color.rgb = WHITE
        r3 = p.add_run()
        r3.text = red_subtitle
        r3.font.name = "Helvetica"
        r3.font.size = Pt(34)
        r3.font.color.rgb = RED


def _bullet_paragraph(tf, text, *, indent=0, size=15,
                      color=BODY_FG, bold=False, italic=False,
                      font="Helvetica", first=False, mono=False,
                      runs=None):
    """Append one bulleted paragraph to a text frame.

    runs: optional list of dicts {text, color, bold, italic, mono, size} for
          rich inline styling within a single bullet.
    """
    p = tf.paragraphs[0] if first else tf.add_paragraph()
    p.alignment = PP_ALIGN.LEFT
    p.level = indent
    p.line_spacing = 1.25
    p.space_after = Pt(8)
    bullet_char = "●  " if indent == 0 else "○  "
    # Bullet glyph
    rb = p.add_run()
    rb.text = bullet_char
    rb.font.name = font
    rb.font.size = Pt(size)
    rb.font.color.rgb = WHITE if indent == 0 else MUTED

    if runs:
        for rd in runs:
            rr = p.add_run()
            rr.text = rd.get("text", "")
            rr.font.name = "Courier New" if rd.get("mono") else font
            rr.font.size = Pt(rd.get("size", size))
            rr.font.bold = rd.get("bold", bold)
            rr.font.italic = rd.get("italic", italic)
            rr.font.color.rgb = rd.get("color", color)
    else:
        rt = p.add_run()
        rt.text = text
        rt.font.name = "Courier New" if mono else font
        rt.font.size = Pt(size)
        rt.font.bold = bold
        rt.font.italic = italic
        rt.font.color.rgb = color


def _bullet_frame(slide, x=None, y=None, w=None, h=None):
    if x is None:
        x = MARGIN_X
    if y is None:
        y = BODY_Y + Inches(0.25)
    if w is None:
        w = BODY_W
    if h is None:
        h = SLIDE_H - y - Inches(0.7)
    tb = slide.shapes.add_textbox(x, y, w, h)
    tf = tb.text_frame
    tf.word_wrap = True
    tf.margin_left = tf.margin_right = Inches(0.05)
    tf.margin_top  = tf.margin_bottom = Inches(0.05)
    return tf


def _content_slide(prs, green_title, red_subtitle=None):
    """Common skeleton for every content slide."""
    s = prs.slides.add_slide(prs.slide_layouts[6])  # blank
    _add_navy_background(s)
    _add_title(s, green_title, red_subtitle)
    _add_jfrog_wordmark(s)
    return s


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  SLIDE 1: TITLE                                                          ║
# ╚══════════════════════════════════════════════════════════════════════════╝
def _slide_title(prs, customer_name, m, regions):
    s = prs.slides.add_slide(prs.slide_layouts[6])
    _add_navy_background(s)

    # JFrog wordmark (top, larger)
    tb = s.shapes.add_textbox(Inches(2.5), Inches(0.85),
                              Inches(3.5), Inches(1.0))
    tf = tb.text_frame
    p = tf.paragraphs[0]
    p.alignment = PP_ALIGN.CENTER
    r = p.add_run()
    r.text = "JFrog"
    r.font.name = "Helvetica"
    r.font.size = Pt(54)
    r.font.bold = True
    r.font.color.rgb = JFROG_GREEN

    # Customer wordmark (right of JFrog)
    tb2 = s.shapes.add_textbox(Inches(7.2), Inches(0.85),
                               Inches(4.0), Inches(1.0))
    tf2 = tb2.text_frame
    p2 = tf2.paragraphs[0]
    p2.alignment = PP_ALIGN.CENTER
    r2 = p2.add_run()
    r2.text = customer_name
    r2.font.name = "Helvetica"
    r2.font.size = Pt(40)
    r2.font.bold = True
    r2.font.color.rgb = WHITE

    # Big green title
    tb3 = s.shapes.add_textbox(Inches(0.5), Inches(2.8),
                               SLIDE_W - Inches(1.0), Inches(1.0))
    tf3 = tb3.text_frame
    p3 = tf3.paragraphs[0]
    p3.alignment = PP_ALIGN.CENTER
    r3 = p3.add_run()
    r3.text = "Software Supply Chain"
    r3.font.name = "Helvetica"
    r3.font.size = Pt(54)
    r3.font.bold = True
    r3.font.color.rgb = JFROG_GREEN

    # White subtitle
    tb4 = s.shapes.add_textbox(Inches(0.5), Inches(3.7),
                               SLIDE_W - Inches(1.0), Inches(0.8))
    tf4 = tb4.text_frame
    p4 = tf4.paragraphs[0]
    p4.alignment = PP_ALIGN.CENTER
    r4 = p4.add_run()
    r4.text = "Risk Analysis Report"
    r4.font.name = "Helvetica"
    r4.font.size = Pt(40)
    r4.font.color.rgb = WHITE

    # Date
    date_str = datetime.date.today().strftime("%-d %B %Y")
    tb5 = s.shapes.add_textbox(Inches(0.5), Inches(4.6),
                               SLIDE_W - Inches(1.0), Inches(0.5))
    tf5 = tb5.text_frame
    p5 = tf5.paragraphs[0]
    p5.alignment = PP_ALIGN.CENTER
    r5 = p5.add_run()
    r5.text = date_str
    r5.font.name = "Helvetica"
    r5.font.size = Pt(22)
    r5.font.color.rgb = WHITE


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  SLIDE 2: PURPOSE                                                        ║
# ╚══════════════════════════════════════════════════════════════════════════╝
def _slide_purpose(prs, customer_name):
    s = _content_slide(prs, "Purpose")
    tf = _bullet_frame(s)
    _bullet_paragraph(tf, "", first=True, runs=[
        {"text": "Dramatic increasing trend of Software Supply Chain attacks: "},
        {"text": "axios, bitwarden, xinference, checkmarx kics, teampcp, trivvy / litellm, qix, shai-hulud, big-red", "mono": True},
        {"text": " …"},
    ])
    _bullet_paragraph(tf,
        f"JFrog proactive approach to help {customer_name} identify incidents and "
        "susceptibility for breach")
    _bullet_paragraph(tf, "Prevent / derisk future risk")
    _bullet_paragraph(tf, "Customer approval")


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  SLIDE 3: PROCESS                                                        ║
# ╚══════════════════════════════════════════════════════════════════════════╝
def _slide_process(prs, m, regions):
    s = _content_slide(prs, "Process")
    tf = _bullet_frame(s)

    # Build region bullet text
    if regions and len(regions) > 1:
        region_names = ", ".join(r[0].replace(f"{regions[0][0][:9]}", "")
                                  .replace("santander", "")
                                  .strip("_- ").lower() or r[0]
                                  for r in regions)
        # Simplify: just suffixes if Santander-style names
        suffixes = []
        for rname, _ in regions:
            low = rname.lower()
            for prefix in ("santander",):
                if low.startswith(prefix):
                    low = low[len(prefix):]
            suffixes.append(low.strip("_- ") or rname)
        cloud_str = ", ".join(suffixes)
    else:
        cloud_str = regions[0][0] if regions else "global"

    _bullet_paragraph(tf, "", first=True, runs=[
        {"text": "One-off analysis of request logs (based on permission granted "},
        {"text": m.get("date_start", ""), "italic": True},
        {"text": ")"},
    ])
    _bullet_paragraph(tf, "All supported ecosystems (npm, pypi, maven, go, nuget, docker)")
    _bullet_paragraph(tf, "", runs=[
        {"text": "Cloud instances: "},
        {"text": cloud_str, "color": JFROG_GREEN, "italic": True},
    ])
    _bullet_paragraph(tf, "After-the-fact policy compliance checks on actual requested "
                          "packages from Artifactory:")
    _bullet_paragraph(tf, "Malicious Packages",                indent=1)
    _bullet_paragraph(tf, "Critical CVE (cvss +9.0)",          indent=1)
    _bullet_paragraph(tf, "Immature Packages <2days, <14days, <30days", indent=1)
    _bullet_paragraph(tf, "Aggregated number of policy-violating package requests "
                          "to quantify risk")


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  SLIDE 4: FINDINGS — MALICIOUS PACKAGE                                   ║
# ╚══════════════════════════════════════════════════════════════════════════╝
def _slide_malicious(prs, customer_name, m, mal_pkgs):
    s = _content_slide(prs, "Findings", "Malicious Package")
    tf = _bullet_frame(s)
    first = True

    def _fmt_ts(ts):
        if not ts:
            return None
        try:
            dt = datetime.datetime.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S")
            return dt.strftime("%-d-%b %H:%M UTC")
        except Exception:
            return ts

    for p in mal_pkgs[:3]:
        meta = MALICIOUS_PACKAGE_META.get(p["name"].lower(), {})

        # 1. Package@version (ecosystem)
        _bullet_paragraph(tf, "", first=first, runs=[
            {"text": f"{p['name']}@{p['version']}", "mono": True, "bold": True},
            {"text": f"  ({p['eco']})"},
        ])
        first = False

        # 2. Description
        if meta.get("description"):
            _bullet_paragraph(tf, meta["description"])

        # 3. Version published date
        pub = meta.get("version_published", {}).get(p["version"])
        if pub:
            _bullet_paragraph(tf, "", runs=[
                {"text": f"v{p['version']} published "},
                {"text": pub, "italic": True},
            ])

        # 4. Advisory link
        if meta.get("advisory"):
            _bullet_paragraph(tf, "", runs=[
                {"text": "Advisory: "},
                {"text": meta["advisory"], "color": LINK_BLUE},
            ])

        # 5. Download timestamp + region
        ts_str = _fmt_ts(p.get("timestamp"))
        region = p.get("region") or "unknown region"
        if ts_str:
            _bullet_paragraph(tf, "", runs=[
                {"text": f"Downloaded {ts_str} on "},
                {"text": region, "italic": True},
            ])
        else:
            _bullet_paragraph(tf, "", runs=[
                {"text": "Detected in "},
                {"text": region, "italic": True},
            ])


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  SLIDE 5: FINDINGS — IMMATURE PACKAGES                                   ║
# ╚══════════════════════════════════════════════════════════════════════════╝
def _slide_immature(prs, m):
    s = _content_slide(prs, "Findings", "Immature Packages")
    tf = _bullet_frame(s)
    imm_2d  = m.get("cat_imm2d",  0)
    imm_14d = m.get("cat_imm14d", 0)
    imm_30d = m.get("cat_imm30d", 0)

    # Pick a primary number to spotlight
    if imm_2d:
        _bullet_paragraph(tf, "", first=True, runs=[
            {"text": f"{imm_2d:,} immature packages < 2 days", "bold": True},
        ])
    elif imm_14d:
        _bullet_paragraph(tf, "", first=True, runs=[
            {"text": f"{imm_14d:,} immature packages < 14 days", "bold": True},
        ])
    elif imm_30d:
        _bullet_paragraph(tf, "", first=True, runs=[
            {"text": f"{imm_30d:,} immature packages < 30 days", "bold": True},
        ])
    else:
        _bullet_paragraph(tf, "No immature packages observed in this window.",
                          first=True)

    _bullet_paragraph(tf, "Acute and Least-visible threat")
    _bullet_paragraph(tf, "Newly published package version with not enough time "
                          "for the security community to assess its risk")
    _bullet_paragraph(tf, "", runs=[
        {"text": "Window of low visibility is the attack surface exploited by "
                 "campaigns such as "},
        {"text": "Shai-Hulud", "italic": True},
    ])

    # Supplementary detail when both 14d and 30d are present
    if imm_2d and (imm_14d or imm_30d):
        _bullet_paragraph(tf, "", runs=[
            {"text": "Wider windows: "},
            {"text": f"{imm_14d:,} packages < 14 days  ·  {imm_30d:,} packages < 30 days",
             "italic": True, "color": MUTED},
        ])


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  SLIDE 6: FINDINGS — CRITICAL CVE                                        ║
# ╚══════════════════════════════════════════════════════════════════════════╝
def _slide_critical_cve(prs, m):
    s = _content_slide(prs, "Findings", "Critical CVE")
    tf = _bullet_frame(s)
    crit = m.get("cat_crit_cve", 0)

    _bullet_paragraph(tf, "", first=True, runs=[
        {"text": f"{crit:,} packages which contain +9.0 CVSS - Critical CVE",
         "bold": True},
    ])
    _bullet_paragraph(tf, "High chance of exploitable vulnerability in runtime")
    _bullet_paragraph(tf, "Overwhelm vulnerability mgmt systems and require "
                          "triage resources")


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  SLIDE 7: FINDINGS — POPULAR TARGETED PACKAGES                           ║
# ║  (Preserved from previous version — table grouped by attack family)      ║
# ╚══════════════════════════════════════════════════════════════════════════╝
def _detect_compromised(m):
    findings = {}
    def _walk(records, kind):
        for r in records:
            name = r.get("name") or r.get("Package Name") or r.get("package_name")
            if not name:
                continue
            entry = COMPROMISED_REGISTRY.get(name)
            if not entry:
                continue
            eco, attack, sev = entry
            f = findings.setdefault(name, {
                "eco": eco, "attack": attack, "severity": sev,
                "blocked_n": 0, "approved_n": 0,
            })
            cnt = int(r.get("count", 0) or 0)
            if kind == "blocked":
                f["blocked_n"] += cnt
            else:
                f["approved_n"] += cnt
    _walk(m.get("_compromise_scan_blocked")  or [], "blocked")
    _walk(m.get("_compromise_scan_approved") or [], "approved")
    return findings


def _slide_popular_targeted(prs, customer_name, m):
    findings = _detect_compromised(m)
    if not findings:
        return False

    s = _content_slide(prs, "Findings", "Popular Targeted Packages")

    # Group by attack family
    by_attack = {}
    for name, f in findings.items():
        by_attack.setdefault(f["attack"], []).append((name, f))
    def _sev_key(items):
        crit = sum(1 for _, f in items if f["severity"] == "critical")
        return (-crit, -len(items))
    sorted_attacks = sorted(by_attack.items(), key=lambda kv: _sev_key(kv[1]))

    # Lead-in line
    total_pkgs = len(findings)
    _add_textbox(s, MARGIN_X, Inches(1.45),
                 BODY_W, Inches(0.45),
                 f"{total_pkgs} package families observed in {customer_name}'s "
                 f"environment that were targeted in major supply chain attacks:",
                 size=13, italic=True, color=MUTED)

    # Header row
    hdr_y = Inches(2.05)
    cols = [
        ("Attack family",  Inches(0.55), Inches(4.4)),
        ("Packages found", Inches(5.0),  Inches(5.4)),
        ("Blocked",        Inches(10.45), Inches(1.2)),
        ("Approved",       Inches(11.65), Inches(1.2)),
    ]
    for label, x, w in cols:
        _add_textbox(s, x, hdr_y, w, Inches(0.3), label,
                     size=11, bold=True, color=MUTED)
    line = s.shapes.add_connector(1, MARGIN_X, hdr_y + Inches(0.32),
                                  SLIDE_W - MARGIN_X, hdr_y + Inches(0.32))
    line.line.color.rgb = MUTED
    line.line.width = Pt(0.5)

    y = hdr_y + Inches(0.45)
    row_h = Inches(0.55)
    for attack, items in sorted_attacks[:8]:
        if y + row_h > Inches(6.6):
            break
        sev = items[0][1]["severity"]
        sev_color = RED if sev == "critical" else (AMBER if sev == "high" else MUTED)
        # severity dot
        dot = s.shapes.add_shape(MSO_SHAPE.OVAL,
                                  Inches(0.55), y + Inches(0.13),
                                  Inches(0.13), Inches(0.13))
        _set_fill(dot, sev_color); _no_line(dot)
        _add_textbox(s, Inches(0.78), y, Inches(4.2), row_h,
                     attack, size=11, bold=True, color=WHITE,
                     anchor=MSO_ANCHOR.MIDDLE)

        names = ", ".join(sorted(n for n, _ in items)[:8])
        if len(items) > 8:
            names += f", +{len(items) - 8} more"
        # monospace list of packages
        tb = s.shapes.add_textbox(Inches(5.0), y, Inches(5.4), row_h)
        tf = tb.text_frame
        tf.word_wrap = True
        tf.vertical_anchor = MSO_ANCHOR.MIDDLE
        p = tf.paragraphs[0]
        r = p.add_run()
        r.text = names
        r.font.name = "Courier New"
        r.font.size = Pt(10)
        r.font.color.rgb = BODY_FG

        blocked_total  = sum(f["blocked_n"]  for _, f in items)
        approved_total = sum(f["approved_n"] for _, f in items)
        _add_textbox(s, Inches(10.45), y, Inches(1.2), row_h,
                     f"{blocked_total:,}", size=12, bold=True, color=RED,
                     anchor=MSO_ANCHOR.MIDDLE)
        approved_color = AMBER if approved_total > 0 else MUTED
        _add_textbox(s, Inches(11.65), y, Inches(1.2), row_h,
                     f"{approved_total:,}", size=12, bold=True, color=approved_color,
                     anchor=MSO_ANCHOR.MIDDLE)

        rule = s.shapes.add_connector(1,
            MARGIN_X, y + row_h,
            SLIDE_W - MARGIN_X, y + row_h)
        rule.line.color.rgb = RGBColor(0x2A, 0x3A, 0x55)
        rule.line.width = Pt(0.25)
        y += row_h + Inches(0.05)

    _add_textbox(s, MARGIN_X, Inches(6.7),
                 BODY_W, Inches(0.4),
                 "Approved values > 0 indicate packages that passed curation — "
                 "these would be exposed to a future maintainer compromise of "
                 "the same family.",
                 size=9, italic=True, color=MUTED)
    return True


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  SLIDE 8: SUMMARY                                                        ║
# ╚══════════════════════════════════════════════════════════════════════════╝
def _slide_summary(prs, customer_name, m, mal_count):
    s = _content_slide(prs, "Summary")
    tf = _bullet_frame(s)
    first = True

    if mal_count:
        _bullet_paragraph(tf, "Investigate malicious usage", first=first)
        first = False

    _bullet_paragraph(tf, "", first=first, runs=[
        {"text": "Call to Action - Curation Policies:", "bold": True},
    ])
    first = False

    if mal_count:
        _bullet_paragraph(tf, "Blocking: Malicious", indent=1)
    _bullet_paragraph(tf, "Blocking: Immature <2days", indent=1)
    _bullet_paragraph(tf, "Dry-Run: CVE +9.0",          indent=1)
    _bullet_paragraph(tf, "Dry-Run: End-of-Life",       indent=1)

    if m.get("cat_eol", 0):
        _bullet_paragraph(tf, "", runs=[
            {"text": "Aged Packages:", "bold": True},
        ])
        _bullet_paragraph(tf, "Upgrade where new version exists",        indent=1)
        _bullet_paragraph(tf, "Replace where new version does not exist", indent=1)


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  PUBLIC API                                                              ║
# ╚══════════════════════════════════════════════════════════════════════════╝
def build_slide_deck(customer_name, m, output_path, regions=None,
                     compromise_blocked=None, compromise_approved=None):
    """Build the executive slide deck."""
    print(f"  → Building slide deck: {output_path} …")

    if compromise_blocked is not None:
        m["_compromise_scan_blocked"] = compromise_blocked
    if compromise_approved is not None:
        m["_compromise_scan_approved"] = compromise_approved

    prs = Presentation()
    prs.slide_width  = SLIDE_W
    prs.slide_height = SLIDE_H

    mal_pkgs  = m.get("malicious_packages", []) or []
    mal_count = len(mal_pkgs)

    _slide_title(prs, customer_name, m, regions)
    _slide_purpose(prs, customer_name)
    _slide_process(prs, m, regions)
    if mal_count:
        _slide_malicious(prs, customer_name, m, mal_pkgs)
    _slide_immature(prs, m)
    _slide_critical_cve(prs, m)
    _slide_popular_targeted(prs, customer_name, m)
    _slide_summary(prs, customer_name, m, mal_count)

    prs.save(output_path)
    print(f"  ✓ Slide deck written → {output_path}")
