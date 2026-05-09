#!/usr/bin/env python3
"""
OSS Supply Chain Risk — Executive Slide Deck Generator
======================================================
Companion to oss_risk_agent.py. Consumes the same `metrics` dict and produces
a 16:9 PowerPoint deck targeted at executive readers (CISO, VP Eng, business
owners). The deck complements the longer-form PDF report by surfacing only the
top-line findings, the active threats, and the prescription.

Usage (programmatic, called from oss_risk_agent.py):
    build_slide_deck(customer_name, metrics, "/tmp/report.pptx", regions=...)

Slide structure:
    1. Title
    2. Executive Summary  (4 KPI tiles)
    3. ⚠ Malicious Package Detected   (only when present)
    4. Risk by Category               (6 risk-tier cards)
    5. Blocked vs Approved · Ecosystem split
    6. Top Blocking Policies
    7. Compromised Package Families   (matches against a built-in registry)
    8. Regional Comparison            (multi-region only)
    9. Recommendations / JFrog Curation
"""

import datetime
from pptx import Presentation
from pptx.util import Inches, Pt, Emu
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.chart.data import CategoryChartData
from pptx.enum.chart import XL_CHART_TYPE, XL_LEGEND_POSITION, XL_LABEL_POSITION


# ─── Palette (mirrors the PDF) ────────────────────────────────────────────
RED       = RGBColor(0xE2, 0x4B, 0x4A)
RED_BG    = RGBColor(0xFC, 0xEB, 0xEB)
RED_DK    = RGBColor(0xA3, 0x2D, 0x2D)
GREEN     = RGBColor(0x1D, 0x9E, 0x75)
BLUE      = RGBColor(0x37, 0x8A, 0xDD)
BLUE_BG   = RGBColor(0xE6, 0xF1, 0xFB)
BLUE_DK   = RGBColor(0x18, 0x5F, 0xA5)
PURPLE    = RGBColor(0x53, 0x4A, 0xB7)
PURPLE_BG = RGBColor(0xEE, 0xED, 0xFE)
AMBER     = RGBColor(0xBA, 0x75, 0x17)
AMBER_BG  = RGBColor(0xFA, 0xEE, 0xDA)
ORANGE    = RGBColor(0xD8, 0x5A, 0x30)
TEAL      = RGBColor(0x0F, 0x6E, 0x56)
TEAL_BG   = RGBColor(0xE1, 0xF5, 0xEE)
GRAY      = RGBColor(0x88, 0x87, 0x80)
GRAY_BG   = RGBColor(0xF1, 0xEF, 0xE8)
GRAY_DK   = RGBColor(0x5F, 0x5E, 0x5A)
NEAR_BLK  = RGBColor(0x2C, 0x2C, 0x2A)
WHITE     = RGBColor(0xFF, 0xFF, 0xFF)
PAGE_BG   = RGBColor(0xF8, 0xF7, 0xF4)
RULE      = RGBColor(0xD3, 0xD1, 0xC7)


# ─── Compromised package registry (curated list of known attack families) ──
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


# ─── Geometry helpers ─────────────────────────────────────────────────────
SLIDE_W  = Inches(13.333)   # 16:9
SLIDE_H  = Inches(7.5)
MARGIN_X = Inches(0.5)
MARGIN_Y = Inches(0.45)


def _set_fill(shape, rgb):
    shape.fill.solid()
    shape.fill.fore_color.rgb = rgb

def _no_line(shape):
    shape.line.fill.background()

def _set_line(shape, rgb, w=Pt(0.75)):
    shape.line.color.rgb = rgb
    shape.line.width = w

def _add_textbox(slide, x, y, w, h, text, *,
                 size=11, bold=False, italic=False,
                 color=NEAR_BLK, align=PP_ALIGN.LEFT,
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

def _add_rect(slide, x, y, w, h, fill=PAGE_BG, line=None):
    s = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, x, y, w, h)
    s.adjustments[0] = 0.06
    _set_fill(s, fill)
    if line is None:
        _no_line(s)
    else:
        _set_line(s, line)
    s.shadow.inherit = False
    return s

def _add_rich(slide, x, y, w, h, runs, *, align=PP_ALIGN.LEFT,
              anchor=MSO_ANCHOR.TOP, line_spacing=1.15):
    """runs = list of dicts: {text, size, bold, italic, color, font}"""
    tb = slide.shapes.add_textbox(x, y, w, h)
    tf = tb.text_frame
    tf.word_wrap = True
    tf.margin_left = tf.margin_right = Inches(0.05)
    tf.margin_top  = tf.margin_bottom = Inches(0.02)
    tf.vertical_anchor = anchor
    first = True
    for run in runs:
        if run.get("br") and not first:
            p = tf.add_paragraph()
        elif first:
            p = tf.paragraphs[0]
        else:
            p = tf.paragraphs[-1] if not run.get("newpara") else tf.add_paragraph()
        p.alignment = align
        if run.get("line_spacing"):
            p.line_spacing = run["line_spacing"]
        else:
            p.line_spacing = line_spacing
        r = p.add_run()
        r.text = run.get("text", "")
        r.font.name = run.get("font", "Helvetica")
        r.font.size = Pt(run.get("size", 11))
        r.font.bold = run.get("bold", False)
        r.font.italic = run.get("italic", False)
        r.font.color.rgb = run.get("color", NEAR_BLK)
        first = False
    return tb


def _add_footer(slide, customer_name, page_no, total_pages, date_range):
    # Bottom rule
    line = slide.shapes.add_connector(1, MARGIN_X, Inches(7.05),
                                      SLIDE_W - MARGIN_X, Inches(7.05))
    line.line.color.rgb = RULE
    line.line.width = Pt(0.5)
    _add_textbox(slide, MARGIN_X, Inches(7.10),
                 Inches(9), Inches(0.3),
                 f"{customer_name}  ·  OSS Supply Chain Risk Assessment  ·  {date_range}",
                 size=8, color=GRAY)
    _add_textbox(slide, SLIDE_W - MARGIN_X - Inches(2),
                 Inches(7.10), Inches(2), Inches(0.3),
                 f"Page {page_no} of {total_pages}",
                 size=8, color=GRAY, align=PP_ALIGN.RIGHT)


def _add_slide_header(slide, eyebrow, title):
    _add_textbox(slide, MARGIN_X, Inches(0.35),
                 SLIDE_W - 2*MARGIN_X, Inches(0.3),
                 eyebrow.upper(), size=9, bold=True, color=PURPLE,
                 font="Helvetica")
    _add_textbox(slide, MARGIN_X, Inches(0.65),
                 SLIDE_W - 2*MARGIN_X, Inches(0.6),
                 title, size=22, bold=True, color=NEAR_BLK)
    line = slide.shapes.add_connector(1, MARGIN_X, Inches(1.30),
                                      SLIDE_W - MARGIN_X, Inches(1.30))
    line.line.color.rgb = RULE
    line.line.width = Pt(0.5)


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  SLIDE 1: TITLE                                                          ║
# ╚══════════════════════════════════════════════════════════════════════════╝
def _slide_title(prs, customer_name, m, regions):
    s = prs.slides.add_slide(prs.slide_layouts[6])  # blank
    # Background
    bg = s.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, SLIDE_W, SLIDE_H)
    _set_fill(bg, NEAR_BLK)
    _no_line(bg)
    # Accent bar
    accent = s.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, Inches(3.2),
                                Inches(0.2), Inches(1.4))
    _set_fill(accent, PURPLE)
    _no_line(accent)

    _add_textbox(s, Inches(0.5), Inches(2.1), Inches(12), Inches(0.4),
                 "OSS PACKAGE & SOFTWARE SUPPLY CHAIN RISK ASSESSMENT",
                 size=12, bold=True, color=PURPLE)
    _add_textbox(s, Inches(0.5), Inches(2.6), Inches(12), Inches(1.2),
                 customer_name, size=44, bold=True, color=WHITE)

    subtitle = ("Global aggregated assessment" if regions else
                "Curation analysis report")
    if regions and len(regions) > 1:
        subtitle += f"  ·  {len(regions)} regions"
    _add_textbox(s, Inches(0.5), Inches(3.9), Inches(12), Inches(0.5),
                 subtitle, size=18, color=GRAY)

    # Stats strip
    date_range = f"{m['date_start']} – {m['date_end']}"
    stats = [
        (f"{m['total_log_entries']:,}", "Log entries"),
        (f"{m['total_blocked']:,}",     "Risky packages flagged"),
        (f"{m['blocked_pct']}%",        "Block rate"),
        (date_range,                    "Reporting window"),
    ]
    col_w = Inches(2.95)
    base_x = Inches(0.5)
    for i, (val, lbl) in enumerate(stats):
        x = base_x + col_w * i
        _add_textbox(s, x, Inches(5.2), col_w, Inches(0.6),
                     val, size=22 if i != 3 else 14, bold=True, color=WHITE)
        _add_textbox(s, x, Inches(5.85), col_w, Inches(0.4),
                     lbl, size=10, color=GRAY)

    _add_textbox(s, Inches(0.5), Inches(6.7), Inches(12), Inches(0.4),
                 f"Generated {datetime.date.today().strftime('%d %b %Y')}  ·  "
                 f"Powered by JFrog Curation",
                 size=9, color=GRAY)


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  SLIDE 2: EXECUTIVE SUMMARY                                              ║
# ╚══════════════════════════════════════════════════════════════════════════╝
def _slide_executive_summary(prs, customer_name, m, regions, mal_count):
    s = prs.slides.add_slide(prs.slide_layouts[6])
    _add_slide_header(s, "01 · Executive Summary", "Top-line findings")

    imm_total = m["cat_imm2d"] + m["cat_imm14d"] + m["cat_imm30d"]
    cat_eol   = m.get("cat_eol", 0)

    body_runs = [
        {"text": f"This assessment quantifies {customer_name}'s ", "size": 13},
        {"text": "OSS supply chain risk", "size": 13, "bold": True},
        {"text": f" exposure based on package request activity observed between "
                 f"{m['date_start']} and {m['date_end']}", "size": 13},
        {"text": (f", aggregated across {len(regions)} regional business units"
                  if regions and len(regions) > 1 else ""), "size": 13},
        {"text": ".", "size": 13},
        {"newpara": True, "text": " ", "size": 4},
        {"newpara": True,
         "text": f"Across {m['total_log_entries']:,} log entries, "
                 f"{m['total_blocked']:,} unique package versions were flagged as risky — "
                 f"a {m['blocked_pct']}% block rate against all classified packages — spanning ",
         "size": 13},
    ]
    if mal_count:
        body_runs += [
            {"text": f"{mal_count} confirmed malicious package request"
                     f"{'s' if mal_count != 1 else ''}",
             "size": 13, "bold": True, "color": RED_DK},
            {"text": ", followed by ", "size": 13},
        ]
    body_runs += [
        {"text": "critical CVEs (CVSS 9–10), license-restricted components, and ",
         "size": 13},
        {"text": f"{imm_total:,} immature packages",
         "size": 13, "bold": True},
        {"text": " requested less than 30 days after publication.", "size": 13},
    ]

    _add_rich(s, MARGIN_X, Inches(1.5),
              SLIDE_W - 2*MARGIN_X, Inches(1.9),
              body_runs)

    # KPI tiles
    tiles = [
        (f"{m['total_blocked']:,}",  "Blocked",     RED_BG,    RED_DK),
        (f"{m['total_approved']:,}", "Approved",    TEAL_BG,   TEAL),
        (f"{cat_eol:,}",             "Aged / EOL",  GRAY_BG,   GRAY_DK),
        (f"{imm_total:,}",           "Immature\n< 30 days", AMBER_BG, AMBER),
    ]
    tile_w = Inches(2.95)
    tile_h = Inches(1.7)
    base_x = Inches(0.5)
    base_y = Inches(4.0)
    for i, (val, lbl, bg, fg) in enumerate(tiles):
        x = base_x + tile_w * i + Inches(0.05) * i
        _add_rect(s, x, base_y, tile_w, tile_h, fill=bg)
        _add_textbox(s, x, base_y + Inches(0.25), tile_w, Inches(0.4),
                     lbl.split("\n")[0], size=11, bold=True, color=fg,
                     align=PP_ALIGN.CENTER)
        _add_textbox(s, x, base_y + Inches(0.55), tile_w, Inches(0.85),
                     val, size=32, bold=True, color=fg,
                     align=PP_ALIGN.CENTER, anchor=MSO_ANCHOR.MIDDLE)
        if "\n" in lbl:
            _add_textbox(s, x, base_y + tile_h - Inches(0.45),
                         tile_w, Inches(0.35),
                         lbl.split("\n", 1)[1], size=9, italic=True, color=fg,
                         align=PP_ALIGN.CENTER)


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  SLIDE: MALICIOUS PACKAGE ALERT                                          ║
# ╚══════════════════════════════════════════════════════════════════════════╝
def _slide_malicious(prs, customer_name, m, mal_pkgs):
    s = prs.slides.add_slide(prs.slide_layouts[6])
    _add_slide_header(s, "02 · Critical Finding",
                      "Malicious Package Download Detected")

    # Red alert banner
    _add_rect(s, MARGIN_X, Inches(1.5),
              SLIDE_W - 2*MARGIN_X, Inches(0.65),
              fill=RED_BG, line=RED_DK)
    _add_textbox(s, MARGIN_X + Inches(0.2), Inches(1.55),
                 SLIDE_W - 2*MARGIN_X - Inches(0.4), Inches(0.55),
                 f"⚠  {len(mal_pkgs)} confirmed malicious package "
                 f"request{'s' if len(mal_pkgs) != 1 else ''} reached "
                 f"{customer_name}'s perimeter during the reporting window.",
                 size=14, bold=True, color=RED_DK,
                 anchor=MSO_ANCHOR.MIDDLE)

    # Per-incident detail
    def _fmt_ts(ts):
        if not ts:
            return None
        try:
            dt = datetime.datetime.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S")
            return dt.strftime("%d %b %Y at %H:%M UTC")
        except Exception:
            return ts

    y = Inches(2.4)
    for p in mal_pkgs[:4]:
        _add_rect(s, MARGIN_X, y,
                  SLIDE_W - 2*MARGIN_X, Inches(0.7),
                  fill=PAGE_BG)
        runs = [
            {"text": f"{p['name']}@{p['version']} ",
             "size": 13, "bold": True, "color": NEAR_BLK},
            {"text": f"({p['eco']})", "size": 11, "color": GRAY_DK},
        ]
        details = []
        if p.get("region"):
            details.append(f"region: {p['region']}")
        ts_str = _fmt_ts(p.get("timestamp"))
        if ts_str:
            details.append(f"first seen: {ts_str}")
        if p.get("count"):
            details.append(f"{p['count']} attempt{'s' if p['count']!=1 else ''}")
        if details:
            runs.append({"text": "   ·   " + "  ·  ".join(details),
                         "size": 10, "color": GRAY_DK})
        _add_rich(s, MARGIN_X + Inches(0.2), y,
                  SLIDE_W - 2*MARGIN_X - Inches(0.4), Inches(0.7),
                  runs, anchor=MSO_ANCHOR.MIDDLE)
        y += Inches(0.85)

    # Closing pitch
    _add_rect(s, MARGIN_X, Inches(6.05),
              SLIDE_W - 2*MARGIN_X, Inches(0.85),
              fill=PURPLE_BG)
    _add_rich(s, MARGIN_X + Inches(0.2), Inches(6.10),
              SLIDE_W - 2*MARGIN_X - Inches(0.4), Inches(0.75),
              [
                  {"text": "Could have been prevented by JFrog Curation.  ",
                   "size": 12, "bold": True, "color": PURPLE},
                  {"text": "Inline policy enforcement at the package gateway "
                           "would have intercepted this request before it "
                           "reached the developer's environment.",
                   "size": 11, "color": GRAY_DK},
              ],
              anchor=MSO_ANCHOR.MIDDLE)


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  SLIDE: RISK BY CATEGORY                                                 ║
# ╚══════════════════════════════════════════════════════════════════════════╝
def _slide_risk_categories(prs, customer_name, m, slide_no):
    s = prs.slides.add_slide(prs.slide_layouts[6])
    _add_slide_header(s, f"{slide_no:02d} · Risk Categories",
                      "Blocked packages by risk tier — priority order")

    cats = [
        ("#1", m["cat_malicious"], "Malicious",     RED_BG,    RED_DK),
        ("#2", m["cat_imm2d"],     "Immature < 2d", AMBER_BG,  AMBER),
        ("#3", m["cat_crit_cve"],  "Critical CVE\n(CVSS 9–10)", RED_BG, RED_DK),
        ("#4", m["cat_imm14d"],    "Immature < 14d", AMBER_BG, AMBER),
        ("#5", m["cat_imm30d"],    "Immature < 30d", BLUE_BG,  BLUE_DK),
        ("#6", m.get("cat_eol",0), "Aged / EOL",     GRAY_BG,  GRAY_DK),
    ]
    card_w = Inches(2.0)
    card_h = Inches(2.0)
    spacing = Inches(0.10)
    base_x = (SLIDE_W - card_w * 6 - spacing * 5) / 2
    base_y = Inches(2.3)

    for i, (rank, val, lbl, bg, fg) in enumerate(cats):
        x = base_x + (card_w + spacing) * i
        _add_rect(s, x, base_y, card_w, card_h, fill=bg)
        _add_textbox(s, x, base_y + Inches(0.15), card_w, Inches(0.3),
                     rank, size=10, bold=True, color=GRAY_DK,
                     align=PP_ALIGN.CENTER)
        _add_textbox(s, x, base_y + Inches(0.5), card_w, Inches(0.85),
                     f"{val:,}", size=30, bold=True, color=fg,
                     align=PP_ALIGN.CENTER, anchor=MSO_ANCHOR.MIDDLE)
        _add_textbox(s, x, base_y + card_h - Inches(0.55),
                     card_w, Inches(0.5),
                     lbl, size=10, color=fg, bold=True,
                     align=PP_ALIGN.CENTER)

    _add_textbox(s, MARGIN_X, Inches(5.0),
                 SLIDE_W - 2*MARGIN_X, Inches(0.5),
                 "Counts represent unique package-version requests blocked by JFrog Curation policy. "
                 "Categories are ordered by severity and remediation priority.",
                 size=10, italic=True, color=GRAY_DK)


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  SLIDE: BLOCKED VS APPROVED  +  ECOSYSTEM                                ║
# ╚══════════════════════════════════════════════════════════════════════════╝
def _slide_block_vs_approved(prs, m, slide_no):
    s = prs.slides.add_slide(prs.slide_layouts[6])
    _add_slide_header(s, f"{slide_no:02d} · Block / Approve",
                      "Outcome distribution and ecosystem split")

    # Left side: donut/ratio
    _add_textbox(s, MARGIN_X, Inches(1.55), Inches(6), Inches(0.4),
                 "Outcome", size=11, bold=True, color=GRAY_DK)
    blocked_pct  = m["blocked_pct"]
    approved_pct = m["approved_pct"]

    # Big numbers
    _add_textbox(s, Inches(0.6), Inches(2.0), Inches(3), Inches(1.0),
                 f"{blocked_pct}%", size=46, bold=True, color=RED)
    _add_textbox(s, Inches(0.6), Inches(3.0), Inches(3), Inches(0.4),
                 f"blocked  ({m['total_blocked']:,})",
                 size=11, color=GRAY_DK)
    _add_textbox(s, Inches(3.6), Inches(2.0), Inches(3), Inches(1.0),
                 f"{approved_pct}%", size=46, bold=True, color=GREEN)
    _add_textbox(s, Inches(3.6), Inches(3.0), Inches(3), Inches(0.4),
                 f"approved  ({m['total_approved']:,})",
                 size=11, color=GRAY_DK)

    # Stacked bar
    bar_y = Inches(3.7)
    bar_total_w = Inches(6.0)
    bar_h = Inches(0.4)
    bar_x = Inches(0.6)
    blocked_w = Emu(int(int(bar_total_w) * (blocked_pct / 100)))
    blk = s.shapes.add_shape(MSO_SHAPE.RECTANGLE, bar_x, bar_y, blocked_w, bar_h)
    _set_fill(blk, RED); _no_line(blk)
    apr = s.shapes.add_shape(MSO_SHAPE.RECTANGLE, bar_x + blocked_w, bar_y,
                              bar_total_w - blocked_w, bar_h)
    _set_fill(apr, GREEN); _no_line(apr)

    # Right side: ecosystem chart
    _add_textbox(s, Inches(7.0), Inches(1.55), Inches(6), Inches(0.4),
                 "Blocked URLs by ecosystem", size=11, bold=True, color=GRAY_DK)
    eco_counts = m.get("ecosystem_counts")
    if eco_counts is not None and len(eco_counts) > 0:
        chart_data = CategoryChartData()
        labels = [str(k) for k in eco_counts.index][:6]
        values = [int(v) for v in eco_counts.values][:6]
        chart_data.categories = labels
        chart_data.add_series("Blocked", values)
        chart = s.shapes.add_chart(
            XL_CHART_TYPE.BAR_CLUSTERED,
            Inches(7.0), Inches(1.95),
            Inches(6.0), Inches(4.5),
            chart_data
        ).chart
        chart.has_title = False
        chart.has_legend = False
        plot = chart.plots[0]
        plot.has_data_labels = True
        plot.data_labels.font.size = Pt(10)
        plot.data_labels.font.color.rgb = NEAR_BLK
        # Color bars per ecosystem
        eco_colors = {"npm": BLUE, "maven": PURPLE, "go": GREEN,
                      "nuget": AMBER, "docker": ORANGE,
                      "pypi": RGBColor(0x63,0x99,0x22)}
        ser = plot.series[0]
        for idx, label in enumerate(labels):
            pt = ser.points[idx]
            pt.format.fill.solid()
            pt.format.fill.fore_color.rgb = eco_colors.get(label.lower(), GRAY)
            pt.format.line.fill.background()


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  SLIDE: TOP BLOCKING POLICIES                                            ║
# ╚══════════════════════════════════════════════════════════════════════════╝
def _slide_top_policies(prs, m, slide_no):
    s = prs.slides.add_slide(prs.slide_layouts[6])
    _add_slide_header(s, f"{slide_no:02d} · Policy Detail",
                      "Top blocking policies — raw event counts")

    pol = m.get("policy_counts")
    if pol is None or len(pol) == 0:
        _add_textbox(s, MARGIN_X, Inches(3.5),
                     SLIDE_W - 2*MARGIN_X, Inches(0.5),
                     "No policy data available in source files.",
                     size=12, color=GRAY_DK, align=PP_ALIGN.CENTER)
        return

    # Take top 8
    items = list(pol.items())[:8]
    items = [(str(k), int(v)) for k, v in items]

    chart_data = CategoryChartData()
    chart_data.categories = [k for k, _ in items][::-1]
    chart_data.add_series("Events", [v for _, v in items][::-1])

    chart = s.shapes.add_chart(
        XL_CHART_TYPE.BAR_CLUSTERED,
        Inches(0.7), Inches(1.6),
        SLIDE_W - Inches(1.4), Inches(5.0),
        chart_data
    ).chart
    chart.has_title = False
    chart.has_legend = False
    plot = chart.plots[0]
    plot.has_data_labels = True
    plot.data_labels.font.size = Pt(10)
    plot.data_labels.font.color.rgb = NEAR_BLK
    plot.data_labels.position = XL_LABEL_POSITION.OUTSIDE_END

    # Color top by purple, fade others to blue
    ser = plot.series[0]
    for idx, (k, _) in enumerate(items[::-1]):
        pt = ser.points[idx]
        pt.format.fill.solid()
        pt.format.fill.fore_color.rgb = PURPLE if "malicious" in k.lower() else BLUE
        pt.format.line.fill.background()


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  SLIDE: COMPROMISED PACKAGE FAMILIES                                     ║
# ╚══════════════════════════════════════════════════════════════════════════╝
def _detect_compromised(m):
    """Scan blocked + approved package data for known-attack package families."""
    findings = {}  # (pkg_name) → {eco, attack, severity, blocked_n, approved_n}

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

    # Two sources: imm2d/crit/malicious lists for blocked; raw approved list omitted
    # (we only have aggregated approved counts at this layer). To detect properly,
    # m may carry _all_blocked_records and _all_approved_records when populated by
    # the agent — we attempt both and fail gracefully.
    blocked_recs  = m.get("_compromise_scan_blocked")  or []
    approved_recs = m.get("_compromise_scan_approved") or []
    _walk(blocked_recs,  "blocked")
    _walk(approved_recs, "approved")
    return findings


def _slide_compromised(prs, customer_name, m, slide_no):
    findings = _detect_compromised(m)
    if not findings:
        return False  # no slide produced

    s = prs.slides.add_slide(prs.slide_layouts[6])
    _add_slide_header(s, f"{slide_no:02d} · Threat Intelligence",
                      "Known-attack package families observed")

    _add_textbox(s, MARGIN_X, Inches(1.5),
                 SLIDE_W - 2*MARGIN_X, Inches(0.6),
                 f"Packages observed in {customer_name}'s environment that are "
                 f"associated with major real-world OSS supply chain attacks.",
                 size=11, italic=True, color=GRAY_DK)

    # Group by attack
    by_attack = {}
    for name, f in findings.items():
        by_attack.setdefault(f["attack"], []).append((name, f))
    # Sort attacks: critical first, by total package count desc
    def _sev_key(items):
        crit = sum(1 for _, f in items if f["severity"] == "critical")
        return (-crit, -len(items))
    sorted_attacks = sorted(by_attack.items(),
                            key=lambda kv: _sev_key(kv[1]))

    # Header row
    hdr_y = Inches(2.15)
    cols = [
        ("Attack family",  Inches(0.5),  Inches(4.2)),
        ("Packages found", Inches(4.7),  Inches(5.6)),
        ("Blocked",        Inches(10.3), Inches(1.2)),
        ("Approved",       Inches(11.5), Inches(1.4)),
    ]
    for label, x, w in cols:
        _add_textbox(s, x, hdr_y, w, Inches(0.3),
                     label, size=10, bold=True, color=GRAY_DK)
    line = s.shapes.add_connector(1, MARGIN_X, hdr_y + Inches(0.32),
                                  SLIDE_W - MARGIN_X, hdr_y + Inches(0.32))
    line.line.color.rgb = RULE
    line.line.width = Pt(0.5)

    y = hdr_y + Inches(0.45)
    row_h = Inches(0.55)
    for attack, items in sorted_attacks[:8]:
        if y + row_h > Inches(6.7):
            break
        # severity color
        sev = items[0][1]["severity"]
        sev_color = RED_DK if sev == "critical" else (AMBER if sev == "high" else GRAY_DK)
        # attack name (with severity dot)
        dot = s.shapes.add_shape(MSO_SHAPE.OVAL,
                                  Inches(0.5), y + Inches(0.10),
                                  Inches(0.12), Inches(0.12))
        _set_fill(dot, sev_color); _no_line(dot)
        _add_textbox(s, Inches(0.7), y, Inches(4.0), Inches(0.5),
                     attack, size=10.5, bold=True, color=NEAR_BLK)

        # packages list
        names = ", ".join(sorted(n for n, _ in items)[:8])
        if len(items) > 8:
            names += f", +{len(items) - 8} more"
        _add_textbox(s, Inches(4.7), y, Inches(5.6), row_h,
                     names, size=9.5, color=GRAY_DK,
                     anchor=MSO_ANCHOR.TOP)

        blocked_total  = sum(f["blocked_n"]  for _, f in items)
        approved_total = sum(f["approved_n"] for _, f in items)
        _add_textbox(s, Inches(10.3), y, Inches(1.2), Inches(0.5),
                     f"{blocked_total:,}", size=11, bold=True, color=RED_DK)
        _add_textbox(s, Inches(11.5), y, Inches(1.4), Inches(0.5),
                     f"{approved_total:,}", size=11, bold=True,
                     color=AMBER if approved_total > 0 else GRAY_DK)

        # Row separator
        rule = s.shapes.add_connector(1,
            MARGIN_X, y + row_h,
            SLIDE_W - MARGIN_X, y + row_h)
        rule.line.color.rgb = RGBColor(0xE8, 0xE6, 0xDF)
        rule.line.width = Pt(0.25)
        y += row_h + Inches(0.05)

    # Footer note
    _add_textbox(s, MARGIN_X, Inches(6.85),
                 SLIDE_W - 2*MARGIN_X, Inches(0.3),
                 "Approved values > 0 indicate packages that passed curation — "
                 "these would be exposed to a future maintainer compromise of the same family.",
                 size=8.5, italic=True, color=GRAY_DK)
    return True


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  SLIDE: REGIONAL COMPARISON                                              ║
# ╚══════════════════════════════════════════════════════════════════════════╝
def _slide_regional(prs, customer_name, regions, slide_no):
    s = prs.slides.add_slide(prs.slide_layouts[6])
    _add_slide_header(s, f"{slide_no:02d} · Regional Breakdown",
                      "Block rate and volume by region")

    # Chart of total_blocked per region
    chart_data = CategoryChartData()
    chart_data.categories = [r[0] for r in regions]
    chart_data.add_series("Blocked", [r[1]["total_blocked"]  for r in regions])
    chart_data.add_series("Approved",[r[1]["total_approved"] for r in regions])

    chart = s.shapes.add_chart(
        XL_CHART_TYPE.BAR_STACKED,
        Inches(0.6), Inches(1.55),
        Inches(7.5), Inches(5.2),
        chart_data
    ).chart
    chart.has_title = False
    chart.has_legend = True
    chart.legend.position = XL_LEGEND_POSITION.BOTTOM
    chart.legend.include_in_layout = False
    plot = chart.plots[0]
    plot.has_data_labels = True
    plot.data_labels.font.size = Pt(9)
    chart.series[0].format.fill.solid()
    chart.series[0].format.fill.fore_color.rgb = RED
    chart.series[1].format.fill.solid()
    chart.series[1].format.fill.fore_color.rgb = GREEN

    # Right-side mini KPI table per region
    _add_textbox(s, Inches(8.4), Inches(1.55), Inches(4.5), Inches(0.4),
                 "Block rate by region", size=11, bold=True, color=GRAY_DK)
    y = Inches(2.0)
    for name, mr in regions:
        _add_rect(s, Inches(8.4), y, Inches(4.5), Inches(0.55), fill=PAGE_BG)
        _add_textbox(s, Inches(8.55), y, Inches(2.5), Inches(0.55),
                     name, size=11, bold=True, color=NEAR_BLK,
                     anchor=MSO_ANCHOR.MIDDLE)
        _add_textbox(s, Inches(11.0), y, Inches(1.85), Inches(0.55),
                     f"{mr['blocked_pct']}% blocked",
                     size=11, bold=True, color=RED_DK,
                     align=PP_ALIGN.RIGHT, anchor=MSO_ANCHOR.MIDDLE)
        y += Inches(0.65)


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  SLIDE: RECOMMENDATIONS                                                  ║
# ╚══════════════════════════════════════════════════════════════════════════╝
def _slide_recommendations(prs, customer_name, m, mal_count, slide_no):
    s = prs.slides.add_slide(prs.slide_layouts[6])
    _add_slide_header(s, f"{slide_no:02d} · Recommendation",
                      "Continuous protection with JFrog Curation")

    intro = (f"The findings above demonstrate that {customer_name}'s development "
             "environment is exposed to the full spectrum of modern OSS supply "
             "chain risk — from active malicious packages to the high-volume "
             "tail of immature, vulnerable, and abandoned dependencies."
             if mal_count else
             f"The findings above demonstrate that {customer_name}'s development "
             "environment is regularly exposed to high-volume OSS supply chain "
             "risk — including immature packages, critical vulnerabilities, "
             "and abandoned dependencies.")
    _add_textbox(s, MARGIN_X, Inches(1.5),
                 SLIDE_W - 2*MARGIN_X, Inches(1.0),
                 intro, size=12, color=GRAY_DK)

    # Three recommendation cards
    recs = [
        ("Block at the gateway",
         "Deploy JFrog Curation policies inline. Every package request is "
         "evaluated against maturity, vulnerability, license, and threat-intel "
         "criteria before it reaches a developer or build runner.",
         PURPLE, PURPLE_BG),
        ("Steer, don't reject",
         "When a request is blocked, Curation transparently surfaces the "
         "nearest safe, policy-compliant version of the same dependency — "
         "preserving developer velocity while eliminating the risky version.",
         BLUE_DK, BLUE_BG),
        ("Continuous baseline",
         "Re-run this assessment quarterly to track block-rate trend, "
         "confirm policy coverage of new ecosystems, and quantify risk "
         "reduction to the board.",
         TEAL, TEAL_BG),
    ]
    card_w = Inches(4.05)
    card_h = Inches(3.2)
    base_x = Inches(0.5)
    base_y = Inches(2.7)
    spacing = Inches(0.15)
    for i, (title, body, fg, bg) in enumerate(recs):
        x = base_x + (card_w + spacing) * i
        _add_rect(s, x, base_y, card_w, card_h, fill=bg)
        # accent bar
        accent = s.shapes.add_shape(MSO_SHAPE.RECTANGLE,
                                     x, base_y, Inches(0.08), card_h)
        _set_fill(accent, fg); _no_line(accent)
        _add_textbox(s, x + Inches(0.25), base_y + Inches(0.25),
                     card_w - Inches(0.4), Inches(0.5),
                     title, size=14, bold=True, color=fg)
        _add_textbox(s, x + Inches(0.25), base_y + Inches(0.85),
                     card_w - Inches(0.4), card_h - Inches(1.0),
                     body, size=11, color=GRAY_DK)

    # Closing CTA
    _add_textbox(s, MARGIN_X, Inches(6.3),
                 SLIDE_W - 2*MARGIN_X, Inches(0.4),
                 "Detailed package-level findings are available in the "
                 "accompanying PDF report.",
                 size=10, italic=True, color=GRAY_DK,
                 align=PP_ALIGN.CENTER)


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  PUBLIC API                                                              ║
# ╚══════════════════════════════════════════════════════════════════════════╝
def build_slide_deck(customer_name, m, output_path, regions=None,
                     compromise_blocked=None, compromise_approved=None):
    """
    Build the executive slide deck.

    Args:
        customer_name: display name
        m: aggregated metrics dict (same as PDF)
        output_path: .pptx output path
        regions: optional list of (region_name, metrics) tuples
        compromise_blocked / compromise_approved: lists of {name,version,eco,count}
            records used by the Compromised Package Families slide
    """
    print(f"  → Building slide deck: {output_path} …")

    # Stash compromise scan inputs into metrics dict for the slide builder
    if compromise_blocked is not None:
        m["_compromise_scan_blocked"] = compromise_blocked
    if compromise_approved is not None:
        m["_compromise_scan_approved"] = compromise_approved

    prs = Presentation()
    prs.slide_width  = SLIDE_W
    prs.slide_height = SLIDE_H

    mal_pkgs  = m.get("malicious_packages", []) or []
    mal_count = len(mal_pkgs)

    # Pre-count slides for footer pagination — generated lazily
    slide_specs = []  # list of (builder, args)
    slide_specs.append(("title", lambda p: _slide_title(p, customer_name, m, regions)))
    slide_specs.append(("exec",  lambda p: _slide_executive_summary(p, customer_name, m, regions, mal_count)))
    if mal_count:
        slide_specs.append(("malicious", lambda p: _slide_malicious(p, customer_name, m, mal_pkgs)))

    next_n = lambda: len([x for x in slide_specs if x[0] != "title"])
    # Numbering starts at 02 for the second slide; assign as we go.
    # (The slide title eyebrow shows the number — handled inside each builder.)

    n = 1
    # Title (no number eyebrow needed)
    slide_specs[0][1](prs); n += 1
    # Exec summary handles its own "01" eyebrow
    slide_specs[1][1](prs); n += 1
    idx_offset = 2
    if mal_count:
        slide_specs[2][1](prs); n += 1
        idx_offset += 1

    next_no = idx_offset  # will be 02 or 03 depending on malicious presence
    _slide_risk_categories(prs, customer_name, m, next_no);  next_no += 1
    _slide_block_vs_approved(prs, m, next_no);               next_no += 1
    _slide_top_policies(prs, m, next_no);                    next_no += 1
    if _slide_compromised(prs, customer_name, m, next_no):
        next_no += 1
    if regions and len(regions) > 1:
        _slide_regional(prs, customer_name, regions, next_no); next_no += 1
    _slide_recommendations(prs, customer_name, m, mal_count, next_no)

    # Footer pass — page number on every slide
    total = len(prs.slides)
    date_range = f"{m['date_start']} – {m['date_end']}"
    for i, sl in enumerate(prs.slides, start=1):
        if i == 1:
            continue  # skip title slide
        _add_footer(sl, customer_name, i, total, date_range)

    prs.save(output_path)
    print(f"  ✓ Slide deck written → {output_path}")
