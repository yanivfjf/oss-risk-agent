#!/usr/bin/env python3
"""
OSS Supply Chain Risk Report Agent
====================================
Accepts one or more curation-analysis tarballs, extracts and analyses the data,
and produces a fully-formatted PDF risk report.

Single tarball:
    python3 oss_risk_agent.py ACME_curation_analysis.tar.gz
    python3 oss_risk_agent.py ACME_curation_analysis.tar.gz --output /tmp/report.pdf

Aggregated report from multiple tarballs (same organisation, different regions):
    python3 oss_risk_agent.py EU.tar.gz LATAM.tar.gz MEXUS.tar.gz \
        --customer-name "Santander" --output /tmp/santander_global.pdf

Flags:
    --output / -o          Output PDF path
    --customer-name / -n   Override the customer display name
"""

import sys
import os
import re
import tarfile
import tempfile
import argparse
import datetime
import textwrap
from pathlib import Path

import pandas as pd

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, KeepTogether
)
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.platypus.flowables import Flowable

# ── Palette ──────────────────────────────────────────────────────────────────
RED      = colors.HexColor("#E24B4A")
RED_BG   = colors.HexColor("#FCEBEB")
RED_DARK = colors.HexColor("#A32D2D")
GREEN    = colors.HexColor("#1D9E75")
BLUE     = colors.HexColor("#378ADD")
BLUE_BG  = colors.HexColor("#E6F1FB")
BLUE_DK  = colors.HexColor("#185FA5")
PURPLE   = colors.HexColor("#534AB7")
PURPLE_BG= colors.HexColor("#EEEDFE")
AMBER    = colors.HexColor("#BA7517")
AMBER_BG = colors.HexColor("#FAEEDA")
ORANGE   = colors.HexColor("#D85A30")
TEAL     = colors.HexColor("#0F6E56")
TEAL_BG  = colors.HexColor("#E1F5EE")
GRAY     = colors.HexColor("#888780")
GRAY_BG  = colors.HexColor("#F1EFE8")
GRAY_DK  = colors.HexColor("#5F5E5A")
NEAR_BLK = colors.HexColor("#2C2C2A")
RULE     = colors.HexColor("#D3D1C7")

W, H   = A4
MARGIN = 20 * mm
CW     = W - 2 * MARGIN


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  STEP 1 — EXTRACT & PARSE                                               ║
# ╚══════════════════════════════════════════════════════════════════════════╝

def extract_tarball(tarball_path: str, work_dir: str) -> str:
    """Extract the tarball and return the path to the customer folder inside."""
    print(f"  → Extracting {tarball_path} …")
    with tarfile.open(tarball_path, "r:gz") as tf:
        tf.extractall(work_dir)

    # Find the top-level customer directory
    entries = [e for e in os.listdir(work_dir) if os.path.isdir(os.path.join(work_dir, e))]
    if not entries:
        raise FileNotFoundError("No directory found inside tarball.")
    customer_dir = os.path.join(work_dir, entries[0])
    print(f"  → Customer folder: {entries[0]}")
    return customer_dir


def parse_summary(summary_path: str) -> dict:
    """Parse the analysis_summary.txt into a dict of key→value."""
    data = {}
    if not os.path.exists(summary_path):
        return data
    with open(summary_path) as f:
        for line in f:
            line = line.strip()
            if ":" in line:
                key, _, val = line.partition(":")
                data[key.strip()] = val.strip()
    return data


def derive_customer_name(customer_dir: str, summary: dict) -> str:
    """Best-effort customer name from folder name or summary."""
    # Try summary first
    for key in ("Customer", "customer", "CUSTOMER"):
        if key in summary:
            return summary[key].strip()
    # Fall back to folder name, prettify it
    name = Path(customer_dir).name
    return name.replace("_", " ").title()


def load_data(customer_dir: str) -> dict:
    """Load all CSV files and return a dict of DataFrames."""
    print("  → Loading CSV files …")
    files = {
        "blocked":    os.path.join(customer_dir, "blocked_packages.csv"),
        "blocked_v2": os.path.join(customer_dir, "blocked_packages_v2.csv"),
        "approved":   os.path.join(customer_dir, "approved_packages.csv"),
        "unmatched":  os.path.join(customer_dir, "unmatched_urls.csv"),
    }
    dfs = {}
    for key, path in files.items():
        if os.path.exists(path):
            dfs[key] = pd.read_csv(path)
            print(f"     {key}: {len(dfs[key]):,} rows")
        else:
            print(f"     {key}: NOT FOUND — skipping")
            dfs[key] = pd.DataFrame()
    return dfs


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  STEP 2 — COMPUTE METRICS                                               ║
# ╚══════════════════════════════════════════════════════════════════════════╝

def compute_metrics(dfs: dict, summary: dict) -> dict:
    """Derive all numbers needed for the report."""
    print("  → Computing metrics …")
    blocked  = dfs["blocked"]
    approved = dfs["approved"]
    v2       = dfs["blocked_v2"]

    m = {}

    # ── totals ──────────────────────────────────────────────────────────
    def _int(val, fallback=0):
        try:
            return int(str(val).replace(",", "").strip())
        except (ValueError, TypeError):
            return fallback

    m["total_log_entries"] = _int(summary.get("Total log entries"), len(blocked) + len(approved))
    m["unique_urls"]       = _int(summary.get("Unique URLs", 0)) or None
    m["total_blocked"]     = len(blocked)
    m["total_approved"]    = len(approved)
    total_classified       = m["total_blocked"] + m["total_approved"]
    m["total_classified"]  = total_classified
    m["blocked_pct"]       = round(m["total_blocked"] / total_classified * 100, 1) if total_classified else 0
    m["approved_pct"]      = round(100 - m["blocked_pct"], 1)

    # ── date range ──────────────────────────────────────────────────────
    start = summary.get("Start", "")
    end   = summary.get("End",   "")
    def fmt_date(s):
        s = s.strip()
        for fmt in ("%Y-%m-%d %H:%M:%S %Z", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                return datetime.datetime.strptime(s, fmt).strftime("%-d %b %Y")
            except (ValueError, AttributeError):
                pass
        return s
    m["date_start"] = fmt_date(start) if start else "N/A"
    m["date_end"]   = fmt_date(end)   if end   else "N/A"
    duration_str    = summary.get("Duration", "")
    days_match      = re.search(r"(\d+)\s*day", duration_str)
    m["duration_days"] = int(days_match.group(1)) if days_match else "?"

    # ── category counts (unique packages from blocked.csv) ───────────────
    def count_policy(pattern):
        if blocked.empty or "Blocking Policies" not in blocked.columns:
            return 0
        return int(blocked["Blocking Policies"].str.contains(pattern, na=False).sum())

    m["cat_malicious"]   = count_policy(r"malicious|malware")
    m["cat_imm2d"]       = count_policy(r"block_immature_packages_2d")
    m["cat_crit_cve"]    = count_policy(r"cvss_9to10")
    m["cat_imm14d"]      = count_policy(r"block_immature_packages_14d")
    m["cat_imm30d"]      = count_policy(r"block_immature_packages_30d")
    m["cat_eol"]         = count_policy(r"eol|end.of.life")

    # ── breakdown by reason ─────────────────────────────────────────────
    m["reason_immature"] = count_policy(r"block_immature_packages")
    m["reason_aged"]     = count_policy(r"block_aged_package")
    m["reason_security"] = count_policy(r"block_cvss")
    m["reason_license"]  = count_policy(r"block_no_license|block_license_")

    # ── ecosystem breakdown ──────────────────────────────────────────────
    eco_col = "Package Type" if "Package Type" in blocked.columns else "package_type"
    if not blocked.empty and eco_col in blocked.columns:
        eco_counts = blocked[eco_col].value_counts()
    elif not v2.empty and "package_type" in v2.columns:
        eco_counts = v2["package_type"].value_counts()
    else:
        eco_counts = pd.Series(dtype=int)
    m["ecosystem_counts"] = eco_counts

    # ── top policies (from v2) ───────────────────────────────────────────
    if not v2.empty and "policy_name" in v2.columns:
        m["policy_counts"] = v2["policy_name"].value_counts().head(8)
    elif not blocked.empty and "Blocking Policies" in blocked.columns:
        all_policies = blocked["Blocking Policies"].str.split("|").explode().str.strip()
        m["policy_counts"] = all_policies.value_counts().head(8)
    else:
        m["policy_counts"] = pd.Series(dtype=int)

    # ── total v2 events ─────────────────────────────────────────────────
    m["total_v2_events"] = len(v2) if not v2.empty else 0

    # ── immature 2d package list ─────────────────────────────────────────
    if not blocked.empty and "Blocking Policies" in blocked.columns:
        imm2_mask = blocked["Blocking Policies"].str.contains("block_immature_packages_2d", na=False)
        pkg_col   = "Package Name"  if "Package Name"  in blocked.columns else "package_name"
        ver_col   = "Package Version" if "Package Version" in blocked.columns else "package_version"
        eco_col2  = "Package Type"  if "Package Type"  in blocked.columns else "package_type"
        cnt_col   = "Count"         if "Count"         in blocked.columns else "count"
        sub = blocked[imm2_mask][[pkg_col, ver_col, eco_col2, cnt_col]].sort_values(cnt_col, ascending=False)
        m["imm2d_packages"] = sub.rename(columns={pkg_col:"name", ver_col:"version", eco_col2:"eco", cnt_col:"count"}).to_dict("records")
    else:
        m["imm2d_packages"] = []

    # ── critical CVE package list ────────────────────────────────────────
    if not blocked.empty and "Blocking Policies" in blocked.columns:
        crit_mask = blocked["Blocking Policies"].str.contains("cvss_9to10", na=False)
        sub = blocked[crit_mask][[pkg_col, ver_col, eco_col2, cnt_col]].sort_values(cnt_col, ascending=False)
        m["crit_packages"] = sub.rename(columns={pkg_col:"name", ver_col:"version", eco_col2:"eco", cnt_col:"count"}).to_dict("records")
    else:
        m["crit_packages"] = []

    # ── imm2d note ───────────────────────────────────────────────────────
    # Try to detect dominant release batch (same version across many packages)
    imm2_pkgs = m["imm2d_packages"]
    if imm2_pkgs:
        ver_freq = {}
        for p in imm2_pkgs:
            ver_freq[p["version"]] = ver_freq.get(p["version"], 0) + 1
        top_ver, top_count = max(ver_freq.items(), key=lambda x: x[1])
        if top_count > 1:
            m["imm2d_note"] = (
                f"{top_count} of the {len(imm2_pkgs)} packages share version <b>{top_ver}</b>, "
                "indicating a coordinated batch release was pulled the same day it was published."
            )
        else:
            m["imm2d_note"] = ""
    else:
        m["imm2d_note"] = ""

    # ── crit CVE note ────────────────────────────────────────────────────
    crit_pkgs = m["crit_packages"]
    if crit_pkgs:
        name_freq = {}
        for p in crit_pkgs:
            name_freq[p["name"]] = name_freq.get(p["name"], 0) + 1
        repeats = sorted([(n, c) for n, c in name_freq.items() if c > 1], key=lambda x: -x[1])[:3]
        if repeats:
            repeat_str = ", ".join(f"<b>{n}</b> ({c} versions)" for n, c in repeats)
            m["crit_note"] = (
                f"Several packages appear across multiple versions, indicating developers are "
                f"actively trying different versions of known-vulnerable libraries. Key repeat "
                f"offenders include {repeat_str}."
            )
        else:
            m["crit_note"] = (
                f"The {len(crit_pkgs)} entries below were flagged due to critical severity "
                "vulnerabilities (CVSS 9–10)."
            )
    else:
        m["crit_note"] = ""

    return m


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  STEP 3 — PDF HELPERS                                                   ║
# ╚══════════════════════════════════════════════════════════════════════════╝

def plain():
    return ParagraphStyle("plain", fontName="Helvetica", fontSize=8,
                          textColor=NEAR_BLK, leading=11, spaceAfter=0)

def body_style():
    return ParagraphStyle("body", fontName="Helvetica", fontSize=8.5,
                          textColor=GRAY_DK, leading=13, spaceAfter=0)

def center_style():
    return ParagraphStyle("center", fontName="Helvetica", fontSize=8,
                          alignment=TA_CENTER, textColor=NEAR_BLK, leading=11)

def right_style():
    return ParagraphStyle("right", fontName="Helvetica", fontSize=8,
                          alignment=TA_RIGHT, textColor=GRAY_DK, leading=12)

def section_label(text):
    return Paragraph(
        f"<font size='7' color='#888780'><b>{text.upper()}</b></font>",
        ParagraphStyle("sl", fontName="Helvetica-Bold", fontSize=7,
                       textColor=GRAY, leading=10, spaceBefore=0, spaceAfter=0)
    )

def appendix_header(label, title):
    items = [
        Paragraph(f"<font size='9' color='#888780'>{label}</font>",
                  ParagraphStyle("al", fontName="Helvetica", fontSize=9, textColor=GRAY, leading=12)),
        Paragraph(f"<b>{title}</b>",
                  ParagraphStyle("at", fontName="Helvetica-Bold", fontSize=13,
                                 textColor=NEAR_BLK, leading=17, spaceBefore=2)),
        HRFlowable(width=CW, thickness=1, color=RULE, spaceBefore=8, spaceAfter=0),
    ]
    return KeepTogether(items)

def eco_cell(eco):
    eco = str(eco).lower()
    palette = {
        "npm":    (RED_BG, RED_DARK),
        "go":     (BLUE_BG, BLUE_DK),
        "maven":  (PURPLE_BG, PURPLE),
        "pypi":   (TEAL_BG, TEAL),
        "nuget":  (AMBER_BG, AMBER),
        "docker": (GRAY_BG, GRAY_DK),
    }
    bg, fg = palette.get(eco, (GRAY_BG, GRAY_DK))
    return Paragraph(
        f"<font size='7' color='{fg.hexval()}'><b>{eco}</b></font>",
        ParagraphStyle("eco", fontName="Helvetica-Bold", fontSize=7,
                       alignment=TA_CENTER, textColor=fg,
                       backColor=bg, leading=9, borderPadding=(2, 5, 2, 5))
    )

def pkg_hdr_row():
    s = ParagraphStyle("th", fontName="Helvetica-Bold", fontSize=7.5,
                       textColor=GRAY_DK, leading=10)
    return [Paragraph(t, s) for t in ["Package name", "Version", "Ecosystem", "Fetches"]]

def pkg_row(rec):
    name_p = Paragraph(f"<font size='8'>{rec['name']}</font>",
                       ParagraphStyle("pn", fontName="Helvetica", fontSize=8,
                                      textColor=NEAR_BLK, leading=10))
    ver_p  = Paragraph(f"<font size='7.5' color='#5F5E5A'>{rec['version']}</font>",
                       ParagraphStyle("pv", fontName="Helvetica", fontSize=7.5,
                                      textColor=GRAY_DK, leading=10))
    cnt_p  = Paragraph(f"<font size='8'>{rec['count']}</font>",
                       ParagraphStyle("pc", fontName="Helvetica", fontSize=8,
                                      alignment=TA_CENTER, textColor=NEAR_BLK, leading=10))
    return [name_p, ver_p, eco_cell(str(rec["eco"])), cnt_p]

def apply_pkg_table_style(tbl):
    tbl.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (-1, 0), GRAY_BG),
        ("LINEBELOW",    (0,0), (-1, 0), 0.75, RULE),
        ("LINEBELOW",    (0,1), (-1,-1), 0.3, colors.HexColor("#ECEAE3")),
        ("TOPPADDING",   (0,0), (-1,-1), 5),
        ("BOTTOMPADDING",(0,0), (-1,-1), 5),
        ("LEFTPADDING",  (0,0), (-1,-1), 6),
        ("RIGHTPADDING", (0,0), (-1,-1), 6),
        ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
        ("ROWBACKGROUNDS",(0,1),(-1,-1), [colors.white, colors.HexColor("#FAFAF8")]),
    ]))


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  STEP 4 — BUILD PDF SECTIONS                                            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

def build_ratio_panel(m: dict) -> Table:
    pw = CW * 0.44
    blocked_pct  = m["blocked_pct"]
    approved_pct = m["approved_pct"]

    num_data = [[
        Paragraph(f"<font size='20' color='#E24B4A'><b>{blocked_pct}%</b></font><br/>"
                  f"<font size='7' color='#888780'>blocked &nbsp;({m['total_blocked']:,})</font>", plain()),
        Paragraph(f"<font size='20' color='#1D9E75'><b>{approved_pct}%</b></font><br/>"
                  f"<font size='7' color='#888780'>approved &nbsp;({m['total_approved']:,})</font>", plain()),
    ]]
    nt = Table(num_data, colWidths=[pw*0.5, pw*0.5])
    nt.setStyle(TableStyle([
        ("LEFTPADDING",(0,0),(-1,-1),0), ("RIGHTPADDING",(0,0),(-1,-1),0),
        ("TOPPADDING",(0,0),(-1,-1),0),  ("BOTTOMPADDING",(0,0),(-1,-1),4),
        ("VALIGN",(0,0),(-1,-1),"TOP"),
    ]))

    bar_inner_w = pw - 20
    bar_d = Drawing(bar_inner_w, 16)
    bw = bar_inner_w * (blocked_pct / 100)
    bar_d.add(Rect(0, 1, bw, 14, fillColor=RED, strokeColor=None))
    bar_d.add(Rect(bw, 1, bar_inner_w - bw, 14, fillColor=GREEN, strokeColor=None))
    bar_d.add(String(bw/2, 5, f"{blocked_pct}%", fontSize=7, fillColor=colors.white,
                     textAnchor="middle", fontName="Helvetica-Bold"))
    bar_d.add(String(bw + (bar_inner_w-bw)/2, 5, f"{approved_pct}%", fontSize=7,
                     fillColor=colors.white, textAnchor="middle", fontName="Helvetica-Bold"))

    # Breakdown table — top 4 reasons by count
    reasons = [
        ("Immature",        m["reason_immature"]),
        ("Aged / outdated", m["reason_aged"]),
        ("Security (CVSS)", m["reason_security"]),
        ("License issues",  m["reason_license"]),
    ]
    total_b = m["total_blocked"] or 1
    hdr = [Paragraph("<font size='7' color='#888780'>Blocked reason</font>", plain()),
           Paragraph("<font size='7' color='#888780'>Count</font>", plain()),
           Paragraph("<font size='7' color='#888780'>%</font>", plain())]
    bt_inner_w = pw - 20
    rows = [hdr] + [
        [Paragraph(label, plain()),
         Paragraph(f"<font color='#2C2C2A'>{cnt:,}</font>", plain()),
         Paragraph(f"<font color='#185FA5'><b>{round(cnt/total_b*100)}%</b></font>", plain())]
        for label, cnt in reasons
    ]
    bt = Table(rows, colWidths=[bt_inner_w*0.56, bt_inner_w*0.24, bt_inner_w*0.20])
    bt.setStyle(TableStyle([
        ("LEFTPADDING",(0,0),(-1,-1),0),  ("RIGHTPADDING",(0,0),(-1,-1),0),
        ("TOPPADDING",(0,0),(-1,-1),4),   ("BOTTOMPADDING",(0,0),(-1,-1),4),
        ("LINEBELOW",(0,0),(-1,0),0.5,RULE),
        ("LINEBELOW",(0,1),(-1,-1),0.3,colors.HexColor("#E8E6DF")),
        ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
    ]))

    panel = Table([[nt],[bar_d],[bt]], colWidths=[pw])
    panel.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,-1),colors.HexColor("#F8F7F4")),
        ("ROUNDEDCORNERS",(0,0),(-1,-1),[6,6,6,6]),
        ("LEFTPADDING",(0,0),(-1,-1),10),  ("RIGHTPADDING",(0,0),(-1,-1),10),
        ("TOPPADDING",(0,0),(0,0),10),     ("BOTTOMPADDING",(0,-1),(-1,-1),10),
        ("TOPPADDING",(0,1),(-1,-1),4),    ("BOTTOMPADDING",(0,0),(-1,-2),4),
    ]))
    return panel


def build_ecosystem_panel(m: dict) -> Table:
    pw = CW * 0.52
    name_w_fixed  = 46
    count_w_fixed = 44
    share_w_fixed = 38
    bar_max = pw - name_w_fixed - count_w_fixed - share_w_fixed - 20

    eco_colours = {
        "maven":  PURPLE, "npm": BLUE, "go": GREEN,
        "nuget":  AMBER,  "docker": ORANGE, "pypi": colors.HexColor("#639922"),
    }
    eco_counts = m["ecosystem_counts"]
    max_count  = eco_counts.iloc[0] if len(eco_counts) else 1
    total_b    = m["total_blocked"] or 1

    rows = []
    for eco_name, cnt in eco_counts.items():
        clr  = eco_colours.get(str(eco_name).lower(), GRAY)
        bw   = max(3, bar_max * cnt / max_count)
        d    = Drawing(bar_max, 14)
        d.add(Rect(0, 2, bw, 10, fillColor=clr, strokeColor=None, rx=2))
        pct  = round(cnt / total_b * 100)
        rows.append([
            Paragraph(f"<font size='8' color='#2C2C2A'>{eco_name}</font>", plain()),
            d,
            Paragraph(f"<font size='8' color='#2C2C2A'>{cnt:,}</font>", plain()),
            Paragraph(f"<font size='8' color='#185FA5'><b>{pct}%</b></font>",
                      ParagraphStyle("rp", fontName="Helvetica-Bold", fontSize=8,
                                     alignment=TA_RIGHT, textColor=BLUE_DK, leading=10)),
        ])

    hdr = [
        Paragraph("<font size='7' color='#888780'>Ecosystem</font>", plain()),
        Paragraph("", plain()),
        Paragraph("<font size='7' color='#888780'>Blocked</font>", plain()),
        Paragraph("<font size='7' color='#888780'>Share</font>",
                  ParagraphStyle("rhdr", fontName="Helvetica", fontSize=7,
                                 alignment=TA_RIGHT, textColor=GRAY, leading=10)),
    ]
    top_eco   = eco_counts.index[0] if len(eco_counts) else "Maven"
    top_pct_v2 = round(eco_counts.iloc[0] / total_b * 100) if len(eco_counts) else 0
    note_para = Paragraph(
        f"<font size='7' color='#888780'>{top_eco} accounts for {top_pct_v2}% of all blocked packages.</font>",
        plain()
    )

    col_w = [name_w_fixed, bar_max, count_w_fixed, share_w_fixed]
    tbl_data = [hdr] + rows + [[note_para, "", "", ""]]
    eco_tbl = Table(tbl_data, colWidths=col_w)
    eco_tbl.setStyle(TableStyle([
        ("LEFTPADDING",(0,0),(-1,-1),0), ("RIGHTPADDING",(0,0),(-1,-1),0),
        ("TOPPADDING",(0,0),(-1,-1),5),  ("BOTTOMPADDING",(0,0),(-1,-1),5),
        ("LINEBELOW",(0,0),(-1,0),0.5,RULE),
        ("LINEBELOW",(0,1),(-1,-2),0.3,colors.HexColor("#E8E6DF")),
        ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
        ("SPAN",(0,-1),(-1,-1)),
        ("TOPPADDING",(0,-1),(-1,-1),8),
        ("BACKGROUND",(0,0),(-1,-1),colors.HexColor("#F8F7F4")),
        ("ROUNDEDCORNERS",(0,0),(-1,-1),[6,6,6,6]),
        ("LEFTPADDING",(0,0),(-1,-1),10), ("RIGHTPADDING",(0,0),(-1,-1),10),
        ("TOPPADDING",(0,0),(0,0),10),    ("BOTTOMPADDING",(0,-1),(-1,-1),10),
    ]))
    return eco_tbl


def build_bar_chart(m: dict) -> Drawing:
    policy_counts = m["policy_counts"]
    if policy_counts.empty:
        return Drawing(CW, 10)

    # Friendly label map
    label_map = {
        "block_immature_packages_30d":            "Immature > 30d",
        "block_aged_package_with_newer_version":  "Aged (newer exists)",
        "block_immature_packages_14d":            "Immature > 14d",
        "block_no_license":                       "No license",
        "block_cvss_7to9_with_or_without_fix_version": "CVSS 7–9 w/without fix",
        "block_cvss_7to9_with_fix_version":       "CVSS 7–9 with fix",
        "block_cvss_4to7_with_or_without_fix_version": "CVSS 4–7 w/without fix",
        "block_cvss_4to7_with_fix_version":       "CVSS 4–7 with fix",
        "block_aged_package_without_newer_version": "Aged (no newer version)",
        "block_image_not_offical_docker_hub":     "Unofficial Docker image",
        "block_license_GPL":                      "License: GPL",
        "block_license_LGPL":                     "License: LGPL",
        "block_license_AGPL":                     "License: AGPL",
        "block_immature_packages_2d":             "Immature > 2d",
        "block_cvss_9to10_with_fix_version":      "CVSS 9–10 with fix",
        "block_cvss_9to10_with_or_without_fix_version": "CVSS 9–10 w/without fix",
    }
    colour_map = {
        "block_immature_packages_30d": RED,
        "block_immature_packages_14d": RED,
        "block_immature_packages_2d":  RED,
        "block_aged_package_with_newer_version":  BLUE,
        "block_aged_package_without_newer_version": BLUE,
        "block_cvss_9to10_with_fix_version": colors.HexColor("#D85A30"),
        "block_cvss_9to10_with_or_without_fix_version": colors.HexColor("#D85A30"),
        "block_cvss_7to9_with_fix_version": colors.HexColor("#D85A30"),
        "block_cvss_7to9_with_or_without_fix_version": colors.HexColor("#D85A30"),
        "block_cvss_4to7_with_fix_version": colors.HexColor("#EF9F27"),
        "block_cvss_4to7_with_or_without_fix_version": colors.HexColor("#EF9F27"),
        "block_no_license": AMBER,
        "block_license_GPL": AMBER,
        "block_license_LGPL": AMBER,
        "block_license_AGPL": AMBER,
        "block_image_not_offical_docker_hub": GRAY,
    }

    policies = list(policy_counts.items())
    max_val  = policies[0][1] if policies else 1

    row_h    = 16
    chart_h  = len(policies) * row_h + 16
    label_w  = 145
    bar_area = CW - label_w - 60

    d = Drawing(CW, chart_h)
    for i, (name, val) in enumerate(reversed(policies)):
        y    = i * row_h + 8
        label = label_map.get(name, name.replace("block_", "").replace("_", " "))
        clr  = colour_map.get(name, GRAY)
        bw   = max(2, bar_area * val / max_val)
        d.add(String(label_w - 4, y + 3, label, fontSize=7.5, fillColor=GRAY_DK,
                     textAnchor="end", fontName="Helvetica"))
        d.add(Rect(label_w, y, bw, row_h - 4, fillColor=clr, strokeColor=None, rx=2))
        d.add(String(label_w + bw + 4, y + 3, f"{val:,}", fontSize=7,
                     fillColor=GRAY_DK, textAnchor="start", fontName="Helvetica"))
    return d


def build_pkg_table(pkg_list: list) -> Table:
    col_w = [CW*0.40, CW*0.32, CW*0.16, CW*0.12]
    rows  = [pkg_hdr_row()] + [pkg_row(p) for p in pkg_list]
    tbl   = Table(rows, colWidths=col_w, repeatRows=1)
    apply_pkg_table_style(tbl)
    return tbl


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  STEP 5 — ASSEMBLE PDF                                                  ║
# ╚══════════════════════════════════════════════════════════════════════════╝

def build_pdf(customer_name: str, m: dict, output_path: str, regions: list = None):
    print(f"  → Building PDF: {output_path} …")

    date_range  = f"{m['date_start']} – {m['date_end']}"
    header_meta = (
        f"{date_range} &nbsp;·&nbsp; {m['duration_days']} days"
        + (f" &nbsp;·&nbsp; {m['total_log_entries']:,} log entries" if m["total_log_entries"] else "")
    )
    footer_text = (
        f"OSS Package and Software Supply Chain Risk Analysis  ·  "
        f"{customer_name}  ·  {date_range}"
    )

    doc = SimpleDocTemplate(
        output_path, pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=16*mm, bottomMargin=18*mm,
        title=f"{customer_name}{' — Global' if regions else ''} — OSS Package and Software Supply Chain Risk Analysis",
        author="JFrog Curation Analysis"
    )

    def add_footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(GRAY)
        canvas.drawString(MARGIN, 14*mm, footer_text)
        canvas.drawRightString(W - MARGIN, 14*mm, f"Page {doc.page}")
        canvas.setStrokeColor(RULE)
        canvas.setLineWidth(0.5)
        canvas.line(MARGIN, 17*mm, W - MARGIN, 17*mm)
        canvas.restoreState()

    story = []

    # ── Page header ──────────────────────────────────────────────────────
    hdr_data = [[
        Paragraph(f"<font color='#2C2C2A' size='14'><b>{customer_name}</b></font><br/>"
                  f"<font color='#888780' size='8'>{'Global Aggregated Report  ·  ' if regions else ''}OSS Package and Software Supply Chain Risk Analysis</font>",
                  plain()),
        Paragraph(f"<font color='#888780' size='7'>{header_meta}</font><br/>"
                  f"<font color='#888780' size='7'>Generated: {datetime.date.today().strftime('%d %b %Y')}</font>",
                  right_style())
    ]]
    hdr_tbl = Table(hdr_data, colWidths=[CW*0.55, CW*0.45])
    hdr_tbl.setStyle(TableStyle([
        ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
        ("LEFTPADDING",(0,0),(-1,-1),0),  ("RIGHTPADDING",(0,0),(-1,-1),0),
        ("BOTTOMPADDING",(0,0),(-1,-1),8),("TOPPADDING",(0,0),(-1,-1),0),
    ]))
    story.append(hdr_tbl)
    story.append(HRFlowable(width=CW, thickness=1, color=RULE, spaceAfter=10))

    # ── Executive Summary ────────────────────────────────────────────────
    story.append(section_label("Executive Summary"))
    story.append(Spacer(1, 6))

    imm_total = m["cat_imm2d"] + m["cat_imm14d"] + m["cat_imm30d"]
    exec_text = (
        f"This report quantifies the current <b>open-source software (OSS) supply chain risk</b> exposure "
        f"within {customer_name}'s software development environment"
        + (f", aggregated across {len(regions)} regional business units" if regions else "")
        + f", based on package request activity observed "
        f"between {m['date_start']} and {m['date_end']}. Across {m['total_log_entries']:,} log entries, "
        f"<b>{m['total_blocked']:,} unique package versions</b> "
        f"were flagged as risky — a <b>{m['blocked_pct']}% block rate</b> against all classified packages — spanning "
        f"critical vulnerabilities (CVSS 9–10), license-restricted components, and, most prominently, "
        f"<b>{imm_total:,} immature package versions</b> that were less than 30 days old at the time of the request."
        "<br/><br/>"
        "Immature packages represent the most acute and least visible threat in the modern OSS supply chain. "
        "A newly published package version has not yet had the time to accumulate community scrutiny, "
        "security researcher analysis, or real-world validation. This window of low visibility is precisely "
        "the attack surface exploited by campaigns such as <b>Shai-Hulud</b> — a class of supply chain "
        "attack observed in the npm ecosystem in which threat actors publish malicious packages designed to "
        "mimic legitimate, widely-used libraries. These packages are engineered to be downloaded "
        "immediately after publication, before detection tools and human reviewers have had a chance to "
        f"identify them. With <b>{m['cat_imm2d']} packages which were downloaded within 2 days of release</b> and hundreds more within "
        f"14 days, this report illustrates that {customer_name}'s developers are actively pulling packages "
        "during exactly this high-risk window — at a scale and frequency that cannot be managed through "
        "manual review alone."
        "<br/><br/>"
        "Critically, <b>this risk is both measurable and preventable</b>. By implementing "
        f"<b>JFrog Curation Policies</b>, {customer_name} can automatically intercept and block risky package "
        "versions at the point of request — including packages published within a configurable maturity "
        "window — before they reach a developer's environment. Rather than simply rejecting a request, "
        "JFrog Curation steers the developer toward the nearest safe, policy-compliant version of the same "
        "dependency, preserving development velocity without introducing exposure. The result is a "
        "supply chain posture in which every OSS component is automatically validated against the "
        f"organisation's security, compliance, and maturity requirements — <b>protecting {customer_name} from "
        "the next Shai-Hulud without slowing down the engineers building its products</b>."
    )

    exec_box = Table(
        [[Paragraph(exec_text, ParagraphStyle("exec", fontName="Helvetica", fontSize=8.5,
                                              textColor=GRAY_DK, leading=13.5, spaceAfter=0))]],
        colWidths=[CW]
    )
    exec_box.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,-1),colors.HexColor("#F8F7F4")),
        ("ROUNDEDCORNERS",(0,0),(-1,-1),[6,6,6,6]),
        ("LEFTPADDING",(0,0),(-1,-1),14),  ("RIGHTPADDING",(0,0),(-1,-1),14),
        ("TOPPADDING",(0,0),(-1,-1),12),   ("BOTTOMPADDING",(0,0),(-1,-1),12),
        ("LINERIGHT",(0,0),(0,-1),3,colors.HexColor("#534AB7")),
    ]))
    story.append(exec_box)
    story.append(Spacer(1, 12))

    # ── Category metric cards ────────────────────────────────────────────
    story.append(section_label("Risky downloaded OSS packages by category (priority order)"))
    story.append(Spacer(1, 6))

    def _fmt(n): return f"{n:,}" if n else "0"
    cats = [
        ("#1", _fmt(m["cat_malicious"]), "Malicious\npackages",
         RED_BG, RED_DARK,
         "" if m["cat_malicious"] else "no policy active"),
        ("#2", _fmt(m["cat_imm2d"]),    "Immature\n< 2 days",   AMBER_BG, AMBER, ""),
        ("#3", _fmt(m["cat_crit_cve"]), "Critical CVE\n(CVSS 9–10)", RED_BG, RED_DARK, ""),
        ("#4", _fmt(m["cat_imm14d"]),   "Immature\n< 14 days",  AMBER_BG, AMBER, ""),
        ("#5", _fmt(m["cat_imm30d"]),   "Immature\n< 30 days",  BLUE_BG,  BLUE_DK, ""),
        ("#6", _fmt(m["cat_eol"]),      "End of life\npackages",
         GRAY_BG, GRAY_DK,
         "" if m["cat_eol"] else "no policy active"),
    ]
    card_w     = CW / 6 - 3
    card_cells = []
    for rank, val, lbl, bg, fg, note in cats:
        note_bit = f"<br/><font size='6' color='#888780'><i>{note}</i></font>" if note else ""
        card_cells.append(Paragraph(
            f"<font size='7' color='#B4B2A9'>{rank}</font><br/>"
            f"<font size='16' color='{fg.hexval()}'><b>{val}</b></font><br/>"
            f"<font size='7' color='{fg.hexval()}'>{lbl.replace(chr(10),' ')}</font>" + note_bit,
            center_style()
        ))
    card_tbl = Table([card_cells], colWidths=[card_w]*6, rowHeights=[62])
    card_style = [
        ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
        ("LEFTPADDING",(0,0),(-1,-1),4), ("RIGHTPADDING",(0,0),(-1,-1),4),
        ("TOPPADDING",(0,0),(-1,-1),6),  ("BOTTOMPADDING",(0,0),(-1,-1),6),
        ("ROUNDEDCORNERS",(0,0),(-1,-1),[4,4,4,4]),
    ]
    for i, cat in enumerate(cats):
        card_style.append(("BACKGROUND",(i,0),(i,0), cat[3]))
    card_tbl.setStyle(TableStyle(card_style))
    story.append(card_tbl)
    story.append(Spacer(1, 12))

    # ── Blocked vs Approved  +  Ecosystem breakdown ──────────────────────
    story.append(section_label("Blocked vs approved  ·  Blocked URLs by ecosystem"))
    story.append(Spacer(1, 6))
    mid_tbl = Table(
        [[build_ratio_panel(m), build_ecosystem_panel(m)]],
        colWidths=[CW*0.46, CW*0.52]
    )
    mid_tbl.setStyle(TableStyle([
        ("VALIGN",(0,0),(-1,-1),"TOP"),
        ("LEFTPADDING",(0,0),(-1,-1),0), ("RIGHTPADDING",(0,0),(-1,-1),0),
        ("TOPPADDING",(0,0),(-1,-1),0),  ("BOTTOMPADDING",(0,0),(-1,-1),0),
    ]))
    story.append(mid_tbl)
    story.append(Spacer(1, 12))

    # ── Top policies bar chart ───────────────────────────────────────────
    story.append(section_label("Top blocking policies — raw event counts"))
    story.append(Spacer(1, 6))
    story.append(build_bar_chart(m))
    story.append(Spacer(1, 8))
    story.append(Paragraph(
        f"<font size='7' color='#888780'>"
        f"Source: blocked_packages_v2.csv · {m['total_v2_events']:,} total block events · "
        f"All policies in live enforcement (dry_run=False)</font>",
        plain()
    ))

    # ── Appendix 1: Immature < 2d ────────────────────────────────────────
    story.append(PageBreak())
    story.append(appendix_header("Appendix 1", "Immature packages — downloaded within 2 days of release"))
    story.append(Spacer(1, 4))
    intro = (
        f"The {len(m['imm2d_packages'])} packages below were flagged because they were fetched "
        f"within 2 days of their public release. "
        + (m["imm2d_note"] if m["imm2d_note"] else "")
    )
    story.append(Paragraph(intro, body_style()))
    story.append(Spacer(1, 10))
    if m["imm2d_packages"]:
        story.append(build_pkg_table(m["imm2d_packages"]))
    else:
        story.append(Paragraph("No packages matched this category in the analysis period.", body_style()))
    story.append(Spacer(1, 8))
    story.append(Paragraph(
        f"<font size='7' color='#888780'>"
        f"Policy: block_immature_packages_2d · Period: {date_range}</font>",
        plain()
    ))

    # ── Appendix 2: Critical CVE ─────────────────────────────────────────
    story.append(PageBreak())
    story.append(appendix_header("Appendix 2", "Critical CVE packages — CVSS score 9.0–10.0"))
    story.append(Spacer(1, 4))
    intro2 = (
        f"The {len(m['crit_packages'])} entries below were blocked due to critical severity "
        f"vulnerabilities (CVSS 9–10). " + (m["crit_note"] if m["crit_note"] else "")
    )
    story.append(Paragraph(intro2, body_style()))
    story.append(Spacer(1, 10))
    if m["crit_packages"]:
        story.append(build_pkg_table(m["crit_packages"]))
    else:
        story.append(Paragraph("No packages matched this category in the analysis period.", body_style()))
    story.append(Spacer(1, 8))
    story.append(Paragraph(
        f"<font size='7' color='#888780'>"
        f"Policy: block_cvss_9to10_with_fix_version | block_cvss_9to10_with_or_without_fix_version "
        f"· Period: {date_range}</font>",
        plain()
    ))

    # ── Regional breakdown (multi-tarball only) ──────────────────────────
    if regions:
        build_region_breakdown_page(regions, story)

    doc.build(story, onFirstPage=add_footer, onLaterPages=add_footer)
    print(f"  ✓ PDF written → {output_path}")


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  AGGREGATION                                                            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

def aggregate_metrics(all_metrics: list) -> dict:
    """Merge a list of per-tarball metric dicts into one combined dict."""
    import functools

    def _sum(key):
        return sum(m.get(key, 0) for m in all_metrics)

    def _eco_merge():
        combined = {}
        for m in all_metrics:
            for eco, cnt in m["ecosystem_counts"].items():
                combined[eco] = combined.get(eco, 0) + cnt
        return pd.Series(combined).sort_values(ascending=False)

    def _policy_merge():
        combined = {}
        for m in all_metrics:
            for pol, cnt in m["policy_counts"].items():
                combined[pol] = combined.get(pol, 0) + cnt
        return pd.Series(combined).sort_values(ascending=False).head(8)

    def _earliest(key):
        vals = [m[key] for m in all_metrics if m.get(key) and m[key] != "N/A"]
        return vals[0] if vals else "N/A"

    def _latest(key):
        vals = [m[key] for m in all_metrics if m.get(key) and m[key] != "N/A"]
        return vals[-1] if vals else "N/A"

    def _merge_pkg_list(key):
        """Merge package lists across regions, deduplicate by (name, version), sum counts."""
        combined = {}
        for m in all_metrics:
            for p in m.get(key, []):
                k = (p["name"], p["version"], p["eco"])
                if k in combined:
                    combined[k]["count"] = combined[k]["count"] + p["count"]
                else:
                    combined[k] = dict(p)
        return sorted(combined.values(), key=lambda x: -x["count"])

    agg = {}
    agg["total_log_entries"] = _sum("total_log_entries")
    agg["total_blocked"]     = _sum("total_blocked")
    agg["total_approved"]    = _sum("total_approved")
    total_classified         = agg["total_blocked"] + agg["total_approved"]
    agg["total_classified"]  = total_classified
    agg["blocked_pct"]       = round(agg["total_blocked"] / total_classified * 100, 1) if total_classified else 0
    agg["approved_pct"]      = round(100 - agg["blocked_pct"], 1)
    agg["total_v2_events"]   = _sum("total_v2_events")
    agg["unique_urls"]       = None

    agg["cat_malicious"]  = _sum("cat_malicious")
    agg["cat_imm2d"]      = _sum("cat_imm2d")
    agg["cat_crit_cve"]   = _sum("cat_crit_cve")
    agg["cat_imm14d"]     = _sum("cat_imm14d")
    agg["cat_imm30d"]     = _sum("cat_imm30d")
    agg["cat_eol"]        = _sum("cat_eol")

    agg["reason_immature"] = _sum("reason_immature")
    agg["reason_aged"]     = _sum("reason_aged")
    agg["reason_security"] = _sum("reason_security")
    agg["reason_license"]  = _sum("reason_license")

    agg["ecosystem_counts"] = _eco_merge()
    agg["policy_counts"]    = _policy_merge()

    # Date range — use earliest start and latest end
    agg["date_start"]    = _earliest("date_start")
    agg["date_end"]      = _latest("date_end")
    agg["duration_days"] = max((m.get("duration_days", 0) for m in all_metrics), default="?")

    agg["imm2d_packages"] = _merge_pkg_list("imm2d_packages")
    agg["crit_packages"]  = _merge_pkg_list("crit_packages")

    # Regenerate notes for aggregated lists
    imm2_pkgs = agg["imm2d_packages"]
    if imm2_pkgs:
        ver_freq = {}
        for p in imm2_pkgs:
            ver_freq[p["version"]] = ver_freq.get(p["version"], 0) + 1
        top_ver, top_count = max(ver_freq.items(), key=lambda x: x[1])
        agg["imm2d_note"] = (
            f"{top_count} of the {len(imm2_pkgs)} packages share version <b>{top_ver}</b>, "
            "indicating a coordinated batch release was pulled the same day it was published."
        ) if top_count > 1 else ""
    else:
        agg["imm2d_note"] = ""

    crit_pkgs = agg["crit_packages"]
    if crit_pkgs:
        name_freq = {}
        for p in crit_pkgs:
            name_freq[p["name"]] = name_freq.get(p["name"], 0) + 1
        repeats = sorted([(n, c) for n, c in name_freq.items() if c > 1], key=lambda x: -x[1])[:3]
        agg["crit_note"] = (
            "Several packages appear across multiple versions and regions. Key repeat offenders include "
            + ", ".join(f"<b>{n}</b> ({c} entries)" for n, c in repeats) + "."
        ) if repeats else ""
    else:
        agg["crit_note"] = ""

    return agg


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  PER-REGION BREAKDOWN PAGE                                              ║
# ╚══════════════════════════════════════════════════════════════════════════╝

REGION_COLOURS = [
    colors.HexColor("#534AB7"),  # purple
    colors.HexColor("#185FA5"),  # blue
    colors.HexColor("#0F6E56"),  # teal
    colors.HexColor("#BA7517"),  # amber
    colors.HexColor("#D85A30"),  # orange
    colors.HexColor("#A32D2D"),  # red-dark
]

def build_region_breakdown_page(regions: list, story: list):
    """
    Append a full per-region comparison page to story.
    regions: list of (region_name, metrics_dict)
    """
    story.append(PageBreak())
    story.append(appendix_header("Regional Breakdown", "Per-region summary — all contributing data sources"))
    story.append(Spacer(1, 10))

    n = len(regions)

    # ── Summary comparison table ─────────────────────────────────────────
    hdr_style  = ParagraphStyle("rbh", fontName="Helvetica-Bold", fontSize=7.5,
                                textColor=GRAY_DK, leading=10)
    cell_style = ParagraphStyle("rbc", fontName="Helvetica", fontSize=8,
                                textColor=NEAR_BLK, leading=11)
    pct_style  = ParagraphStyle("rbp", fontName="Helvetica-Bold", fontSize=8,
                                textColor=BLUE_DK, leading=11)
    red_style  = ParagraphStyle("rbr", fontName="Helvetica-Bold", fontSize=8,
                                textColor=RED_DARK, leading=11)

    col_labels = ["Region", "Blocked", "Approved", "Block rate", "Imm <2d", "Crit CVE", "Imm <30d"]
    hdr_row    = [Paragraph(c, hdr_style) for c in col_labels]

    col_w_reg = [CW*0.26, CW*0.11, CW*0.11, CW*0.12, CW*0.11, CW*0.11, CW*0.18]

    data_rows = [hdr_row]
    for region_name, m in regions:
        data_rows.append([
            Paragraph(region_name, cell_style),
            Paragraph(f"{m['total_blocked']:,}", cell_style),
            Paragraph(f"{m['total_approved']:,}", cell_style),
            Paragraph(f"{m['blocked_pct']}%", red_style),
            Paragraph(f"{m['cat_imm2d']:,}", cell_style),
            Paragraph(f"{m['cat_crit_cve']:,}", cell_style),
            Paragraph(f"{m['cat_imm30d']:,}", cell_style),
        ])

    summary_tbl = Table(data_rows, colWidths=col_w_reg, repeatRows=1)
    summary_tbl.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (-1,0), GRAY_BG),
        ("LINEBELOW",    (0,0), (-1,0), 0.75, RULE),
        ("LINEBELOW",    (0,1), (-1,-1), 0.3, colors.HexColor("#ECEAE3")),
        ("TOPPADDING",   (0,0), (-1,-1), 5),
        ("BOTTOMPADDING",(0,0), (-1,-1), 5),
        ("LEFTPADDING",  (0,0), (-1,-1), 6),
        ("RIGHTPADDING", (0,0), (-1,-1), 6),
        ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white, colors.HexColor("#FAFAF8")]),
    ]))
    story.append(summary_tbl)
    story.append(Spacer(1, 18))

    # ── Per-region blocked bar charts (stacked horizontal) ───────────────
    story.append(section_label("Blocked packages by region — ecosystem distribution"))
    story.append(Spacer(1, 8))

    eco_colours_map = {
        "maven":  PURPLE, "npm": BLUE, "go": GREEN,
        "nuget":  AMBER,  "docker": ORANGE, "pypi": colors.HexColor("#639922"),
    }

    bar_h    = 14
    label_w  = 90
    bar_area = CW - label_w - 50
    row_gap  = 6

    chart_h = n * (bar_h + row_gap) + 10
    d = Drawing(CW, chart_h)

    all_total = max(sum(m["total_blocked"] for _, m in regions), 1)

    for i, (region_name, m) in enumerate(regions):
        y = (n - 1 - i) * (bar_h + row_gap) + 5
        # Region label
        d.add(String(label_w - 4, y + 3, region_name, fontSize=7.5, fillColor=GRAY_DK,
                     textAnchor="end", fontName="Helvetica"))
        # Stacked bar segments by ecosystem
        x_off = label_w
        eco_counts = m["ecosystem_counts"]
        total_b    = m["total_blocked"] or 1
        for eco_name, cnt in eco_counts.items():
            clr = eco_colours_map.get(str(eco_name).lower(), GRAY)
            seg_w = bar_area * cnt / all_total
            if seg_w >= 1:
                d.add(Rect(x_off, y, seg_w, bar_h, fillColor=clr, strokeColor=colors.white,
                           strokeWidth=0.5))
                x_off += seg_w
        # Total label
        d.add(String(x_off + 4, y + 3, f"{m['total_blocked']:,}", fontSize=7,
                     fillColor=GRAY_DK, textAnchor="start", fontName="Helvetica"))

    story.append(d)
    story.append(Spacer(1, 8))

    # Ecosystem legend
    legend_items = list(eco_colours_map.items())
    leg_data = [[
        Paragraph(
            f"<font size='8' color='{clr.hexval()}'>■</font> "
            f"<font size='7' color='#5F5E5A'>{eco}</font>",
            ParagraphStyle("leg", fontName="Helvetica", fontSize=7,
                           textColor=GRAY_DK, leading=10)
        )
        for eco, clr in legend_items
    ]]
    leg_tbl = Table(leg_data, colWidths=[CW / len(legend_items)] * len(legend_items))
    leg_tbl.setStyle(TableStyle([
        ("LEFTPADDING",(0,0),(-1,-1),0), ("RIGHTPADDING",(0,0),(-1,-1),4),
        ("TOPPADDING",(0,0),(-1,-1),0),  ("BOTTOMPADDING",(0,0),(-1,-1),0),
    ]))
    story.append(leg_tbl)
    story.append(Spacer(1, 18))

    # ── Block rate comparison bar ─────────────────────────────────────────
    story.append(section_label("Block rate by region"))
    story.append(Spacer(1, 8))

    br_h    = 14
    br_area = CW - label_w - 50
    br_chart_h = n * (br_h + row_gap) + 10
    d2 = Drawing(CW, br_chart_h)

    for i, (region_name, m) in enumerate(regions):
        y    = (n - 1 - i) * (br_h + row_gap) + 5
        pct  = m["blocked_pct"]
        bw   = br_area * pct / 100
        # background track
        d2.add(Rect(label_w, y, br_area, br_h, fillColor=colors.HexColor("#ECEAE3"),
                    strokeColor=None))
        # fill
        clr = RED if pct >= 75 else ORANGE if pct >= 60 else BLUE
        d2.add(Rect(label_w, y, bw, br_h, fillColor=clr, strokeColor=None))
        d2.add(String(label_w - 4, y + 3, region_name, fontSize=7.5, fillColor=GRAY_DK,
                      textAnchor="end", fontName="Helvetica"))
        d2.add(String(label_w + bw + 4, y + 3, f"{pct}%", fontSize=7.5,
                      fillColor=clr, textAnchor="start", fontName="Helvetica-Bold"))

    story.append(d2)


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  ENTRYPOINT                                                             ║
# ╚══════════════════════════════════════════════════════════════════════════╝

def main():
    parser = argparse.ArgumentParser(
        description="Generate an OSS Supply Chain Risk PDF report from one or more curation analysis tarballs."
    )
    parser.add_argument("tarballs", nargs="+", help="Path(s) to .tar.gz curation analysis file(s)")
    parser.add_argument("--output", "-o", default=None,
                        help="Output PDF path")
    parser.add_argument("--customer-name", "-n", default=None,
                        help="Override customer display name (useful for multi-tarball aggregation)")
    args = parser.parse_args()

    for t in args.tarballs:
        if not os.path.exists(t):
            print(f"ERROR: File not found: {t}")
            sys.exit(1)

    multi = len(args.tarballs) > 1

    print(f"\n{'═'*60}")
    print(f"  OSS Supply Chain Risk Report Agent")
    print(f"  Mode: {'AGGREGATED (%d tarballs)' % len(args.tarballs) if multi else 'SINGLE'}")
    print(f"{'═'*60}")

    all_metrics   = []
    region_names  = []
    region_data   = []   # list of (region_label, metrics)

    with tempfile.TemporaryDirectory() as work_dir:
        for idx, tarball_path in enumerate(args.tarballs):
            sub_dir = os.path.join(work_dir, f"tb_{idx}")
            os.makedirs(sub_dir)
            print(f"\n  [{idx+1}/{len(args.tarballs)}] {os.path.basename(tarball_path)}")
            customer_dir  = extract_tarball(tarball_path, sub_dir)
            summary_path  = os.path.join(customer_dir, "analysis_summary.txt")
            summary       = parse_summary(summary_path)
            region_label  = derive_customer_name(customer_dir, summary)
            print(f"  Region label: {region_label}")
            dfs     = load_data(customer_dir)
            metrics = compute_metrics(dfs, summary)
            all_metrics.append(metrics)
            region_data.append((region_label, metrics))

        # Customer name resolution
        if args.customer_name:
            customer_name = args.customer_name
        elif multi:
            # Strip common suffixes to find shared root (e.g. santanderlatam → Santander)
            labels = [r[0].lower() for r in region_data]
            # Find longest common prefix across all region names
            if labels:
                prefix = labels[0]
                for lbl in labels[1:]:
                    while not lbl.startswith(prefix) and prefix:
                        prefix = prefix[:-1]
                customer_name = prefix.strip("_- ").title() if len(prefix) > 2 else region_data[0][0]
            else:
                customer_name = region_data[0][0]
        else:
            customer_name = region_data[0][0]

        print(f"\n  Customer name: {customer_name}")

        # Aggregate
        final_metrics = aggregate_metrics(all_metrics) if multi else all_metrics[0]

        # Output path
        if args.output:
            output_path = args.output
        else:
            safe_name   = re.sub(r"[^\w]", "_", customer_name).upper()
            suffix      = "_GLOBAL_oss_risk_report.pdf" if multi else "_oss_risk_report.pdf"
            tarball_dir = os.path.dirname(os.path.abspath(args.tarballs[0]))
            output_path = os.path.join(tarball_dir, safe_name + suffix)

        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        print(f"  Output: {output_path}")

        # Build PDF — pass region_data only in multi mode
        build_pdf(
            customer_name, final_metrics, output_path,
            regions=region_data if multi else None
        )

    print(f"\n  ✓ Done. Report saved to:\n    {output_path}\n")


if __name__ == "__main__":
    main()
