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

    # Some tarballs nest the CSVs under a `results/` subfolder
    candidate_dirs = [customer_dir, os.path.join(customer_dir, "results")]
    base = customer_dir
    for c in candidate_dirs:
        if os.path.exists(os.path.join(c, "blocked_packages.csv")):
            base = c
            break

    files = {
        "blocked":    os.path.join(base, "blocked_packages.csv"),
        "blocked_v2": os.path.join(base, "blocked_packages_v2.csv"),
        "approved":   os.path.join(base, "approved_packages.csv"),
        "unmatched":  os.path.join(base, "unmatched_urls.csv"),
    }
    # Some result directories use 'unmatched.csv' instead of 'unmatched_urls.csv'
    if not os.path.exists(files["unmatched"]) and os.path.exists(os.path.join(base, "unmatched.csv")):
        files["unmatched"] = os.path.join(base, "unmatched.csv")

    dfs = {}
    for key, path in files.items():
        if os.path.exists(path):
            dfs[key] = pd.read_csv(path)
            print(f"     {key}: {len(dfs[key]):,} rows")
        else:
            print(f"     {key}: NOT FOUND — skipping")
            dfs[key] = pd.DataFrame()

    # If the blocked CSV uses the policy-matrix format (one column per policy, no
    # "Blocking Policies" column), synthesise the unified "Blocking Policies" column.
    blk = dfs.get("blocked")
    if blk is not None and not blk.empty and "Blocking Policies" not in blk.columns:
        policy_cols = [c for c in blk.columns if c.startswith("block_")]
        if policy_cols:
            def _row_policies(row):
                return "|".join(c for c in policy_cols if (str(row[c]).strip() not in ("", "0", "0.0", "nan")))
            blk["Blocking Policies"] = blk.apply(_row_policies, axis=1)
            print(f"     (translated {len(policy_cols)} policy-matrix columns → Blocking Policies)")

    return dfs


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  STEP 2 — COMPUTE METRICS                                               ║
# ╚══════════════════════════════════════════════════════════════════════════╝

def compute_metrics(dfs: dict, summary: dict, customer_dir: str = None, region_label: str = None) -> dict:
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
    # EOL = aged packages (semantic equivalent — package older than policy threshold,
    # covering both "with newer version" and "without newer version" variants)
    m["cat_eol"]         = count_policy(r"block_aged_package|eol|end.of.life")

    # ── breakdown by reason ─────────────────────────────────────────────
    m["reason_malicious"] = count_policy(r"malicious|malware")
    m["reason_immature"]  = count_policy(r"block_immature_packages")
    m["reason_aged"]      = count_policy(r"block_aged_package")
    m["reason_security"]  = count_policy(r"block_cvss")
    m["reason_license"]   = count_policy(r"block_no_license|block_license_")

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

    # ── malicious package list + earliest raw-log timestamp ─────────────
    m["malicious_packages"] = []
    if not blocked.empty and "Blocking Policies" in blocked.columns:
        mal_mask = blocked["Blocking Policies"].str.contains(r"malicious|malware", na=False, regex=True)
        if mal_mask.any():
            pkg_col  = "Package Name"    if "Package Name"    in blocked.columns else "package_name"
            ver_col  = "Package Version" if "Package Version" in blocked.columns else "package_version"
            eco_col3 = "Package Type"    if "Package Type"    in blocked.columns else "package_type"
            cnt_col  = "Count"           if "Count"           in blocked.columns else "count"
            url_col  = "URL"             if "URL"             in blocked.columns else ("url" if "url" in blocked.columns else None)
            sub = blocked[mal_mask]
            for _, row in sub.iterrows():
                m["malicious_packages"].append({
                    "name":    str(row[pkg_col]),
                    "version": str(row[ver_col]),
                    "eco":     str(row[eco_col3]),
                    "count":   int(row[cnt_col]) if cnt_col in blocked.columns else 0,
                    "url":     str(row[url_col]) if url_col else "",
                    "region":  region_label or "",
                    "timestamp": None,
                })

            # Try to enrich with earliest timestamp from raw_logs.jsonl
            if customer_dir:
                raw_logs_path = os.path.join(customer_dir, "raw_logs.jsonl")
                if os.path.exists(raw_logs_path):
                    import json
                    try:
                        pkg_ts = {}  # url → earliest timestamp
                        with open(raw_logs_path) as rf:
                            for line in rf:
                                try:
                                    d = json.loads(line)
                                except Exception:
                                    continue
                                req_path = d.get("request_path", "")
                                ts       = d.get("@timestamp", "")
                                for p in m["malicious_packages"]:
                                    if p["url"] and p["url"] in req_path:
                                        prev = pkg_ts.get(p["url"])
                                        if prev is None or ts < prev:
                                            pkg_ts[p["url"]] = ts
                        for p in m["malicious_packages"]:
                            if p["url"] in pkg_ts:
                                p["timestamp"] = pkg_ts[p["url"]]
                    except Exception as e:
                        print(f"     (raw_logs enrichment skipped: {e})")

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

    # Breakdown table — top reasons by count (Malicious always listed first when present)
    reasons = []
    if m.get("reason_malicious", 0) > 0:
        reasons.append(("Malicious", m["reason_malicious"]))
    reasons.extend([
        ("Immature",        m["reason_immature"]),
        ("Aged / outdated", m["reason_aged"]),
        ("Security (CVSS)", m["reason_security"]),
        ("License issues",  m["reason_license"]),
    ])
    total_b = m["total_blocked"] or 1
    hdr = [Paragraph("<font size='7' color='#888780'>Blocked reason</font>", plain()),
           Paragraph("<font size='7' color='#888780'>Count</font>", plain()),
           Paragraph("<font size='7' color='#888780'>%</font>", plain())]
    bt_inner_w = pw - 20
    def _reason_row(label, cnt):
        is_mal = (label == "Malicious")
        label_html = (f"<font color='#A32D2D'><b>{label}</b></font>" if is_mal else label)
        cnt_color  = "#A32D2D" if is_mal else "#2C2C2A"
        pct_color  = "#A32D2D" if is_mal else "#185FA5"
        return [
            Paragraph(label_html, plain()),
            Paragraph(f"<font color='{cnt_color}'><b>{cnt:,}</b></font>" if is_mal
                      else f"<font color='{cnt_color}'>{cnt:,}</font>", plain()),
            Paragraph(f"<font color='{pct_color}'><b>{round(cnt/total_b*100)}%</b></font>", plain()),
        ]
    rows = [hdr] + [_reason_row(label, cnt) for label, cnt in reasons]
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

    # ── Critical alert: malicious package detected ───────────────────────
    mal_pkgs = m.get("malicious_packages", [])
    if mal_pkgs:
        # Build a descriptive string listing each malicious package
        def _fmt_ts(ts):
            if not ts:
                return None
            try:
                # Example input: 2026-04-17T16:40:07.320Z
                dt = datetime.datetime.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S")
                return dt.strftime("%d %b %Y at %H:%M UTC")
            except Exception:
                return ts

        # Group by (name, region) to summarise
        lines = []
        for p in mal_pkgs:
            ts_str = _fmt_ts(p.get("timestamp"))
            region = p.get("region") or "unknown region"
            loc = f"<b>{region}</b>"
            if ts_str:
                loc += f" on <b>{ts_str}</b>"
            lines.append(
                f"<b>{p['name']}@{p['version']}</b> ({p['eco']}) — requested in {loc}"
            )
        pkg_list_html = "<br/>".join(f"&nbsp;&nbsp;•&nbsp;&nbsp;{ln}" for ln in lines)

        # Risk explanation — tailored for sweetalert2 specifically, but general-purpose otherwise
        primary = mal_pkgs[0]
        name_lower = primary["name"].lower()
        if "sweetalert2" in name_lower:
            risk_text = (
                "<b>sweetalert2</b> is one of the most widely-used JavaScript libraries for modal dialogs "
                "and user-facing alerts, installed in millions of web applications including banking and "
                "financial front-ends. A malicious version of such a ubiquitous UI component represents a "
                "worst-case supply chain scenario: once loaded in a browser, the compromised code runs in "
                "the same security context as the application itself, giving the attacker the ability to "
                "<b>exfiltrate session tokens, capture credentials and one-time passwords, inject fraudulent "
                "transactions, manipulate what customers see on screen, and pivot into internal APIs</b> — "
                "all through code that every downstream user implicitly trusts. Because sweetalert2 is a "
                "transitive dependency of thousands of other npm packages, a single infected version can "
                "cascade across an entire product portfolio within hours of publication."
            )
        else:
            risk_text = (
                f"A malicious package represents the most severe class of OSS supply chain risk: code "
                f"deliberately crafted by an adversary to execute on developer workstations, build "
                f"infrastructure, or end-user systems. Typical objectives include credential theft, "
                f"data exfiltration, establishing persistence, and pivoting into internal networks. "
                f"Because <b>{primary['name']}</b> was actively requested by a developer or automated "
                f"build, the attack chain had already begun."
            )

        alert_html = (
            "<font size='11' color='#A32D2D'><b>⚠ Malicious Package Download Detected</b></font>"
            "<br/><br/>"
            f"During the reporting window, <b>{len(mal_pkgs)} confirmed malicious package request"
            f"{'s' if len(mal_pkgs) != 1 else ''}</b> "
            f"{'were' if len(mal_pkgs) != 1 else 'was'} observed originating from within "
            f"{customer_name}'s development environment:"
            "<br/><br/>"
            f"{pkg_list_html}"
            "<br/><br/>"
            f"This is not a theoretical exposure — it is an <b>actual event of a malicious OSS package "
            f"reaching {customer_name}'s perimeter</b>. In this case the package behaviour was altered to "
            f"inject undesired audio/video content into UI elements created with the package. This event "
            f"proves the susceptibility of the software development process in {customer_name} to such attacks. "
            "<br/><br/>"
            "<b>This attack could have been prevented by JFrog Curation.</b> With Curation deployed "
            "inline at the package gateway, this malicious request would have been intercepted before "
            f"reaching the developer's <code>node_modules</code> or any CI/CD artifact — the policy "
            "<code>block_malicious_package</code> would have fired automatically on the first download "
            "attempt, blocking it and alerting the security team without requiring any developer action. "
            "Instead, without Curation, the package was delivered into the build pipeline and is now part "
            "of an active incident requiring manual investigation, dependency remediation, and forensic "
            f"review across every system that consumed it. <b>Curation turns attacks of this class into "
            "logged, blocked events — before they become breaches.</b>"
        )

        alert_box = Table(
            [[Paragraph(alert_html, ParagraphStyle("alert", fontName="Helvetica", fontSize=9,
                                                    textColor=RED_DARK, leading=14, spaceAfter=0))]],
            colWidths=[CW]
        )
        alert_box.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,-1), RED_BG),
            ("ROUNDEDCORNERS",(0,0),(-1,-1),[6,6,6,6]),
            ("LEFTPADDING",(0,0),(-1,-1),16),  ("RIGHTPADDING",(0,0),(-1,-1),16),
            ("TOPPADDING",(0,0),(-1,-1),14),   ("BOTTOMPADDING",(0,0),(-1,-1),14),
            ("BOX",(0,0),(-1,-1),1.2, RED_DARK),
            ("LINELEFT",(0,0),(0,-1),5, RED_DARK),
        ]))
        story.append(alert_box)
        story.append(Spacer(1, 10))

    imm_total = m["cat_imm2d"] + m["cat_imm14d"] + m["cat_imm30d"]
    mal_count = len(m.get("malicious_packages", []))
    if mal_count:
        mal_phrase = (
            f"<b>{mal_count} confirmed malicious package "
            f"request{'s' if mal_count != 1 else ''}</b> (detailed in the alert above and in Appendix 0), "
            f"followed by critical vulnerabilities (CVSS 9–10), license-restricted components, "
            f"and <b>{imm_total:,} immature package versions</b> that were less than 30 days old at "
            f"the time of the request"
        )
    else:
        mal_phrase = (
            f"critical vulnerabilities (CVSS 9–10), license-restricted components, and, most prominently, "
            f"<b>{imm_total:,} immature package versions</b> that were less than 30 days old at the time of the request"
        )
    exec_text = (
        f"This report quantifies the current <b>open-source software (OSS) supply chain risk</b> exposure "
        f"within {customer_name}'s software development environment"
        + (f", aggregated across {len(regions)} regional business units" if regions else "")
        + f", based on package request activity observed "
        f"between {m['date_start']} and {m['date_end']}. Across {m['total_log_entries']:,} log entries, "
        f"<b>{m['total_blocked']:,} unique package versions</b> "
        f"were flagged as risky — a <b>{m['blocked_pct']}% block rate</b> against all classified packages — spanning "
        f"{mal_phrase}."
        "<br/><br/>"
        "Immature packages represent the most acute and least visible threat in the modern OSS supply chain. "
        "A newly published package version has not yet had the time to accumulate community scrutiny, "
        "security researcher analysis, or real-world validation. This window of low visibility is precisely "
        "the attack surface exploited by campaigns such as <b>Shai-Hulud</b> — a class of supply chain "
        "attack observed in the npm ecosystem in which threat actors publish malicious packages designed to "
        "mimic legitimate, widely-used libraries. These packages are engineered to be downloaded "
        "immediately after publication, before detection tools and human reviewers have had a chance to "
        "identify them. "
        + (
            f"With <b>{m['cat_imm2d']} packages which were downloaded within 2 days of release</b> and "
            f"hundreds more within 14 days, "
            if m.get("cat_imm2d", 0) > 0 else
            f"With <b>{m['cat_imm14d']:,} packages downloaded within 14 days of release</b> and "
            f"<b>{m['cat_imm30d']:,} within 30 days</b>, "
        )
        + f"this report illustrates that {customer_name}'s developers are actively pulling packages "
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

    # Optional footnote — clarifies that maven entries are gradle packages
    if m.get("_maven_gradle_note"):
        story.append(Spacer(1, 4))
        story.append(Paragraph(
            "<font size='7' color='#888780'><i>"
            "* Requests that appear under the maven ecosystem are actually gradle packages "
            "requested from upstream repo: <font color='#185FA5'>https://plugins.gradle.org/m2/</font> "
            "which is defined as a maven remote repository in Cato Networks' environment."
            "</i></font>",
            plain()
        ))
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

    # ── Appendix 0: Malicious packages ───────────────────────────────────
    mal_pkgs_app = m.get("malicious_packages", [])
    if mal_pkgs_app:
        story.append(PageBreak())
        story.append(appendix_header("Appendix 0", "Malicious Packages"))
        story.append(Spacer(1, 4))

        # Build descriptive intro with region and timestamp info
        def _fmt_ts_app(ts):
            if not ts:
                return None
            try:
                dt = datetime.datetime.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S")
                return dt.strftime("%d %b %Y at %H:%M UTC")
            except Exception:
                return ts

        detail_lines = []
        for p in mal_pkgs_app:
            ts_str = _fmt_ts_app(p.get("timestamp"))
            region = p.get("region") or "unknown region"
            bits = [
                f"<b>{p['name']}@{p['version']}</b> ({p['eco']})",
                f"region: <b>{region}</b>",
            ]
            if ts_str:
                bits.append(f"first requested: <b>{ts_str}</b>")
            if p.get("count"):
                bits.append(f"attempts: <b>{p['count']}</b>")
            if p.get("url"):
                bits.append(f"source: <font size='7'>{p['url']}</font>")
            detail_lines.append(" &nbsp;·&nbsp; ".join(bits))

        intro0 = (
            f"The {len(mal_pkgs_app)} package request"
            f"{'s' if len(mal_pkgs_app) != 1 else ''} below "
            f"{'were' if len(mal_pkgs_app) != 1 else 'was'} flagged by the "
            f"<code>block_malicious_package</code> policy — the most severe classification in the "
            f"curation policy set. Each entry represents a confirmed attempt to pull a package that the "
            f"upstream public registry was knowingly serving as malicious at the time of request, "
            f"constituting a successful supply chain attack against {customer_name}'s development "
            f"environment. Had JFrog Curation been enforcing policy inline at the gateway, every one of "
            f"these requests would have been blocked automatically before reaching the requesting "
            f"workstation, CI runner, or artifact repository."
        )
        story.append(Paragraph(intro0, body_style()))
        story.append(Spacer(1, 8))

        # Per-incident detail block
        for ln in detail_lines:
            story.append(Paragraph(f"&nbsp;&nbsp;•&nbsp;&nbsp;{ln}", body_style()))
            story.append(Spacer(1, 3))
        story.append(Spacer(1, 8))

        # Standard package table (same structure as Appendices 1 & 2)
        story.append(build_pkg_table(mal_pkgs_app))
        story.append(Spacer(1, 8))
        story.append(Paragraph(
            f"<font size='7' color='#888780'>"
            f"Policy: block_malicious_package · Period: {date_range}</font>",
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
        + f" We identified immature version downloads of packages previously compromised by the "
          f"<b>Shai-Hulud</b> attack — such as <b>eslint</b> and <b>duckdb</b> — highlighting the "
          f"likelihood of similar attacks targeting {customer_name} in the future."
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

    agg["reason_malicious"] = _sum("reason_malicious")
    agg["reason_immature"]  = _sum("reason_immature")
    agg["reason_aged"]      = _sum("reason_aged")
    agg["reason_security"]  = _sum("reason_security")
    agg["reason_license"]   = _sum("reason_license")

    agg["ecosystem_counts"] = _eco_merge()
    agg["policy_counts"]    = _policy_merge()

    # Date range — use earliest start and latest end
    agg["date_start"]    = _earliest("date_start")
    agg["date_end"]      = _latest("date_end")
    # Coerce to int, ignoring missing or non-numeric values (e.g. "?")
    _durations = []
    for _m in all_metrics:
        try:
            _durations.append(int(_m.get("duration_days", 0)))
        except (ValueError, TypeError):
            continue
    agg["duration_days"] = max(_durations) if _durations else "?"

    agg["imm2d_packages"] = _merge_pkg_list("imm2d_packages")
    agg["crit_packages"]  = _merge_pkg_list("crit_packages")

    # Malicious packages — preserve region info, do not dedupe across regions
    agg["malicious_packages"] = []
    for m in all_metrics:
        for p in m.get("malicious_packages", []):
            agg["malicious_packages"].append(dict(p))

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
    parser.add_argument("--date-start", default=None,
                        help="Override analysis window start date shown in report header (e.g. '13 Apr 2026')")
    parser.add_argument("--date-end", default=None,
                        help="Override analysis window end date shown in report header (e.g. '17 Apr 2026')")
    parser.add_argument("--duration-days", default=None, type=int,
                        help="Override duration in days shown in the report header")
    parser.add_argument("--maven-gradle-note", action="store_true",
                        help="Add a footnote under the ecosystem chart explaining that maven entries are gradle packages from plugins.gradle.org")
    parser.add_argument("--slides", action="store_true",
                        help="Also generate an executive .pptx slide deck alongside the PDF")
    parser.add_argument("--slides-output", default=None,
                        help="Path for the .pptx slide deck (defaults to PDF path with .pptx extension)")
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
    compromise_blocked  = []   # accumulated for slide deck threat-intel scan
    compromise_approved = []

    def _capture_records(df, ecosystem_default=None):
        """Yield {name, version, eco, count, region} dicts from a CSV-derived DF."""
        if df is None or df.empty:
            return []
        name_col = "Package Name"    if "Package Name"    in df.columns else "package_name"
        ver_col  = "Package Version" if "Package Version" in df.columns else "package_version"
        eco_col  = "Package Type"    if "Package Type"    in df.columns else "package_type"
        cnt_col  = "Count"           if "Count"           in df.columns else "count"
        out = []
        for _, row in df.iterrows():
            try:
                out.append({
                    "name":    str(row[name_col]),
                    "version": str(row[ver_col])     if ver_col in df.columns else "",
                    "eco":     str(row[eco_col]).lower() if eco_col in df.columns else (ecosystem_default or ""),
                    "count":   int(row[cnt_col])     if cnt_col in df.columns else 0,
                })
            except Exception:
                continue
        return out

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
            metrics = compute_metrics(dfs, summary, customer_dir=customer_dir, region_label=region_label)
            all_metrics.append(metrics)
            region_data.append((region_label, metrics))

            # Capture raw records for the compromise-scan slide
            for rec in _capture_records(dfs.get("blocked")):
                rec["region"] = region_label
                compromise_blocked.append(rec)
            for rec in _capture_records(dfs.get("approved")):
                rec["region"] = region_label
                compromise_approved.append(rec)

        # Consolidate same-region tarballs — merge entries whose region_label matches
        consolidated = {}        # region_label → list of metrics
        order = []               # preserve first-seen order
        for label, mx in region_data:
            key = label.lower().strip()
            if key not in consolidated:
                consolidated[key] = {"label": label, "metrics": []}
                order.append(key)
            consolidated[key]["metrics"].append(mx)

        merged_region_data = []
        for key in order:
            label  = consolidated[key]["label"]
            mlist  = consolidated[key]["metrics"]
            if len(mlist) == 1:
                merged_region_data.append((label, mlist[0]))
            else:
                print(f"  → Merging {len(mlist)} tarballs for region '{label}'")
                merged_region_data.append((label, aggregate_metrics(mlist)))
        region_data = merged_region_data

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

        # Optional CLI overrides for header date range
        if args.date_start:
            final_metrics["date_start"] = args.date_start
        if args.date_end:
            final_metrics["date_end"]   = args.date_end
        if args.duration_days is not None:
            final_metrics["duration_days"] = args.duration_days
        final_metrics["_maven_gradle_note"] = args.maven_gradle_note

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

        # Optional: build executive slide deck
        slides_path = None
        if args.slides:
            try:
                from oss_risk_slides import build_slide_deck
            except ImportError as e:
                print(f"  ⚠  Could not import slide-deck module: {e}")
                print(f"     Install with: pip install python-pptx")
                build_slide_deck = None
            if build_slide_deck:
                if args.slides_output:
                    slides_path = args.slides_output
                else:
                    slides_path = re.sub(r"\.pdf$", "", output_path) + ".pptx"
                build_slide_deck(
                    customer_name, final_metrics, slides_path,
                    regions=region_data if multi else None,
                    compromise_blocked=compromise_blocked,
                    compromise_approved=compromise_approved,
                )

    print(f"\n  ✓ Done. Report saved to:\n    {output_path}")
    if slides_path:
        print(f"             Slide deck:\n    {slides_path}")
    print()


if __name__ == "__main__":
    main()
