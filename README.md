# OSS Supply Chain Risk Report Agent

Generates a fully-formatted PDF risk report from one or more JFrog Curation analysis tarballs.

## Usage

**Single tarball:**
```bash
python3 oss_risk_agent.py ACME_curation_analysis.tar.gz
python3 oss_risk_agent.py ACME_curation_analysis.tar.gz --output /tmp/report.pdf
```

**Aggregated report from multiple tarballs (same organisation, different regions):**
```bash
python3 oss_risk_agent.py EU.tar.gz LATAM.tar.gz MEXUS.tar.gz \
    --customer-name "Santander" --output /tmp/santander_global.pdf
```

## Flags

| Flag | Short | Description |
|------|-------|-------------|
| `--output` | `-o` | Output PDF path |
| `--customer-name` | `-n` | Override the customer display name |
| `--date-start` | | Override the analysis-window start date shown in the header |
| `--date-end` | | Override the analysis-window end date shown in the header |
| `--duration-days` | | Override the duration (in days) shown in the header |
| `--maven-gradle-note` | | Add a footnote clarifying that maven entries are gradle packages from `plugins.gradle.org` |
| `--slides` | | Also generate an executive `.pptx` slide deck alongside the PDF |
| `--slides-output` | | Path for the slide deck (defaults to PDF path with `.pptx` extension) |

## Executive slide deck

Pass `--slides` to additionally generate a 16:9 PowerPoint deck targeted at executive readers. The deck mirrors the PDF's information architecture and includes:

1. Title slide with customer name and headline KPIs
2. Executive summary
3. **Malicious package detected** alert (when applicable)
4. Risk by category (6-tier card layout)
5. Block/approve outcome + ecosystem breakdown
6. Top blocking policies
7. **Compromised package families** — packages observed in the customer's environment that match a built-in registry of known supply-chain attack victims (Shai-Hulud, Qix/debug-chalk, Marak/colors, axios CVE chain, LiteLLM CVEs, etc.)
8. Regional comparison (multi-region only)
9. Recommendation / JFrog Curation positioning

## Installation

```bash
pip install -r requirements.txt
```

## Input Format

The agent expects tarballs (`.tar.gz`) containing a customer directory with:
- `analysis_summary.txt` — key:value metadata
- `blocked_packages.csv` — packages blocked by curation policies
- `blocked_packages_v2.csv` — enriched blocked package events
- `approved_packages.csv` — packages that passed curation
- `unmatched_urls.csv` — URLs that couldn't be matched (optional)

## Sample Output

![Report sample showing block/approve rates, ecosystem breakdown, and top blocking policies](assets/report_sample.png)

## Output

A PDF report covering:
- Executive summary with block/approve rates
- Breakdown by risk category (malicious, immature, critical CVE, EOL, etc.)
- Ecosystem breakdown
- Top blocking policies
- Package-level detail tables
