"""
reports/reporter.py
Generate scan reports in multiple formats: JSON, HTML, CSV, Markdown, SARIF.
"""

import csv
import json
import html as _html

def _esc(v):
    """Escape HTML — cegah secondary XSS di laporan HTML."""
    return _html.escape(str(v) if v else "")

import io
import time
from datetime import datetime, timezone
from typing import List
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from utils.config import Finding

console = Console()

TOOL_NAME    = "XScanner v2.0"
TOOL_VERSION = "2.0.0"
TOOL_URI     = "https://github.com/Auto-runs/xscannerv2-"


class Reporter:
    """
    Formats and saves scan findings.
    Supports: JSON · HTML · CSV · Markdown · SARIF · Rich CLI table
    """

    def __init__(self, findings: List[Finding], targets: list, elapsed: float):
        self.findings = findings
        self.targets  = targets
        self.elapsed  = elapsed
        self.ts       = datetime.now(timezone.utc).isoformat()

    # ─── JSON Report ─────────────────────────────────────────────────────────

    def save_json(self, path: str) -> str:
        report = {
            "tool":             TOOL_NAME,
            "timestamp":        self.ts,
            "duration_sec":     round(self.elapsed, 2),
            "targets":          self.targets,
            "total_findings":   len(self.findings),
            "severity_summary": self._severity_summary(),
            "findings":         [self._finding_to_dict(f) for f in self.findings],
        }
        return self._write(path, json.dumps(report, indent=2))

    # ─── HTML Report ─────────────────────────────────────────────────────────

    def save_html(self, path: str) -> str:
        sev = self._severity_summary()
        rows = ""
        for i, f in enumerate(self.findings, 1):
            color = {"High": "#e74c3c", "Medium": "#f39c12",
                     "Low": "#27ae60", "Info": "#7f8c8d"}.get(f.severity, "#fff")
            rows += f"""
            <tr>
              <td>{i}</td>
              <td>{self._he(f.url)}</td>
              <td>{self._he(f.param)}</td>
              <td><span style="color:{color};font-weight:bold">{_esc(f.severity)}</span></td>
              <td>{_esc(f.xss_type)}</td>
              <td>{_esc(f.context)}</td>
              <td><code>{self._he(f.payload[:80])}</code></td>
              <td>{'✓' if f.waf_bypassed else '-'}</td>
              <td>{'✓' if f.verified else '-'}</td>
            </tr>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>XScanner Report — {self.ts[:10]}</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: 'Segoe UI', sans-serif; background: #0f1117; color: #e1e4e8; padding: 2rem; }}
    h1 {{ color: #58a6ff; margin-bottom: .5rem; }}
    .meta {{ color: #8b949e; font-size: .9rem; margin-bottom: 2rem; }}
    .stats {{ display: flex; gap: 1.5rem; margin-bottom: 2rem; flex-wrap: wrap; }}
    .stat {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1rem 1.5rem; min-width: 120px; }}
    .stat .num {{ font-size: 2rem; font-weight: bold; }}
    .stat .lbl {{ color: #8b949e; font-size: .85rem; }}
    .high {{ color: #e74c3c; }} .medium {{ color: #f39c12; }}
    .low {{ color: #27ae60; }} .info {{ color: #7f8c8d; }}
    table {{ width: 100%; border-collapse: collapse; background: #161b22; border-radius: 8px; overflow: hidden; }}
    th {{ background: #21262d; color: #58a6ff; padding: .75rem 1rem; text-align: left; font-size: .85rem; }}
    td {{ padding: .6rem 1rem; border-bottom: 1px solid #21262d; font-size: .85rem; word-break: break-all; }}
    tr:hover td {{ background: #1c2128; }}
    code {{ background: #21262d; padding: .15rem .4rem; border-radius: 4px; font-size: .8rem; color: #79c0ff; }}
    .none {{ color: #30363d; }}
  </style>
</head>
<body>
  <h1>🔍 XScanner Report</h1>
  <p class="meta">Generated: {self.ts} &nbsp;|&nbsp; Duration: {self.elapsed:.1f}s &nbsp;|&nbsp; Targets: {len(self.targets)}</p>

  <div class="stats">
    <div class="stat"><div class="num">{len(self.findings)}</div><div class="lbl">Total Findings</div></div>
    <div class="stat"><div class="num high">{sev['High']}</div><div class="lbl">High</div></div>
    <div class="stat"><div class="num medium">{sev['Medium']}</div><div class="lbl">Medium</div></div>
    <div class="stat"><div class="num low">{sev['Low']}</div><div class="lbl">Low</div></div>
  </div>

  {'<p style="color:#27ae60;font-size:1.1rem">✓ No XSS vulnerabilities found.</p>' if not self.findings else f"""
  <table>
    <thead><tr>
      <th>#</th><th>URL</th><th>Param</th><th>Severity</th><th>Type</th>
      <th>Context</th><th>Payload</th><th>WAF</th><th>Verified</th>
    </tr></thead>
    <tbody>{rows}</tbody>
  </table>"""}
</body>
</html>"""
        return self._write(path, html)

    # ─── CSV Report ──────────────────────────────────────────────────────────

    def save_csv(self, path: str) -> str:
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["#", "url", "param", "severity", "xss_type", "context",
                    "payload", "encoding", "waf_bypassed", "verified", "evidence"])
        for i, f in enumerate(self.findings, 1):
            def csv_safe(v):
                """Cegah CSV formula injection dan escape HTML di nilai."""
                s = str(v) if v is not None else ''
                # Prefix dengan apostrof jika dimulai dengan karakter formula
                if s and s[0] in ('=','+','-','@','|','%'):
                    s = "'" + s
                return s
            w.writerow([i, csv_safe(f.url), csv_safe(f.param), f.severity,
                        f.xss_type, f.context, csv_safe(f.payload),
                        csv_safe(f.encoding_used), f.waf_bypassed,
                        f.verified, csv_safe(f.evidence[:200])])
        return self._write(path, buf.getvalue())

    # ─── Markdown Report ─────────────────────────────────────────────────────

    def save_md(self, path: str) -> str:
        sev = self._severity_summary()
        lines = [
            f"# XScanner Report",
            f"",
            f"**Generated:** {self.ts}  ",
            f"**Duration:** {self.elapsed:.1f}s  ",
            f"**Targets:** {', '.join(self.targets)}  ",
            f"",
            f"## Summary",
            f"",
            f"| Severity | Count |",
            f"|----------|-------|",
            f"| 🔴 High   | {sev['High']} |",
            f"| 🟡 Medium | {sev['Medium']} |",
            f"| 🟢 Low    | {sev['Low']} |",
            f"| ℹ Info    | {sev['Info']} |",
            f"",
        ]
        if not self.findings:
            lines.append("✅ No XSS vulnerabilities found.\n")
        else:
            lines += [
                "## Findings",
                "",
                "| # | URL | Param | Severity | Type | Context | WAF | Verified |",
                "|---|-----|-------|----------|------|---------|-----|----------|",
            ]
            for i, f in enumerate(self.findings, 1):
                lines.append(
                    f"| {i} | `{f.url[:60]}` | `{_esc(f.param)}` | **{f.severity}** "
                    f"| {f.xss_type} | {f.context} | "
                    f"{'✓' if f.waf_bypassed else '-'} | "
                    f"{'✓' if f.verified else '-'} |"
                )
            lines.append("")
            lines.append("## Details")
            lines.append("")
            for i, f in enumerate(self.findings, 1):
                lines += [
                    f"### Finding #{i} — {f.severity} ({f.xss_type})",
                    f"",
                    f"- **URL:** `{_esc(f.url)}`",
                    f"- **Parameter:** `{_esc(f.param)}`",
                    f"- **Context:** `{f.context}`",
                    f"- **Payload:** `{_esc(f.payload)}`",
                    f"- **Encoding:** `{_esc(f.encoding_used)}`",
                    f"- **WAF Bypassed:** {'Yes' if f.waf_bypassed else 'No'}",
                    f"- **Verified:** {'Yes' if f.verified else 'No'}",
                    f"",
                    f"**Evidence:**",
                    f"```",
                    _esc(f.evidence[:400]),
                    f"```",
                    f"",
                ]
        return self._write(path, "\n".join(lines))

    # ─── SARIF Report (v2.1.0) ───────────────────────────────────────────────

    def save_sarif(self, path: str) -> str:
        """
        SARIF 2.1.0 — compatible with GitHub Code Scanning, VS Code, and CI/CD.
        """
        sev_map = {"High": "error", "Medium": "warning", "Low": "note", "Info": "none"}
        results = []
        for f in self.findings:
            results.append({
                "ruleId": f"XSS/{f.xss_type.upper()}",
                "level": sev_map.get(f.severity, "warning"),
                "message": {
                    "text": (
                        f"{f.xss_type.title()} XSS in parameter '{_esc(f.param)}' "
                        f"(context: {f.context}). "
                        f"Payload: {_esc(f.payload[:120])}"
                    )
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.url},
                        "region": {"startLine": 1},
                    }
                }],
                "properties": {
                    "param":        _esc(f.param),
                    "context":      f.context,
                    "xss_type":     f.xss_type,
                    "payload":      _esc(f.payload),
                    "encoding":     f.encoding_used,
                    "waf_bypassed": f.waf_bypassed,
                    "verified":     f.verified,
                    "severity":     f.severity,
                    "confidence":   f.confidence,
                },
            })

        sarif = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [{
                "tool": {
                    "driver": {
                        "name":           TOOL_NAME,
                        "version":        TOOL_VERSION,
                        "informationUri": TOOL_URI,
                        "rules": [{
                            "id":               f"XSS/{xtype}",
                            "name":             f"CrossSiteScripting{xtype.title()}",
                            "shortDescription": {"text": f"{xtype.title()} XSS vulnerability"},
                            "helpUri":          "https://owasp.org/www-community/attacks/xss/",
                            "properties": {"tags": ["security", "xss", "web"]},
                        } for xtype in {"reflected", "stored", "dom", "blind"}],
                    }
                },
                "results":   results,
                "invocations": [{
                    "executionSuccessful": True,
                    "startTimeUtc":       self.ts,
                    "endTimeUtc":         datetime.now(timezone.utc).isoformat(),
                    "toolExecutionNotifications": [],
                }],
            }],
        }
        return self._write(path, json.dumps(sarif, indent=2))

    # ─── CLI Summary ─────────────────────────────────────────────────────────

    def print_summary(self):
        console.print()
        console.rule("[bold cyan]SCAN SUMMARY[/bold cyan]")

        sev = self._severity_summary()
        stats = (
            f"[bold]Targets:[/bold]  {len(self.targets)}\n"
            f"[bold]Duration:[/bold] {self.elapsed:.1f}s\n"
            f"[bold]Findings:[/bold] {len(self.findings)}\n"
            f"[red]High:[/red]      {sev['High']}  "
            f"[yellow]Medium:[/yellow] {sev['Medium']}  "
            f"[green]Low:[/green]    {sev['Low']}"
        )
        console.print(Panel(stats, title="[bold]Results[/bold]", border_style="cyan", box=box.ROUNDED))

        if not self.findings:
            console.print("\n  [green]✓ No XSS vulnerabilities found.[/green]\n")
            return

        table = Table(
            title="XSS Findings",
            box=box.SIMPLE_HEAD,
            show_header=True,
            header_style="bold cyan",
            border_style="dim",
        )
        table.add_column("#",         style="dim",      width=4)
        table.add_column("Type",      style="bold red", width=10)
        table.add_column("Sev",                         width=8)
        table.add_column("Conf",                        width=8)
        table.add_column("Param",     style="yellow",   width=15)
        table.add_column("Context",   style="cyan",     width=12)
        table.add_column("WAF?",                        width=5)
        table.add_column("Verified",                    width=8)
        table.add_column("URL",       style="dim",      max_width=50)

        sev_colors = {"High": "red", "Medium": "yellow", "Low": "green", "Info": "dim"}
        for i, f in enumerate(self.findings, 1):
            color   = sev_colors.get(f.severity, "white")
            waf_str = "[green]✓[/green]" if f.waf_bypassed else "-"
            ver_str = "[green]✓[/green]" if f.verified     else "-"
            table.add_row(
                str(i), f.xss_type,
                f"[{color}]{f.severity}[/{color}]", f.confidence,
                f.param[:15], f.context[:12],
                waf_str, ver_str, f.url[:60],
            )
        console.print(table)
        console.print()

    def print_finding_details(self):
        for i, f in enumerate(self.findings, 1):
            console.print(Panel(
                f"[bold]URL:[/bold]       {_esc(f.url)}\n"
                f"[bold]Param:[/bold]     [yellow]{_esc(f.param)}[/yellow]\n"
                f"[bold]Type:[/bold]      [red]{f.xss_type}[/red]\n"
                f"[bold]Context:[/bold]   [cyan]{f.context}[/cyan]\n"
                f"[bold]Payload:[/bold]   [green]{_esc(f.payload)}[/green]\n"
                f"[bold]Encoding:[/bold]  {_esc(f.encoding_used)}\n"
                f"[bold]WAF:[/bold]       {'Bypassed ✓' if f.waf_bypassed else 'N/A'}\n"
                f"[bold]Verified:[/bold]  {'✓ Confirmed in headless browser' if f.verified else 'Not verified'}\n"
                f"[bold]Evidence:[/bold]  [dim]{f.evidence[:200]}[/dim]",
                title=f"[bold red]Finding #{i}[/bold red]",
                border_style="red",
                box=box.ROUNDED,
            ))

    # ─── Helpers ─────────────────────────────────────────────────────────────

    def _finding_to_dict(self, f: Finding) -> dict:
        return {
            "url":           f.url,
            "param":         f.param,
            "xss_type":      f.xss_type,
            "context":       f.context,
            "severity":      f.severity,
            "confidence":    f.confidence,
            "payload":       f.payload,
            "encoding_used": f.encoding_used,
            "waf_bypassed":  f.waf_bypassed,
            "verified":      f.verified,
            "evidence":      f.evidence,
        }

    def _severity_summary(self) -> dict:
        summary = {"High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for f in self.findings:
            summary[f.severity] = summary.get(f.severity, 0) + 1
        return summary

    @staticmethod
    def _he(s: str) -> str:
        """HTML-escape a string for safe embedding in HTML output."""
        return (s.replace("&", "&amp;")
                 .replace("<", "&lt;")
                 .replace(">", "&gt;")
                 .replace('"', "&quot;"))

    @staticmethod
    def _write(path: str, content: str) -> str:
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(content, encoding="utf-8")
        return str(out.resolve())
