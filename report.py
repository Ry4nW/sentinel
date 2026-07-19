import html

SEVERITY_ORDER = ['critical', 'high', 'medium', 'low']

SEVERITY_COLORS = {
    'critical': '#8b0000',
    'high': '#c0392b',
    'medium': '#c98a11',
    'low': '#2e6da4',
}


def _severity_rank(severity):
    return SEVERITY_ORDER.index(severity) if severity in SEVERITY_ORDER else len(SEVERITY_ORDER)


def _badge(severity):
    color = SEVERITY_COLORS.get(severity, '#555')
    return f'<span class="sev" style="background:{color}">{html.escape(str(severity))}</span>'


def _row(finding):
    payload = html.escape(finding.get('payload') or '')
    return (
        '<tr>'
        f'<td>{_badge(finding.get("severity"))}</td>'
        f'<td>{html.escape(finding.get("type", ""))}</td>'
        f'<td>{html.escape(finding.get("url", ""))}</td>'
        f'<td><code>{payload}</code></td>'
        '</tr>'
    )


def render_html(report):
    findings = sorted(report.get('findings', []), key=lambda f: _severity_rank(f.get('severity')))

    counts = {sev: 0 for sev in SEVERITY_ORDER}
    for f in findings:
        counts[f.get('severity')] = counts.get(f.get('severity'), 0) + 1

    rows = ''.join(_row(f) for f in findings) or '<tr><td colspan="4">no findings</td></tr>'
    summary = ' '.join(
        f'{_badge(sev)} {counts[sev]}' for sev in SEVERITY_ORDER if counts[sev]
    ) or 'no findings'

    target = html.escape(report.get('target', ''))
    visited_count = len(report.get('visited', []))
    finding_count = len(findings)

    return f'''<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>sentinel report - {target}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, sans-serif; background: #111; color: #eee; padding: 2rem; }}
  h1 {{ font-size: 1.25rem; margin-bottom: .25rem; }}
  .meta {{ color: #aaa; margin-bottom: 1rem; }}
  table {{ border-collapse: collapse; width: 100%; }}
  td, th {{ padding: .5rem .75rem; border-bottom: 1px solid #333; text-align: left; vertical-align: top; }}
  th {{ color: #aaa; font-weight: normal; text-transform: uppercase; font-size: .75rem; }}
  .sev {{ color: #fff; padding: .1rem .5rem; border-radius: 3px; font-size: .75rem; text-transform: uppercase; }}
  code {{ word-break: break-all; color: #ddd; }}
</style>
</head>
<body>
  <h1>sentinel scan report</h1>
  <p class="meta">target: {target}<br>visited {visited_count} url(s), {finding_count} finding(s)</p>
  <p>{summary}</p>
  <table>
    <tr><th>severity</th><th>type</th><th>url</th><th>payload</th></tr>
    {rows}
  </table>
</body>
</html>
'''


def write_html_report(report, path):
    with open(path, 'w', encoding='utf-8') as f:
        f.write(render_html(report))
