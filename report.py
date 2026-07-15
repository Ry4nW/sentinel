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
