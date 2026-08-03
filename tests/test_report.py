from report import render_html


def make_report(findings):
    return {
        'target': 'http://example.com',
        'visited': ['http://example.com', 'http://example.com/a'],
        'findings': findings,
    }


def test_includes_target_and_counts():
    out = render_html(make_report([
        {'type': 'SQL Injection', 'url': 'http://example.com/a', 'payload': "' OR '1'='1", 'severity': 'critical'},
        {'type': 'Clickjacking', 'url': 'http://example.com', 'payload': None, 'severity': 'medium'},
    ]))
    assert 'http://example.com' in out
    assert 'SQL Injection' in out
    assert 'critical' in out
    assert '2 finding' in out


def test_handles_no_findings():
    out = render_html(make_report([]))
    assert 'no findings' in out


def test_escapes_payloads_to_avoid_self_xss():
    out = render_html(make_report([
        {'type': 'XSS', 'url': 'http://example.com', 'payload': "<script>alert(1)</script>", 'severity': 'high'},
    ]))
    assert '<script>alert(1)</script>' not in out
    assert '&lt;script&gt;' in out


def test_sorts_findings_by_severity():
    out = render_html(make_report([
        {'type': 'Clickjacking', 'url': 'http://example.com', 'payload': None, 'severity': 'medium'},
        {'type': 'SQL Injection', 'url': 'http://example.com', 'payload': 'x', 'severity': 'critical'},
    ]))
    assert out.index('SQL Injection') < out.index('Clickjacking')
