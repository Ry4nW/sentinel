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
