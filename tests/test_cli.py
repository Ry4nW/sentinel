from cli import should_fail


def test_none_never_fails():
    assert should_fail([{'severity': 'critical'}], 'none') is False


def test_fails_when_finding_at_threshold():
    assert should_fail([{'severity': 'high'}], 'high') is True


def test_fails_when_finding_above_threshold():
    assert should_fail([{'severity': 'critical'}], 'high') is True


def test_does_not_fail_when_only_below_threshold():
