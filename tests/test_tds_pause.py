import creator_features as cf


def test_new_payouts_do_not_withhold_tds_by_default(monkeypatch):
    monkeypatch.delenv("TDS_WITHHOLDING_ENABLED", raising=False)
    assert cf.compute_tds(1000) == 0


def test_tds_can_be_explicitly_reenabled(monkeypatch):
    monkeypatch.setenv("TDS_WITHHOLDING_ENABLED", "true")
    assert cf.compute_tds(1000) == 100
    assert cf.compute_tds(1000, exempt=True) == 0


def test_explicit_pause_disables_withholding(monkeypatch):
    monkeypatch.setenv("TDS_WITHHOLDING_ENABLED", "false")
    assert cf.compute_tds(1000) == 0
