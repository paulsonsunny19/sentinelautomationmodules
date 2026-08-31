from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from modules.ip_baseline import classify_baseline


def test_absence_is_not_scored_without_coverage():
    state, score, rationale = classify_baseline(0, 0, 0)
    assert state == 'not_observed'
    assert score == 0
    assert 'coverage is unknown' in rationale


def test_isolated_peer_is_corroborating_risk():
    state, score, _ = classify_baseline(4, 1, 2)
    assert state == 'isolated_new_peer'
    assert score == 5


def test_established_peer_does_not_reduce_score():
    state, score, _ = classify_baseline(5000, 80, 25)
    assert state == 'established_estate_peer'
    assert score == 0
