from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import sys


def _load_runtime_module():
    path = Path(__file__).resolve().parents[1] / 'modules' / 'ip_baseline.py'
    name = 'stat_next_ip_baseline_runtime'
    spec = spec_from_file_location(name, path)
    module = module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


classify_baseline = _load_runtime_module().classify_baseline


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
