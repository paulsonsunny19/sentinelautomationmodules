import math

import pytest

from modules.scoring import calculate, score_module


def test_calculate_skips_failed_module_bodies_and_keeps_other_scores():
    result = calculate([
        {'module': None},
        {'module': {'error': 'downstream_failure'}},
        {'module': {'ModuleName': 'TIModule', 'MatchedTIItemCount': 1}},
    ])

    assert result['TotalScore'] == 10
    assert len(result['DetailedResults']) == 1


@pytest.mark.parametrize('value', [float('nan'), float('inf'), float('-inf'), -1, 101])
def test_score_multiplier_rejects_non_finite_negative_or_excessive_values(value):
    with pytest.raises(ValueError, match='scoreMultiplier'):
        calculate([{'module': {'ModuleName': 'TIModule', 'MatchedTIItemCount': 1}, 'scoreMultiplier': value}])


def test_custom_scoring_data_does_not_reduce_risk_or_poison_total():
    scores = score_module({
        'ModuleName': 'IPNetworkBaselineModule',
        'ScoringData': [
            {'Score': 5, 'ScoreLabel': 'isolated peer'},
            {'Score': -100, 'ScoreLabel': 'attacker-shaped downgrade'},
            {'Score': float('nan'), 'ScoreLabel': 'nan'},
            {'Score': float('inf'), 'ScoreLabel': 'inf'},
        ],
    })

    assert scores == [{'Score': 5.0, 'ScoreSource': 'isolated peer'}]
    assert all(math.isfinite(row['Score']) and row['Score'] >= 0 for row in scores)


def test_custom_float_score_is_supported_when_finite_and_nonnegative():
    scores = score_module({
        'ModuleName': 'CustomModule',
        'ScoringData': [{'Score': 2.5, 'ScoreLabel': 'custom'}],
    })
    assert scores == [{'Score': 2.5, 'ScoreSource': 'custom'}]
