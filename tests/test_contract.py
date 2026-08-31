import pytest

from modules.related_alerts import RelatedAlertsRequest, query_related_alerts
from modules.scoring import calculate, score_module


def test_related_alert_request_is_immutable():
    request = RelatedAlertsRequest(workspace_id='workspace', base={})
    assert request.lookback_days == 14
    with pytest.raises(Exception):
        request.lookback_days = 30


def test_related_alert_filter_rejects_arbitrary_kql():
    request = RelatedAlertsRequest(
        workspace_id='workspace',
        base={},
        alert_kql_filter='SecurityAlert | take 1',
    )
    with pytest.raises(ValueError, match='only supports'):
        query_related_alerts(request)


def test_related_alert_filter_allows_where_only():
    request = RelatedAlertsRequest(
        workspace_id='workspace',
        base={},
        alert_kql_filter='| where AlertSeverity == "High"',
    )
    result = query_related_alerts(request)
    assert result['ModuleName'] == 'RelatedAlerts'
    assert result['RelatedAlertsCount'] == 0


def test_custom_scoring_data_accepts_ip_baseline_score():
    scored = score_module({
        'ModuleName': 'IPNetworkBaselineModule',
        'ScoringData': [{'Score': 5, 'ScoreLabel': 'IP baseline: isolated peer'}],
    })
    assert scored == [{'Score': 5.0, 'ScoreSource': 'IP baseline: isolated peer'}]


def test_calculate_combines_runtime_module_scores():
    result = calculate([
        {'module': {'ModuleName': 'ThreatIntelligenceModule', 'MatchedTIItemCount': 1}},
        {'module': {'ModuleName': 'IPNetworkBaselineModule', 'ScoringData': [{'Score': 5, 'ScoreLabel': 'IP baseline'}]}},
    ])
    assert result['TotalScore'] == 15.0
