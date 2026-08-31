import json

import pytest

from modules.aad_risks import _mfa_telemetry_query
from modules.base import _normalize_geodata, _sentinel_geodata
from modules.comment import build_comment
from modules.related_alerts import RelatedAlertsRequest, query_related_alerts
from modules.scoring import calculate, score_module
from modules.ueba import _anomaly_query


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


def test_geodata_normalizes_properties_payload():
    assert _normalize_geodata({'properties': {'city': 'Mortlake', 'country': 'australia', 'asn': '4804'}}) == {
        'city': 'Mortlake',
        'country': 'australia',
        'asn': '4804',
    }


def test_geodata_falls_back_to_compatibility_api(monkeypatch):
    class Credential:
        def get_token(self, _scope):
            return type('Token', (), {'token': 'test-token'})()

    class Response:
        def __init__(self, payload): self.payload = payload
        def __enter__(self): return self
        def __exit__(self, *_args): return False
        def read(self): return json.dumps(self.payload).encode()

    calls = []
    def fake_urlopen(request, timeout=15):
        calls.append((request.get_method(), request.full_url, timeout))
        if len(calls) == 1:
            return Response({})
        return Response({'city': 'Mortlake', 'state': 'new south wales', 'country': 'australia', 'organization': 'optus internet pty ltd', 'organizationType': 'Telecommunications', 'asn': '4804'})

    monkeypatch.setattr('modules.base.urllib.request.urlopen', fake_urlopen)
    geo, warning = _sentinel_geodata(Credential(), '00000000-0000-0000-0000-000000000000', 'rg', 'workspace', '49.186.62.27')
    assert warning is None
    assert geo['city'] == 'Mortlake'
    assert geo['asn'] == '4804'
    assert calls[0][0] == 'POST'
    assert 'listGeodataByIp' in calls[0][1]
    assert calls[1][0] == 'GET'
    assert '/enrichment/ip/geodata/' in calls[1][1]


def test_comment_surfaces_ip_geodata_warning():
    comment = build_comment(
        {
            'EntitiesCount': 1,
            'IPs': [{'Address': '49.186.62.27', 'GeoData': {}}],
            'PublicIPsCount': 1,
            'GeoEnrichedIPsCount': 0,
            'EnrichmentWarnings': ['Sentinel GeoIP failed for 49.186.62.27: HTTP 403'],
        },
        {'TotalScore': 0},
    )
    assert comment['PartialEnrichment'] is True
    assert 'IP enrichment warning' in comment['Message']
    assert 'Sentinel GeoIP failed for 49.186.62.27' in comment['Message']
    assert 'IP GeoData' in comment['Message']


def test_mfa_telemetry_kql_uses_valid_union_and_post_summary_labels():
    query = _mfa_telemetry_query('user@example.com', 14, True, True)
    assert query.startswith('union (SigninLogs')
    assert "), (AuditLogs" in query
    assert "summarize Kind='failed'" not in query
    assert "summarize Kind='fraud'" not in query
    assert "| extend Kind='failed'" in query
    assert "| extend Kind='fraud'" in query


def test_ueba_anomaly_kql_uses_current_id_column():
    query = _anomaly_query(['user@example.com'], 14)
    assert 'dcount(Id)' in query
    assert 'AnomalyId' not in query
    assert 'UserPrincipalName in~ (UPNs)' in query
