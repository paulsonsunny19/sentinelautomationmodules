from modules.threat_intel import ThreatIntelRequest, _result, _threat_intel_query, query_threat_intel


def test_threat_intel_query_uses_current_sentinel_table_only():
    query = _threat_intel_query([
        ('IP', '203.0.113.10'),
        ('Domain', 'Example.COM'),
        ('URL', 'https://example.com/CaseSensitive'),
        ('FileHash', 'ABCDEF'),
    ], 14)

    assert '\nThreatIntelIndicators\n' in query
    assert 'ThreatIntelligenceIndicator\n' not in query
    assert "ObservableKey == 'domain-name:value'" in query
    assert "ObservableKey == 'url:value'" in query
    assert "ObservableKey startswith 'file:hashes.'" in query
    assert 'IsActive == true' in query
    assert 'IsDeleted != true' in query
    assert 'Revoked != true' in query
    assert 'ValidUntil > now()' in query


def test_threat_intel_query_escapes_candidate_literals():
    query = _threat_intel_query([('Domain', 'evil"; .show tables')], 14)
    assert 'evil\\"; .show tables' in query
    assert 'datatable(TIType:string,TIData:string,MatchKey:string)' in query


def test_threat_intel_result_matches_domains_and_hashes_case_insensitively_but_urls_exactly():
    details = [
        {'TIType': 'Domain', 'TIData': 'example.com'},
        {'TIType': 'FileHash', 'TIData': 'abcdef'},
        {'TIType': 'URL', 'TIData': 'https://example.com/Path'},
    ]
    result = _result(
        details,
        [],
        ['Example.COM'],
        ['https://example.com/path'],
        ['ABCDEF'],
    )

    assert result['DomainEntitiesWithTI'] == 1
    assert result['FileHashEntitiesWithTI'] == 1
    assert result['URLEntitiesWithTI'] == 0
    assert result['ThreatIntelTable'] == 'ThreatIntelIndicators'


def test_threat_intel_short_circuits_without_entities(monkeypatch):
    def fail(*_args, **_kwargs):
        raise AssertionError('network client should not be constructed')

    monkeypatch.setattr('modules.threat_intel.LogsQueryClient', fail)
    result = query_threat_intel(ThreatIntelRequest('workspace', {}))
    assert result['MatchedTIItemCount'] == 0
    assert result['ThreatIntelTable'] == 'ThreatIntelIndicators'
