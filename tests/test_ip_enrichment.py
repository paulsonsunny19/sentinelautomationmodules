from modules.base import normalize
from modules.ip_enrichment import IPEnrichmentRequest, query_ip_enrichment
import modules.ip_enrichment as ip_enrichment


INCIDENT = '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws/providers/Microsoft.SecurityInsights/incidents/inc1'


def test_base_only_normalizes_ip_without_geodata(monkeypatch):
    base = normalize(
        [{'kind': 'ip', 'properties': {'address': '49.186.62.27'}}],
        INCIDENT,
        'workspace-guid',
    )
    assert base['IPs'][0]['Address'] == '49.186.62.27'
    assert base['IPs'][0]['IsPublic'] is True
    assert 'GeoData' not in base['IPs'][0]
    assert 'GeoEnrichedIPsCount' not in base
    assert 'EnrichmentWarnings' not in base


def test_ip_enrichment_returns_geo_and_source(monkeypatch):
    class Credential:
        pass

    monkeypatch.setattr(ip_enrichment, 'DefaultAzureCredential', lambda **kwargs: Credential())
    monkeypatch.setattr(
        ip_enrichment,
        '_sentinel_geodata',
        lambda credential, subscription, resource_group, workspace, ip: (
            {'city': 'Sydney', 'country': 'Australia', 'asn': 1221}, None
        ),
    )
    base = normalize(
        [{'kind': 'ip', 'properties': {'address': '49.186.62.27'}}],
        INCIDENT,
        'workspace-guid',
    )
    result = query_ip_enrichment(IPEnrichmentRequest(base))
    assert result['ModuleName'] == 'IPEnrichmentModule'
    assert result['IPsAnalyzedCount'] == 1
    assert result['IPsEnrichedCount'] == 1
    assert result['DetailedResults'][0]['city'] == 'Sydney'
    assert result['DetailedResults'][0]['Source'] == 'Microsoft Sentinel GeoData'


def test_ip_enrichment_warning_isolated_from_base(monkeypatch):
    class Credential:
        pass

    monkeypatch.setattr(ip_enrichment, 'DefaultAzureCredential', lambda **kwargs: Credential())
    monkeypatch.setattr(
        ip_enrichment,
        '_sentinel_geodata',
        lambda credential, subscription, resource_group, workspace, ip: ({}, 'HTTP 403 AuthorizationFailed'),
    )
    base = normalize(
        [{'kind': 'ip', 'properties': {'address': '49.186.62.27'}}],
        INCIDENT,
        'workspace-guid',
    )
    result = query_ip_enrichment(IPEnrichmentRequest(base))
    assert 'EnrichmentWarnings' not in base
    assert result['IPsEnrichedCount'] == 0
    assert 'HTTP 403' in result['EnrichmentWarnings'][0]
