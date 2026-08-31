import pytest

from modules.kql import KQLRequest, _prefix, run_kql


def test_denies_dangerous_query_before_network_access():
    request = KQLRequest(
        workspace_id='workspace',
        base={},
        query='SecurityAlert | take 1; .show database',
    )
    with pytest.raises(ValueError):
        run_kql(request)


def test_requires_query():
    with pytest.raises(ValueError, match='required'):
        run_kql(KQLRequest(workspace_id='workspace', base={}, query=''))


def test_rejects_overlong_query():
    with pytest.raises(ValueError, match='maximum permitted length'):
        run_kql(KQLRequest(workspace_id='workspace', base={}, query='x' * 50001))


def test_prefix_uses_current_geodata_shape():
    prefix = _prefix({
        'IncidentARMId': '/subscriptions/sub/resourceGroups/rg',
        'IPs': [{
            'Address': '49.186.62.27',
            'GeoData': {
                'latitude': '-33.84',
                'longitude': '151.18',
                'country': 'australia',
                'state': 'new south wales',
            },
        }],
    })
    assert '49.186.62.27' in prefix
    assert 'australia' in prefix
    assert 'new south wales' in prefix
