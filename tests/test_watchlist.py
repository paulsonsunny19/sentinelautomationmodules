import pytest

from modules.watchlist import WatchlistRequest, query_watchlist


def test_rejects_bad_alias_before_network_access():
    request = WatchlistRequest(
        workspace_id='workspace',
        base={},
        watchlist_alias='bad alias!',
        watchlist_key='IPAddress',
        watchlist_key_data_type='ip',
    )
    with pytest.raises(ValueError):
        query_watchlist(request)


def test_rejects_bad_key_before_network_access():
    request = WatchlistRequest(
        workspace_id='workspace',
        base={},
        watchlist_alias='TrustedNetworks',
        watchlist_key='x]); .show tables',
        watchlist_key_data_type='ip',
    )
    with pytest.raises(ValueError):
        query_watchlist(request)


def test_no_entities_short_circuits_without_query():
    request = WatchlistRequest(
        workspace_id='workspace',
        base={},
        watchlist_alias='TrustedNetworks',
        watchlist_key='IPAddress',
        watchlist_key_data_type='ip',
    )
    result = query_watchlist(request)
    assert result['EntitiesAnalyzedCount'] == 0
    assert result['ModuleName'] == 'WatchlistModule'
