from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Any
import ipaddress

from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient, LogsQueryStatus

from .kql_safety import assert_safe_watchlist_alias, assert_safe_watchlist_key


@dataclass(frozen=True)
class WatchlistRequest:
    workspace_id: str
    base: dict[str, Any]
    watchlist_alias: str
    watchlist_key: str
    watchlist_key_data_type: str


def _entity_values(base: dict[str, Any], kind: str) -> list[str]:
    kind = kind.lower()
    if kind == 'upn':
        vals = []
        for x in base.get('Accounts', []):
            raw = x.get('RawEntity', x)
            value = x.get('UserPrincipalName') or raw.get('userPrincipalName') or raw.get('UPNSuffix')
            if value:
                vals.append(str(value))
        return vals
    if kind in ('ip', 'cidr'):
        return [str(x.get('Address')) for x in base.get('IPs', []) if x.get('Address')]
    if kind == 'fqdn':
        return [
            str(x.get('FQDN') or x.get('Hostname'))
            for x in base.get('Hosts', [])
            if x.get('FQDN') or x.get('Hostname')
        ]
    raise ValueError('watchlistKeyDataType must be upn, ip, cidr, or fqdn')


def query_watchlist(req: WatchlistRequest) -> dict[str, Any]:
    assert_safe_watchlist_alias(req.watchlist_alias)
    assert_safe_watchlist_key(req.watchlist_key)

    values = list(dict.fromkeys(_entity_values(req.base, req.watchlist_key_data_type)))
    rows = []
    if values:
        query = (
            f'_GetWatchlist("{req.watchlist_alias}") '
            f'| project WatchValue=tostring({req.watchlist_key}), WatchlistItemId, SearchKey, _DTItemType'
        )
        client = LogsQueryClient(DefaultAzureCredential(exclude_interactive_browser_credential=True))
        result = client.query_workspace(req.workspace_id, query, timespan=timedelta(days=28), server_timeout=20)
        if result.status == LogsQueryStatus.SUCCESS and result.tables:
            table = result.tables[0]
            names = [str(getattr(column, 'name', column)) for column in table.columns]
            rows = [dict(zip(names, row)) for row in table.rows]

    watch_values = [str(x.get('WatchValue', '')) for x in rows]
    details = []
    dtype = req.watchlist_key_data_type.lower()
    for value in values:
        match = False
        if dtype == 'cidr':
            try:
                match = any(
                    ipaddress.ip_address(value) in ipaddress.ip_network(w, strict=False)
                    for w in watch_values
                    if w
                )
            except ValueError:
                match = False
        elif dtype == 'fqdn':
            match = any(
                value.lower() == w.lower() or value.split('.')[0].lower() == w.lower()
                for w in watch_values
            )
        else:
            match = any(value.lower() == w.lower() for w in watch_values)
        details.append({'OnWatchlist': match, 'EntityData': value})

    count = sum(1 for x in details if x['OnWatchlist'])
    return {
        'DetailedResults': details,
        'EntitiesAnalyzedCount': len(details),
        'EntitiesOnWatchlist': count > 0,
        'EntitiesOnWatchlistCount': count,
        'WatchlistMatchCount': count,
        'ModuleName': 'WatchlistModule',
        'WatchlistName': req.watchlist_alias,
    }
