from __future__ import annotations
from dataclasses import dataclass
from typing import Any
from datetime import timedelta
import ipaddress
from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient, LogsQueryStatus

@dataclass(frozen=True)
class WatchlistRequest:
    workspace_id: str
    base: dict[str, Any]
    watchlist_alias: str
    watchlist_key: str
    watchlist_key_data_type: str


def _entity_values(base: dict[str, Any], kind: str) -> list[str]:
    kind=kind.lower()
    if kind == 'upn':
        vals=[]
        for x in base.get('Accounts',[]):
            raw=x.get('RawEntity',x); v=x.get('UserPrincipalName') or raw.get('userPrincipalName') or raw.get('UPNSuffix')
            if v: vals.append(str(v))
        return vals
    if kind in ('ip','cidr'):
        return [str(x.get('Address')) for x in base.get('IPs',[]) if x.get('Address')]
    if kind == 'fqdn':
        return [str(x.get('FQDN') or x.get('Hostname')) for x in base.get('Hosts',[]) if x.get('FQDN') or x.get('Hostname')]
    raise ValueError('watchlistKeyDataType must be upn, ip, cidr, or fqdn')


def query_watchlist(req: WatchlistRequest) -> dict[str, Any]:
    values=list(dict.fromkeys(_entity_values(req.base,req.watchlist_key_data_type)))
    rows=[]
    if values:
        escaped=req.watchlist_key.replace("'","''")
        query=f'''_GetWatchlist("{req.watchlist_alias.replace(chr(34), chr(92)+chr(34))}") | project WatchValue=tostring([\'{escaped}\']), WatchlistItemId, SearchKey, _DTItemType'''
        client=LogsQueryClient(DefaultAzureCredential(exclude_interactive_browser_credential=True))
        result=client.query_workspace(req.workspace_id,query,timespan=timedelta(days=28))
        if result.status == LogsQueryStatus.SUCCESS and result.tables:
            t=result.tables[0]; rows=[dict(zip(t.columns,r)) for r in t.rows]
    watch_values=[str(x.get('WatchValue','')) for x in rows]
    details=[]
    dtype=req.watchlist_key_data_type.lower()
    for value in values:
        match=False
        if dtype=='cidr':
            try: match=any(ipaddress.ip_address(value) in ipaddress.ip_network(w,strict=False) for w in watch_values if w)
            except ValueError: match=False
        elif dtype=='fqdn': match=any(value.lower()==w.lower() or value.split('.')[0].lower()==w.lower() for w in watch_values)
        else: match=any(value.lower()==w.lower() for w in watch_values)
        details.append({'OnWatchlist':match,'EntityData':value})
    count=sum(1 for x in details if x['OnWatchlist'])
    return {'DetailedResults':details,'EntitiesAnalyzedCount':len(details),'EntitiesOnWatchlist':count>0,'EntitiesOnWatchlistCount':count,'WatchlistMatchCount':count,'ModuleName':'WatchlistModule','WatchlistName':req.watchlist_alias}
