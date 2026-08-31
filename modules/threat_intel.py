from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient, LogsQueryStatus

from .kql_safety import datatable_literal


@dataclass(frozen=True)
class ThreatIntelRequest:
    workspace_id: str
    base: dict[str, Any]
    lookback_days: int = 14
    check_ips: bool = True
    check_domains: bool = True
    check_urls: bool = True
    check_file_hashes: bool = True


def _values(base: dict[str, Any], bucket: str, keys: tuple[str, ...]) -> list[str]:
    out=[]
    for item in base.get(bucket, []):
        raw=item.get('RawEntity', item)
        for key in keys:
            value=item.get(key) or raw.get(key) or raw.get(key[0].lower()+key[1:])
            if value:
                out.append(str(value)); break
    return list(dict.fromkeys(out))


def _column_names(columns) -> list[str]:
    return [str(getattr(column, 'name', column)) for column in columns]


def _match_key(kind: str, value: str) -> str:
    # Domain names and hashes are case-insensitive. Keep URLs byte-for-byte so
    # case-sensitive URL paths do not create false-positive TI matches.
    return value.lower() if kind in ('Domain', 'FileHash') else value


def _threat_intel_query(candidates: list[tuple[str, str]], scan_days: int) -> str:
    entity_rows=[(kind, value, _match_key(kind, value)) for kind,value in candidates]
    entities=datatable_literal('Entities', ('TIType','TIData','MatchKey'), entity_rows)
    return f'''{entities}
ThreatIntelIndicators
| where TimeGenerated >= ago({scan_days}d)
| summarize arg_max(TimeGenerated, *) by Id, ObservableKey, ObservableValue
| where IsActive == true and IsDeleted != true and Revoked != true
| where isempty(ValidUntil) or ValidUntil > now()
| extend TIType=case(
    ObservableKey in ('ipv4-addr:value','ipv6-addr:value','network-traffic:src_ref.value','network-traffic:dst_ref.value'), 'IP',
    ObservableKey == 'domain-name:value', 'Domain',
    ObservableKey == 'url:value', 'URL',
    ObservableKey startswith 'file:hashes.', 'FileHash',
    '')
| where isnotempty(TIType) and isnotempty(ObservableValue)
| extend MatchKey=case(TIType in ('Domain','FileHash'), tolower(ObservableValue), ObservableValue)
| join kind=inner Entities on TIType, MatchKey
| summarize arg_max(TimeGenerated, *) by Id, TIType, TIData
| project TIType, TIData, SourceSystem,
    Description=tostring(Data.description),
    ThreatType=tostring(Data.indicator_types),
    ConfidenceScore=Confidence,
    IndicatorId=Id,
    ObservableKey, Pattern, ValidUntil, Tags
| take 200'''


def _result(details: list[dict[str, Any]], ips: list[str], domains: list[str], urls: list[str], hashes: list[str], warning: str | None = None) -> dict[str, Any]:
    def stats(kind: str, vals: list[str]):
        matched={_match_key(kind, str(item.get('TIData'))) for item in details if item.get('TIType')==kind and item.get('TIData') is not None}
        requested={_match_key(kind, value) for value in vals}
        hits=requested & matched
        return len(vals),len(hits),bool(hits)

    ic,im,ifound=stats('IP',ips)
    dc,dm,dfound=stats('Domain',domains)
    uc,um,ufound=stats('URL',urls)
    fc,fm,ffound=stats('FileHash',hashes)
    result={
        'AnyTIFound':bool(details),
        'DetailedResults':details,
        'DomainEntitiesCount':dc,
        'DomainEntitiesWithTI':dm,
        'DomainTIFound':dfound,
        'FileHashEntitiesCount':fc,
        'FileHashEntitiesWithTI':fm,
        'FileHashTIFound':ffound,
        'IPEntitiesCount':ic,
        'IPEntitiesWithTI':im,
        'IPTIFound':ifound,
        'ModuleName':'TIModule',
        'TotalTIMatchCount':len(details),
        'MatchedTIItemCount':len(details),
        'URLEntitiesCount':uc,
        'URLEntitiesWithTI':um,
        'URLTIFound':ufound,
        'ThreatIntelTable':'ThreatIntelIndicators',
    }
    if warning:
        result['EnrichmentWarnings']=[warning]
    return result


def query_threat_intel(req: ThreatIntelRequest) -> dict[str, Any]:
    ips=_values(req.base,'IPs',('Address',)) if req.check_ips else []
    domains=_values(req.base,'Domains',('DomainName','Name','domainName')) if req.check_domains else []
    urls=_values(req.base,'URLs',('Url','URL','url')) if req.check_urls else []
    hashes=_values(req.base,'FileHashes',('Value','HashValue','value')) if req.check_file_hashes else []
    candidates=[('IP',x) for x in ips]+[('Domain',x) for x in domains]+[('URL',x) for x in urls]+[('FileHash',x) for x in hashes]
    if not candidates:
        return _result([],ips,domains,urls,hashes)

    days=max(1,min(int(req.lookback_days),30))
    # Sentinel republishes current TI into Log Analytics on a roughly 7-10 day
    # cycle. Scan at least 14 days so an active indicator remains discoverable
    # even when the caller requests a shorter incident lookback.
    scan_days=max(days,14)
    query=_threat_intel_query(candidates,scan_days)
    try:
        client=LogsQueryClient(DefaultAzureCredential(exclude_interactive_browser_credential=True))
        response=client.query_workspace(req.workspace_id,query,timespan=timedelta(days=scan_days),server_timeout=20)
        if response.status==LogsQueryStatus.PARTIAL:
            return _result([],ips,domains,urls,hashes,'Threat intelligence query returned a partial Log Analytics result')
        details=[]
        for table in response.tables or []:
            names=_column_names(table.columns)
            details.extend(dict(zip(names,row)) for row in table.rows)
        return _result(details,ips,domains,urls,hashes)
    except Exception as exc:
        return _result([],ips,domains,urls,hashes,f'Threat intelligence query failed ({type(exc).__name__}: {str(exc)[:160]})')
