from __future__ import annotations
from dataclasses import dataclass
from typing import Any
from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient, LogsQueryStatus
from datetime import timedelta

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


def query_threat_intel(req: ThreatIntelRequest) -> dict[str, Any]:
    ips=_values(req.base,'IPs',('Address',)) if req.check_ips else []
    domains=_values(req.base,'Domains',('DomainName','Name','domainName')) if req.check_domains else []
    urls=_values(req.base,'URLs',('Url','URL','url')) if req.check_urls else []
    hashes=_values(req.base,'FileHashes',('Value','HashValue','value')) if req.check_file_hashes else []
    candidates=[('IP',x) for x in ips]+[('Domain',x) for x in domains]+[('URL',x) for x in urls]+[('FileHash',x) for x in hashes]
    details=[]
    if candidates:
        datatable=', '.join(f'"{t}", "{v.replace(chr(34), chr(92)+chr(34))}"' for t,v in candidates)
        query=f'''let Entities=datatable(TIType:string, TIData:string)[{datatable}];
ThreatIntelligenceIndicator
| where TimeGenerated >= ago({max(1,req.lookback_days)}d) or Active == true
| where Active != false
| extend TIData=case(isnotempty(NetworkIP),NetworkIP,isnotempty(DomainName),DomainName,isnotempty(Url),Url,isnotempty(FileHashValue),FileHashValue,"")
| join kind=inner Entities on TIData
| project TIType, TIData, SourceSystem, Description, ThreatType, ConfidenceScore, IndicatorId'''
        client=LogsQueryClient(DefaultAzureCredential(exclude_interactive_browser_credential=True))
        result=client.query_workspace(req.workspace_id,query,timespan=timedelta(days=max(1,req.lookback_days)))
        if result.status == LogsQueryStatus.SUCCESS and result.tables:
            table=result.tables[0]; details=[dict(zip(table.columns,row)) for row in table.rows]
    def stats(kind, vals):
        matched={str(x.get('TIData')) for x in details if x.get('TIType')==kind}
        return len(vals),len(set(vals)&matched),bool(set(vals)&matched)
    ic,im,ifound=stats('IP',ips); dc,dm,dfound=stats('Domain',domains); uc,um,ufound=stats('URL',urls); fc,fm,ffound=stats('FileHash',hashes)
    return {'AnyTIFound':bool(details),'DetailedResults':details,'DomainEntitiesCount':dc,'DomainEntitiesWithTI':dm,'DomainTIFound':dfound,'FileHashEntitiesCount':fc,'FileHashEntitiesWithTI':fm,'FileHashTIFound':ffound,'IPEntitiesCount':ic,'IPEntitiesWithTI':im,'IPTIFound':ifound,'ModuleName':'TIModule','TotalTIMatchCount':len(details),'MatchedTIItemCount':len(details),'URLEntitiesCount':uc,'URLEntitiesWithTI':um,'URLTIFound':ufound}
