from __future__ import annotations
from dataclasses import dataclass
from typing import Any
from datetime import timedelta
from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient, LogsQueryStatus

@dataclass(frozen=True)
class UEBARequest:
    workspace_id: str
    base: dict[str, Any]
    lookback_days: int = 14
    minimum_investigation_priority: int = 1

def _column_names(columns):
    return [str(getattr(c,'name',c)) for c in columns]

def _upns(base: dict[str,Any])->list[str]:
    out=[]
    for x in base.get('Accounts',[]):
        r=x.get('RawEntity',x); v=x.get('UserPrincipalName') or r.get('userPrincipalName') or r.get('upn')
        if v: out.append(str(v))
    return list(dict.fromkeys(out))

def _quoted_upns(upns:list[str])->str:
    return ','.join("'"+x.replace("'","''")+"'" for x in upns)

def _anomaly_query(upns:list[str],days:int)->str:
    quoted=_quoted_upns(upns)
    return f'''let UPNs=dynamic([{quoted}]);
Anomalies
| where TimeGenerated >= ago({days}d)
| where UserPrincipalName in~ (UPNs) or tostring(Entities) has_any ({quoted})
| summarize AnomalyCount=dcount(Id), AnomalyTactics=make_set(Tactics,100)'''

def _empty(warnings=None)->dict[str,Any]:
    result={'AllEntityEventCount':0,'AllEntityInvestigationPriorityAverage':0,'AllEntityInvestigationPriorityMax':0,'AllEntityInvestigationPrioritySum':0,'AnomalyCount':0,'AnomalyTactics':[],'AnomalyTacticsCount':0,'DetailedResults':[],'InvestigationPrioritiesFound':False,'ModuleName':'UEBAModule','ThreatIntelFound':False,'ThreatIntelMatchCount':0}
    if warnings: result['EnrichmentWarnings']=warnings
    return result

def query_ueba(req:UEBARequest)->dict[str,Any]:
    upns=_upns(req.base); days=max(1,min(int(req.lookback_days),30)); minimum=max(1,min(int(req.minimum_investigation_priority),10))
    if not upns: return _empty()
    quoted=_quoted_upns(upns); warnings=[]
    query=f'''let UPNs=dynamic([{quoted}]);
BehaviorAnalytics
| where TimeGenerated >= ago({days}d)
| where UserPrincipalName in~ (UPNs)
| extend Priority=toint(InvestigationPriority)
| where Priority >= {minimum}
| extend TI=iff(tostring(ActivityInsights) has "Threat Intelligence" or tostring(DevicesInsights) has "Threat Intelligence" or tostring(UsersInsights) has "Threat Intelligence",1,0)
| summarize InvestigationPrioritySum=sum(Priority), InvestigationPriorityAverage=avg(Priority), InvestigationPriorityMax=max(Priority), EventCount=count(), ThreatIntelMatchCount=sum(TI) by UserPrincipalName
| take 100'''
    client=LogsQueryClient(DefaultAzureCredential(exclude_interactive_browser_credential=True)); detail=[]
    try:
        result=client.query_workspace(req.workspace_id,query,timespan=timedelta(days=days),server_timeout=20)
        if result.status==LogsQueryStatus.SUCCESS and result.tables:
            t=result.tables[0]; names=_column_names(t.columns); detail=[dict(zip(names,r)) for r in t.rows]
        elif result.status==LogsQueryStatus.PARTIAL: warnings.append('UEBA BehaviorAnalytics query returned a partial result')
    except Exception as exc: warnings.append(f'UEBA BehaviorAnalytics query failed ({type(exc).__name__}: {str(exc)[:160]})')
    anomaly_count=0; tactics=[]
    try:
        ar=client.query_workspace(req.workspace_id,_anomaly_query(upns,days),timespan=timedelta(days=days),server_timeout=20)
        if ar.status==LogsQueryStatus.SUCCESS and ar.tables and ar.tables[0].rows:
            names=_column_names(ar.tables[0].columns); d=dict(zip(names,ar.tables[0].rows[0])); anomaly_count=int(d.get('AnomalyCount') or 0)
            raw=d.get('AnomalyTactics') or []
            for value in raw if isinstance(raw,list) else [raw]:
                if isinstance(value,list): tactics.extend(str(x) for x in value if x)
                elif value: tactics.extend(x.strip() for x in str(value).split(',') if x.strip())
        elif ar.status==LogsQueryStatus.PARTIAL: warnings.append('UEBA Anomalies query returned a partial result')
    except Exception as exc: warnings.append(f'UEBA Anomalies query failed ({type(exc).__name__}: {str(exc)[:160]})')
    count=sum(int(x.get('EventCount') or 0) for x in detail); priority_sum=sum(int(x.get('InvestigationPrioritySum') or 0) for x in detail); ti=sum(int(x.get('ThreatIntelMatchCount') or 0) for x in detail); max_priority=max((int(x.get('InvestigationPriorityMax') or 0) for x in detail),default=0); average=(priority_sum/count if count else 0); tactics=sorted(set(tactics))
    result={'AllEntityEventCount':count,'AllEntityInvestigationPriorityAverage':average,'AllEntityInvestigationPriorityMax':max_priority,'AllEntityInvestigationPrioritySum':priority_sum,'AnomalyCount':anomaly_count,'AnomalyTactics':tactics,'AnomalyTacticsCount':len(tactics),'DetailedResults':detail,'InvestigationPrioritiesFound':count>0,'ModuleName':'UEBAModule','ThreatIntelFound':ti>0,'ThreatIntelMatchCount':ti}
    if warnings: result['EnrichmentWarnings']=sorted(set(warnings))
    return result
