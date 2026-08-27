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


def _upns(base: dict[str,Any])->list[str]:
    out=[]
    for x in base.get('Accounts',[]):
        r=x.get('RawEntity',x); v=x.get('UserPrincipalName') or r.get('userPrincipalName') or r.get('upn')
        if v: out.append(str(v))
    return list(dict.fromkeys(out))


def query_ueba(req:UEBARequest)->dict[str,Any]:
    upns=_upns(req.base); days=max(1,min(int(req.lookback_days),90)); minimum=max(1,min(int(req.minimum_investigation_priority),10))
    if not upns:
        return {'AllEntityEventCount':0,'AllEntityInvestigationPriorityAverage':0,'AllEntityInvestigationPriorityMax':0,'AllEntityInvestigationPrioritySum':0,'AnomalyCount':0,'AnomalyTactics':[],'AnomalyTacticsCount':0,'DetailedResults':[],'InvestigationPrioritiesFound':False,'ModuleName':'UEBAModule','ThreatIntelFound':False,'ThreatIntelMatchCount':0}
    quoted=','.join("'"+x.replace("'","''")+"'" for x in upns)
    query=f'''let UPNs=dynamic([{quoted}]);
let BA=BehaviorAnalytics
| where TimeGenerated >= ago({days}d)
| extend UPN=tostring(UserPrincipalName), Priority=toint(InvestigationPriority)
| where UPN in~ (UPNs) and Priority >= {minimum}
| extend TI=iff(tostring(ActivityInsights) has "Threat Intelligence" or tostring(DevicesInsights) has "Threat Intelligence" or tostring(UsersInsights) has "Threat Intelligence",1,0);
let Detail=BA | summarize InvestigationPrioritySum=sum(Priority), InvestigationPriorityAverage=avg(Priority), InvestigationPriorityMax=max(Priority), EventCount=count(), ThreatIntelMatchCount=sum(TI) by UserPrincipalName=UPN | extend RecordType="detail";
let Summary=BA | summarize InvestigationPrioritySum=sum(Priority), InvestigationPriorityAverage=avg(Priority), InvestigationPriorityMax=max(Priority), EventCount=count(), ThreatIntelMatchCount=sum(TI) | extend UserPrincipalName="", RecordType="summary";
union Detail, Summary'''
    client=LogsQueryClient(DefaultAzureCredential(exclude_interactive_browser_credential=True)); result=client.query_workspace(req.workspace_id,query,timespan=timedelta(days=days)); rows=[]
    if result.status==LogsQueryStatus.SUCCESS and result.tables:
        t=result.tables[0]; rows=[dict(zip(t.columns,r)) for r in t.rows]
    detail=[x for x in rows if x.get('RecordType')=='detail']; summary=next((x for x in rows if x.get('RecordType')=='summary'),{})
    anomaly_query=f'''Anomalies | where TimeGenerated >= ago({days}d) | where tostring(Entities) has_any ({quoted}) | extend Tactics=todynamic(Tactics) | mv-expand Tactic=Tactics | summarize AnomalyCount=dcount(AnomalyId), AnomalyTactics=make_set(tostring(Tactic))'''
    ar=client.query_workspace(req.workspace_id,anomaly_query,timespan=timedelta(days=days)); anomaly_count=0; tactics=[]
    if ar.status==LogsQueryStatus.SUCCESS and ar.tables and ar.tables[0].rows:
        d=dict(zip(ar.tables[0].columns,ar.tables[0].rows[0])); anomaly_count=int(d.get('AnomalyCount') or 0); tactics=list(d.get('AnomalyTactics') or [])
    ti=int(summary.get('ThreatIntelMatchCount') or 0); count=int(summary.get('EventCount') or 0)
    return {'AllEntityEventCount':count,'AllEntityInvestigationPriorityAverage':float(summary.get('InvestigationPriorityAverage') or 0),'AllEntityInvestigationPriorityMax':int(summary.get('InvestigationPriorityMax') or 0),'AllEntityInvestigationPrioritySum':int(summary.get('InvestigationPrioritySum') or 0),'AnomalyCount':anomaly_count,'AnomalyTactics':tactics,'AnomalyTacticsCount':len(tactics),'DetailedResults':[{k:v for k,v in x.items() if k!='RecordType'} for x in detail],'InvestigationPrioritiesFound':count>0,'ModuleName':'UEBAModule','ThreatIntelFound':ti>0,'ThreatIntelMatchCount':ti}
