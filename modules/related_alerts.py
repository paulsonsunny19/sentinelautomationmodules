from dataclasses import dataclass
from datetime import timedelta
from typing import Any
from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient, LogsQueryStatus

@dataclass(frozen=True)
class RelatedAlertsRequest:
    workspace_id: str
    base: dict[str, Any]
    lookback_days: int = 14
    alert_kql_filter: str = ''
    check_accounts: bool = True
    check_hosts: bool = True
    check_ips: bool = True

SEVERITY={'informational':1,'low':2,'medium':3,'high':4}

def _vals(base,key,fields):
    out=[]
    for x in base.get(key,[]):
        r=x.get('RawEntity',x)
        for f in fields:
            v=x.get(f) or r.get(f)
            if v: out.append(str(v).lower())
    return list(dict.fromkeys(out))

def query_related_alerts(req: RelatedAlertsRequest) -> dict[str, Any]:
    days=max(1,min(int(req.lookback_days),90))
    if req.alert_kql_filter and any(line.strip() and not line.strip().startswith('| where') for line in req.alert_kql_filter.splitlines()):
        raise ValueError('alert_kql_filter only supports | where statements')
    accounts=_vals(req.base,'Accounts',['UserPrincipalName','SamAccountName','userPrincipalName','accountName']) if req.check_accounts else []
    hosts=_vals(req.base,'Hosts',['FQDN','Hostname','hostName','dnsDomain']) if req.check_hosts else []
    ips=_vals(req.base,'IPs',['Address','address']) if req.check_ips else []
    current=[str(x) for x in req.base.get('AlertIds',[]) if x]
    q=lambda xs: ','.join("'"+x.replace("'","''")+"'" for x in xs)
    query=f'''let Accounts=dynamic([{q(accounts)}]); let Hosts=dynamic([{q(hosts)}]); let IPs=dynamic([{q(ips)}]); let CurrentAlerts=dynamic([{q(current)}]);
SecurityAlert
| where TimeGenerated > ago({days}d)
| summarize arg_max(TimeGenerated, *) by SystemAlertId
| where SystemAlertId !in (CurrentAlerts)
| mv-expand Entity=todynamic(Entities)
{req.alert_kql_filter}
| extend E=tostring(Entity)
| extend AccountEntityMatch=array_length(Accounts)>0 and E has_any (Accounts), HostEntityMatch=array_length(Hosts)>0 and E has_any (Hosts), IPEntityMatch=array_length(IPs)>0 and E has_any (IPs)
| where AccountEntityMatch or HostEntityMatch or IPEntityMatch
| summarize AccountEntityMatch=max(toint(AccountEntityMatch))==1, HostEntityMatch=max(toint(HostEntityMatch))==1, IPEntityMatch=max(toint(IPEntityMatch))==1, StartTime=take_any(StartTime), DisplayName=take_any(AlertName), AlertSeverity=take_any(AlertSeverity), ProviderName=take_any(ProviderName), Tactics=take_any(Tactics) by SystemAlertId
| take 200'''
    client=LogsQueryClient(DefaultAzureCredential(exclude_interactive_browser_credential=True)); result=client.query_workspace(req.workspace_id,query,timespan=timedelta(days=days),server_timeout=30)
    if result.status==LogsQueryStatus.PARTIAL: raise RuntimeError(f'Log Analytics partial query failure: {result.partial_error}')
    rows=[]
    for table in result.tables:
        names=[c.name for c in table.columns]; rows.extend(dict(zip(names,r)) for r in table.rows)
    tactics=[]
    for r in rows:
        t=r.get('Tactics') or []
        if isinstance(t,str): t=[x.strip() for x in t.split(',') if x.strip()]
        tactics.extend(t)
    tactics=sorted(set(tactics)); highest=max((str(r.get('AlertSeverity') or 'Informational') for r in rows),key=lambda x:SEVERITY.get(x.lower(),0),default='Informational')
    ac=sum(bool(r.get('AccountEntityMatch')) for r in rows); hc=sum(bool(r.get('HostEntityMatch')) for r in rows); ic=sum(bool(r.get('IPEntityMatch')) for r in rows)
    return {'AllTactics':tactics,'AllTacticsCount':len(tactics),'DetailedResults':rows,'HighestSeverityAlert':highest,'ModuleName':'RelatedAlerts','RelatedAlertsCount':len(rows),'RelatedAlertsFound':bool(rows),'RelatedAccountAlertsCount':ac,'RelatedAccountAlertsFound':ac>0,'RelatedHostAlertsCount':hc,'RelatedHostAlertsFound':hc>0,'RelatedIPAlertsCount':ic,'RelatedIPAlertsFound':ic>0}
