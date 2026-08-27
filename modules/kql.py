from __future__ import annotations
from dataclasses import dataclass
from typing import Any
from datetime import timedelta
from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient, LogsQueryStatus

@dataclass(frozen=True)
class KQLRequest:
    workspace_id: str
    base: dict[str, Any]
    query: str
    lookback_days: int = 14
    query_description: str | None = None


def _q(value: Any) -> str:
    return '"' + str(value or '').replace('\\','\\\\').replace('"','\\"') + '"'


def _prefix(base: dict[str, Any]) -> str:
    accounts=[]
    for x in base.get('Accounts',[]):
        r=x.get('RawEntity',x)
        accounts.append([x.get('UserPrincipalName') or r.get('userPrincipalName'),x.get('SamAccountName') or r.get('accountName'),x.get('ObjectSID') or r.get('sid'),x.get('AADUserId') or r.get('aadUserId'),x.get('ManagerUPN')])
    ips=[]
    for x in base.get('IPs',[]):
        r=x.get('RawEntity',x); geo=x.get('GeoLocation',{}) or {}
        ips.append([x.get('Address') or r.get('address'),geo.get('Latitude'),geo.get('Longitude'),geo.get('CountryName') or geo.get('Country'),geo.get('State')])
    hosts=[]
    for x in base.get('Hosts',[]): hosts.append([x.get('FQDN'),x.get('Hostname')])
    def dt(name, cols, rows):
        values=', '.join(','.join(_q(v) for v in row) for row in rows)
        return f'let {name}=datatable({",".join(c+":string" for c in cols)})[{values}];'
    incident=_q(base.get('IncidentARMId',''))
    return '\n'.join([dt('accountEntities',['UserPrincipalName','SamAccountName','ObjectSID','AADUserId','ManagerUPN'],accounts),dt('ipEntities',['IPAddress','Latitude','Longitude','Country','State'],ips),dt('hostEntities',['FQDN','Hostname'],hosts),f'let incidentArmId={incident};'])


def run_kql(req: KQLRequest) -> dict[str, Any]:
    if not req.query or len(req.query) > 50000: raise ValueError('KQL query is required and must be <= 50000 characters')
    days=max(1,min(int(req.lookback_days),90))
    full=f'{_prefix(req.base)}\n{req.query}'
    client=LogsQueryClient(DefaultAzureCredential(exclude_interactive_browser_credential=True))
    result=client.query_workspace(req.workspace_id,full,timespan=timedelta(days=days))
    rows=[]; count=0
    if result.status == LogsQueryStatus.SUCCESS and result.tables:
        table=result.tables[0]; count=len(table.rows); rows=[dict(zip(table.columns,r)) for r in table.rows[:10]]
    return {'DetailedResults':rows,'ModuleName':'KQLModule','ResultsCount':count,'ItemCount':count,'ResultsFound':count>0,'QueryDescription':req.query_description}
