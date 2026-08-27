from __future__ import annotations
from dataclasses import dataclass
from typing import Any
from datetime import timedelta
from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient, LogsQueryStatus
import json
import urllib.request

@dataclass(frozen=True)
class AADRisksRequest:
    workspace_id: str
    base: dict[str, Any]
    lookback_days: int = 14
    mfa_failure_lookup: bool = True
    mfa_fraud_lookup: bool = True

RANK={'unknown':0,'none':1,'low':2,'medium':3,'high':4}

def _accounts(base: dict[str,Any]) -> list[dict[str,str]]:
    out=[]
    for x in base.get('Accounts',[]):
        r=x.get('RawEntity',x)
        upn=x.get('UserPrincipalName') or r.get('userPrincipalName') or r.get('upn')
        uid=x.get('AADUserId') or r.get('aadUserId') or r.get('objectGuid')
        if upn or uid: out.append({'upn':str(upn or ''),'id':str(uid or '')})
    return out

def _graph_risk(credential: DefaultAzureCredential, account: dict[str,str]) -> tuple[str,str]:
    token=credential.get_token('https://graph.microsoft.com/.default').token
    filt=f"id eq '{account['id']}'" if account['id'] else f"userPrincipalName eq '{account['upn'].replace(chr(39),chr(39)*2)}'"
    url='https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?$select=id,userPrincipalName,riskLevel&$filter='+urllib.parse.quote(filt,safe=" ='@.")
    request=urllib.request.Request(url,headers={'Authorization':f'Bearer {token}','Accept':'application/json'})
    try:
        with urllib.request.urlopen(request,timeout=15) as response:
            values=json.loads(response.read().decode()).get('value',[])
            if values:
                return str(values[0].get('riskLevel') or 'unknown').lower(), str(values[0].get('id') or account['id'])
    except Exception:
        pass
    return 'unknown',account['id']

def query_aad_risks(req: AADRisksRequest) -> dict[str,Any]:
    accounts=_accounts(req.base); days=max(1,min(int(req.lookback_days),90)); credential=DefaultAzureCredential(exclude_interactive_browser_credential=True)
    logs=LogsQueryClient(credential); details=[]
    for account in accounts:
        risk,uid=_graph_risk(credential,account); failed=0; fraud=0; upn=account['upn']
        if upn and (req.mfa_failure_lookup or req.mfa_fraud_lookup):
            safe=upn.replace("'","''")
            parts=[]
            if req.mfa_failure_lookup:
                parts.append(f"SigninLogs | where TimeGenerated >= ago({days}d) | where UserPrincipalName =~ '{safe}' | where ResultType in ('50074','500121') or ResultDescription has_any ('MFA','multifactor') and ResultDescription has_any ('denied','timeout') | summarize Kind='failed', Count=count()")
            if req.mfa_fraud_lookup:
                parts.append(f"AuditLogs | where TimeGenerated >= ago({days}d) | where tostring(TargetResources) has '{safe}' | where OperationName has_any ('fraud','Fraud') or tostring(AdditionalDetails) has_any ('fraud','Fraud') | summarize Kind='fraud', Count=count()")
            result=logs.query_workspace(req.workspace_id,' union '.join(f'({p})' for p in parts),timespan=timedelta(days=days))
            if result.status==LogsQueryStatus.SUCCESS and result.tables:
                t=result.tables[0]
                for row in t.rows:
                    d=dict(zip(t.columns,row)); failed=int(d.get('Count',0)) if d.get('Kind')=='failed' else failed; fraud=int(d.get('Count',0)) if d.get('Kind')=='fraud' else fraud
        details.append({'UserFailedMFACount':failed,'UserMFAFraudCount':fraud,'UserId':uid,'UserPrincipalName':upn,'UserRiskLevel':risk})
    highest=max((x['UserRiskLevel'] for x in details),key=lambda x:RANK.get(x,0),default='unknown')
    return {'AnalyzedEntities':len(details),'FailedMFATotalCount':sum(x['UserFailedMFACount'] for x in details),'HighestRiskLevel':highest,'MFAFraudTotalCount':sum(x['UserMFAFraudCount'] for x in details),'ModuleName':'AADRisksModule','DetailedResults':details}
