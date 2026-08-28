from __future__ import annotations
from dataclasses import dataclass
from typing import Any
from datetime import timedelta
from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient, LogsQueryStatus
import json
import urllib.parse
import urllib.request

@dataclass(frozen=True)
class AADRisksRequest:
    workspace_id: str
    base: dict[str, Any]
    lookback_days: int = 14
    mfa_failure_lookup: bool = True
    mfa_fraud_lookup: bool = True

RANK={'unknown':0,'none':1,'low':2,'medium':3,'high':4}


def _additional(raw: dict[str,Any]) -> dict[str,Any]:
    value=raw.get('additionalData') or raw.get('AdditionalData')
    return value if isinstance(value,dict) else {}


def _first(*values: Any) -> Any:
    for value in values:
        if value is not None and value != '': return value
    return None


def _accounts(base: dict[str,Any]) -> list[dict[str,str]]:
    out=[]
    for x in base.get('Accounts',[]):
        r=x.get('RawEntity',x); a=_additional(r)
        upn=_first(x.get('UserPrincipalName'),a.get('UserPrincipalName'),a.get('userPrincipalName'),r.get('userPrincipalName'),r.get('upn'))
        uid=_first(x.get('AADUserId'),r.get('aadUserId'),r.get('objectGuid'),a.get('AadUserId'),a.get('aadUserId'))
        if upn or uid: out.append({'upn':str(upn or ''),'id':str(uid or '')})
    return out


def _graph_get(token: str,url: str) -> dict[str,Any] | None:
    request=urllib.request.Request(url,headers={'Authorization':f'Bearer {token}','Accept':'application/json'})
    try:
        with urllib.request.urlopen(request,timeout=15) as response:
            value=json.loads(response.read().decode())
            return value if isinstance(value,dict) else None
    except Exception:
        return None


def _graph_risk(token: str,account: dict[str,str]) -> tuple[str,str]:
    filt=f"id eq '{account['id']}'" if account['id'] else f"userPrincipalName eq '{account['upn'].replace(chr(39),chr(39)*2)}'"
    url='https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?$select=id,userPrincipalName,riskLevel&$filter='+urllib.parse.quote(filt,safe=" ='@.")
    data=_graph_get(token,url) or {}; values=data.get('value',[])
    if values:
        return str(values[0].get('riskLevel') or 'unknown').lower(),str(values[0].get('id') or account['id'])
    return 'unknown',account['id']


def _graph_profile(token: str,account: dict[str,str]) -> dict[str,Any]:
    key=account['id'] or account['upn']
    if not key: return {}
    select='id,userPrincipalName,displayName,city,country,department,jobTitle,officeLocation,companyName'
    # $expand=manager keeps the app-only lookup on the user resource. User.Read.All is required.
    url='https://graph.microsoft.com/v1.0/users/'+urllib.parse.quote(key,safe='@.-_')+'?$select='+select+'&$expand=manager($select=id,displayName,userPrincipalName)'
    data=_graph_get(token,url) or {}
    manager=data.get('manager') if isinstance(data.get('manager'),dict) else {}
    return {'City':data.get('city'),'Country':data.get('country'),'Department':data.get('department'),'JobTitle':data.get('jobTitle'),'Office':data.get('officeLocation'),'Company':data.get('companyName'),'DisplayName':data.get('displayName'),'ManagerUPN':manager.get('userPrincipalName'),'ManagerName':manager.get('displayName')}


def _graph_registration(token: str,user_id: str) -> dict[str,Any]:
    if not user_id: return {}
    url='https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails/'+urllib.parse.quote(user_id,safe='-_')+'?$select=isMfaRegistered,isSsprEnabled,isSsprRegistered'
    data=_graph_get(token,url) or {}
    return {'MfaRegistered':data.get('isMfaRegistered'),'SSPREnabled':data.get('isSsprEnabled'),'SSPRRegistered':data.get('isSsprRegistered')}


def _graph_roles(token: str,user_id: str) -> list[str] | None:
    if not user_id: return None
    filt=urllib.parse.quote(f"principalId eq '{user_id}'",safe=" ='" )
    assignments=_graph_get(token,'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$select=roleDefinitionId&$filter='+filt)
    if assignments is None: return None
    names=[]
    for assignment in assignments.get('value',[]):
        role_id=assignment.get('roleDefinitionId') if isinstance(assignment,dict) else None
        if not role_id: continue
        role=_graph_get(token,'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions/'+urllib.parse.quote(str(role_id),safe='-_')+'?$select=displayName') or {}
        if role.get('displayName'): names.append(str(role['displayName']))
    return sorted(set(names))


def query_aad_risks(req: AADRisksRequest) -> dict[str,Any]:
    accounts=_accounts(req.base); days=max(1,min(int(req.lookback_days),90)); credential=DefaultAzureCredential(exclude_interactive_browser_credential=True)
    token=credential.get_token('https://graph.microsoft.com/.default').token
    logs=LogsQueryClient(credential); details=[]
    for account in accounts:
        risk,uid=_graph_risk(token,account); failed=0; fraud=0; upn=account['upn']
        profile=_graph_profile(token,{'id':uid or account['id'],'upn':upn})
        registration=_graph_registration(token,uid or account['id'])
        roles=_graph_roles(token,uid or account['id'])
        if upn and (req.mfa_failure_lookup or req.mfa_fraud_lookup):
            safe=upn.replace("'","''"); parts=[]
            if req.mfa_failure_lookup:
                parts.append(f"SigninLogs | where TimeGenerated >= ago({days}d) | where UserPrincipalName =~ '{safe}' | where ResultType in ('50074','500121') or ResultDescription has_any ('MFA','multifactor') and ResultDescription has_any ('denied','timeout') | summarize Kind='failed', Count=count()")
            if req.mfa_fraud_lookup:
                parts.append(f"AuditLogs | where TimeGenerated >= ago({days}d) | where tostring(TargetResources) has '{safe}' | where OperationName has_any ('fraud','Fraud') or tostring(AdditionalDetails) has_any ('fraud','Fraud') | summarize Kind='fraud', Count=count()")
            result=logs.query_workspace(req.workspace_id,' union '.join(f'({p})' for p in parts),timespan=timedelta(days=days))
            if result.status==LogsQueryStatus.SUCCESS and result.tables:
                t=result.tables[0]
                for row in t.rows:
                    d=dict(zip(t.columns,row)); failed=int(d.get('Count',0)) if d.get('Kind')=='failed' else failed; fraud=int(d.get('Count',0)) if d.get('Kind')=='fraud' else fraud
        details.append({'UserFailedMFACount':failed,'UserMFAFraudCount':fraud,'UserId':uid,'UserPrincipalName':upn,'UserRiskLevel':risk,'AADRoles':roles,**profile,**registration})
    highest=max((x['UserRiskLevel'] for x in details),key=lambda x:RANK.get(x,0),default='unknown')
    return {'AnalyzedEntities':len(details),'FailedMFATotalCount':sum(x['UserFailedMFACount'] for x in details),'HighestRiskLevel':highest,'MFAFraudTotalCount':sum(x['UserMFAFraudCount'] for x in details),'ModuleName':'AADRisksModule','DetailedResults':details}
