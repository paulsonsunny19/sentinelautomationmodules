from __future__ import annotations
from dataclasses import dataclass
from typing import Any
from datetime import timedelta
from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient, LogsQueryStatus
import json
import urllib.error
import urllib.parse
import urllib.request

@dataclass(frozen=True)
class AADRisksRequest:
    workspace_id: str
    base: dict[str, Any]
    lookback_days: int = 14
    mfa_failure_lookup: bool = True
    mfa_fraud_lookup: bool = True

RANK={'unknown':0,'none':1,'low':2,'medium':3,'high':4,'hidden':0,'unknownfuturevalue':0}


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


def _graph_get(token: str,url: str,warnings: list[str],label: str) -> dict[str,Any] | None:
    request=urllib.request.Request(url,headers={'Authorization':f'Bearer {token}','Accept':'application/json'})
    try:
        with urllib.request.urlopen(request,timeout=15) as response:
            value=json.loads(response.read().decode())
            return value if isinstance(value,dict) else None
    except urllib.error.HTTPError as exc:
        warnings.append(f'{label}: Microsoft Graph returned HTTP {exc.code}')
    except urllib.error.URLError:
        warnings.append(f'{label}: Microsoft Graph connection failed')
    except Exception:
        warnings.append(f'{label}: Microsoft Graph lookup failed')
    return None


def _graph_risky_user(token: str,account: dict[str,str],warnings: list[str]) -> dict[str,Any]:
    filt=f"id eq '{account['id']}'" if account['id'] else f"userPrincipalName eq '{account['upn'].replace(chr(39),chr(39)*2)}'"
    select='id,userPrincipalName,userDisplayName,riskLevel,riskState,riskDetail,riskLastUpdatedDateTime'
    url='https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?$select='+select+'&$filter='+urllib.parse.quote(filt,safe=" ='@.")
    data=_graph_get(token,url,warnings,'Risky user lookup') or {}; values=data.get('value',[])
    return values[0] if values and isinstance(values[0],dict) else {}


def _graph_risk_detections(token: str,account: dict[str,str],warnings: list[str]) -> list[dict[str,Any]]:
    # IdentityRiskEvent.Read.All is the least-privileged application permission for riskDetections.
    if account['id']:
        filt=f"userId eq '{account['id']}'"
    elif account['upn']:
        filt=f"userPrincipalName eq '{account['upn'].replace(chr(39),chr(39)*2)}'"
    else:
        return []
    select='id,userId,userPrincipalName,riskEventType,riskLevel,riskState,riskDetail,source,detectionTimingType,activity,ipAddress,activityDateTime,detectedDateTime,lastUpdatedDateTime'
    url='https://graph.microsoft.com/v1.0/identityProtection/riskDetections?$select='+select+'&$filter='+urllib.parse.quote(filt,safe=" ='@.")+'&$top=50'
    data=_graph_get(token,url,warnings,'Risk detections')
    if data is None: return []
    rows=[]
    for item in data.get('value',[]):
        if not isinstance(item,dict): continue
        rows.append({
            'RiskEventType':item.get('riskEventType'),
            'RiskLevel':item.get('riskLevel'),
            'RiskState':item.get('riskState'),
            'RiskDetail':item.get('riskDetail'),
            'Activity':item.get('activity'),
            'Source':item.get('source'),
            'DetectionTimingType':item.get('detectionTimingType'),
            'IPAddress':item.get('ipAddress'),
            'ActivityDateTime':item.get('activityDateTime'),
            'DetectedDateTime':item.get('detectedDateTime'),
            'LastUpdatedDateTime':item.get('lastUpdatedDateTime'),
        })
    rows.sort(key=lambda x:str(x.get('DetectedDateTime') or x.get('ActivityDateTime') or ''),reverse=True)
    return rows


def _graph_profile(token: str,account: dict[str,str],warnings: list[str]) -> tuple[dict[str,Any],str]:
    key=account['id'] or account['upn']
    if not key: return {},''
    select='id,userPrincipalName,displayName,city,country,department,jobTitle,officeLocation,companyName'
    user_url='https://graph.microsoft.com/v1.0/users/'+urllib.parse.quote(key,safe='@.-_')+'?$select='+select
    data=_graph_get(token,user_url,warnings,'User profile') or {}
    user_id=str(data.get('id') or account['id'] or '')
    manager={}
    if user_id:
        manager_url='https://graph.microsoft.com/v1.0/users/'+urllib.parse.quote(user_id,safe='-_')+'/manager?$select=id,displayName,userPrincipalName'
        manager_data=_graph_get(token,manager_url,warnings,'Manager lookup')
        if isinstance(manager_data,dict): manager=manager_data
    return ({'City':data.get('city'),'Country':data.get('country'),'Department':data.get('department'),'JobTitle':data.get('jobTitle'),'Office':data.get('officeLocation'),'Company':data.get('companyName'),'DisplayName':data.get('displayName'),'ManagerUPN':manager.get('userPrincipalName'),'ManagerName':manager.get('displayName')},user_id)


def _graph_registration(token: str,user_id: str,warnings: list[str]) -> dict[str,Any]:
    if not user_id: return {}
    url='https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails/'+urllib.parse.quote(user_id,safe='-_')+'?$select=isMfaRegistered,isSsprEnabled,isSsprRegistered'
    data=_graph_get(token,url,warnings,'Authentication registration') or {}
    return {'MfaRegistered':data.get('isMfaRegistered'),'SSPREnabled':data.get('isSsprEnabled'),'SSPRRegistered':data.get('isSsprRegistered')}


def _graph_roles(token: str,user_id: str,warnings: list[str]) -> list[str] | None:
    if not user_id: return None
    filt=urllib.parse.quote(f"principalId eq '{user_id}'",safe=" ='" )
    assignments=_graph_get(token,'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$select=roleDefinitionId&$filter='+filt,warnings,'Directory role assignments')
    if assignments is None: return None
    names=[]; role_cache={}
    for assignment in assignments.get('value',[]):
        role_id=assignment.get('roleDefinitionId') if isinstance(assignment,dict) else None
        if not role_id: continue
        if role_id not in role_cache:
            role=_graph_get(token,'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions/'+urllib.parse.quote(str(role_id),safe='-_')+'?$select=displayName',warnings,'Directory role definition') or {}
            role_cache[role_id]=role.get('displayName')
        if role_cache.get(role_id): names.append(str(role_cache[role_id]))
    return sorted(set(names))


def query_aad_risks(req: AADRisksRequest) -> dict[str,Any]:
    accounts=_accounts(req.base); days=max(1,min(int(req.lookback_days),90)); credential=DefaultAzureCredential(exclude_interactive_browser_credential=True)
    token=credential.get_token('https://graph.microsoft.com/.default').token
    logs=LogsQueryClient(credential); details=[]; warnings=[]; all_events=[]
    for account in accounts:
        account_warnings=[]; failed=0; fraud=0; upn=account['upn']
        risky_user=_graph_risky_user(token,account,account_warnings)
        profile,profile_uid=_graph_profile(token,account,account_warnings)
        uid=profile_uid or str(risky_user.get('id') or '') or account['id']
        graph_account={'id':uid,'upn':upn}
        risk_events=_graph_risk_detections(token,graph_account,account_warnings)
        for event in risk_events:
            all_events.append({'UserPrincipalName':upn,'UserId':uid,**event})
        registration=_graph_registration(token,uid,account_warnings)
        roles=_graph_roles(token,uid,account_warnings)
        risk=str(risky_user.get('riskLevel') or 'none').lower() if risky_user else 'none'
        if risk in ('hidden','unknownfuturevalue'): risk='unknown'
        if upn and (req.mfa_failure_lookup or req.mfa_fraud_lookup):
            safe=upn.replace("'","''"); parts=[]
            if req.mfa_failure_lookup:
                parts.append(f"SigninLogs | where TimeGenerated >= ago({days}d) | where UserPrincipalName =~ '{safe}' | where ResultType in ('50074','500121') or ResultDescription has_any ('MFA','multifactor') and ResultDescription has_any ('denied','timeout') | summarize Kind='failed', Count=count()")
            if req.mfa_fraud_lookup:
                parts.append(f"AuditLogs | where TimeGenerated >= ago({days}d) | where tostring(TargetResources) has '{safe}' | where OperationName has_any ('fraud','Fraud') or tostring(AdditionalDetails) has_any ('fraud','Fraud') | summarize Kind='fraud', Count=count()")
            try:
                result=logs.query_workspace(req.workspace_id,' union '.join(f'({p})' for p in parts),timespan=timedelta(days=days))
                if result.status==LogsQueryStatus.SUCCESS and result.tables:
                    t=result.tables[0]
                    for row in t.rows:
                        d=dict(zip(t.columns,row)); failed=int(d.get('Count',0)) if d.get('Kind')=='failed' else failed; fraud=int(d.get('Count',0)) if d.get('Kind')=='fraud' else fraud
                elif result.status!=LogsQueryStatus.SUCCESS: account_warnings.append('MFA telemetry query did not complete successfully')
            except Exception: account_warnings.append('MFA telemetry query failed')
        detail={'UserFailedMFACount':failed,'UserMFAFraudCount':fraud,'UserId':uid,'UserPrincipalName':upn,'UserRiskLevel':risk,'UserRiskState':risky_user.get('riskState') if risky_user else None,'UserRiskDetail':risky_user.get('riskDetail') if risky_user else None,'UserRiskLastUpdated':risky_user.get('riskLastUpdatedDateTime') if risky_user else None,'RiskEventCount':len(risk_events),'AADRoles':roles,**profile,**registration}
        if account_warnings: detail['EnrichmentWarnings']=sorted(set(account_warnings))
        details.append(detail); warnings.extend(account_warnings)
    highest=max((x['UserRiskLevel'] for x in details),key=lambda x:RANK.get(x,0),default='none')
    return {'AnalyzedEntities':len(details),'FailedMFATotalCount':sum(x['UserFailedMFACount'] for x in details),'HighestRiskLevel':highest,'MFAFraudTotalCount':sum(x['UserMFAFraudCount'] for x in details),'RiskEventCount':len(all_events),'RiskEvents':all_events,'ModuleName':'AADRisksModule','DetailedResults':details,'EnrichmentWarnings':sorted(set(warnings))}
