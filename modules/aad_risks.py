from __future__ import annotations
from dataclasses import dataclass
from typing import Any
from datetime import timedelta
from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient, LogsQueryStatus
import json, urllib.error, urllib.parse, urllib.request

@dataclass(frozen=True)
class AADRisksRequest:
    workspace_id:str; base:dict[str,Any]; lookback_days:int=14; mfa_failure_lookup:bool=True; mfa_fraud_lookup:bool=True
RANK={'unknown':0,'none':1,'low':2,'medium':3,'high':4,'hidden':0,'unknownfuturevalue':0}

def _column_names(columns):return [str(getattr(c,'name',c)) for c in columns]
def _additional(raw):
    value=raw.get('additionalData') or raw.get('AdditionalData');return value if isinstance(value,dict) else {}
def _first(*values):
    for value in values:
        if value is not None and value!='':return value
    return None
def _accounts(base):
    out=[];seen=set()
    for x in base.get('Accounts',[]):
        r=x.get('RawEntity',x);a=_additional(r);upn=_first(x.get('UserPrincipalName'),a.get('UserPrincipalName'),a.get('userPrincipalName'),r.get('userPrincipalName'),r.get('upn'));uid=_first(x.get('AADUserId'),r.get('aadUserId'),r.get('objectGuid'),a.get('AadUserId'),a.get('aadUserId'));key=(str(uid or '').lower(),str(upn or '').lower())
        if (upn or uid) and key not in seen:seen.add(key);out.append({'upn':str(upn or ''),'id':str(uid or '')})
    return out

def _mfa_telemetry_query(upn:str,days:int,include_failures:bool=True,include_fraud:bool=True)->str:
    safe=upn.replace("'","''");parts=[]
    if include_failures:
        parts.append(f'''SigninLogs
| where TimeGenerated >= ago({days}d)
| where UserPrincipalName =~ '{safe}'
| where ResultType in ('50074','500121') or (ResultDescription has_any ('MFA','multifactor') and ResultDescription has_any ('denied','timeout'))
| summarize Count=count()
| extend Kind='failed'
| project Kind, Count''')
    if include_fraud:
        parts.append(f'''AuditLogs
| where TimeGenerated >= ago({days}d)
| where tostring(TargetResources) has '{safe}'
| where OperationName has_any ('fraud','Fraud') or tostring(AdditionalDetails) has_any ('fraud','Fraud')
| summarize Count=count()
| extend Kind='fraud'
| project Kind, Count''')
    if not parts:return ''
    return parts[0] if len(parts)==1 else 'union ' + ', '.join(f'({part})' for part in parts)

def _graph_url(path:str,params:dict[str,str]|None=None)->str:
    return 'https://graph.microsoft.com/v1.0/'+path.lstrip('/')+('?' + urllib.parse.urlencode(params,quote_via=urllib.parse.quote) if params else '')
def _graph_get(token,url,warnings,label,ignore_http=()):
    try:
        request=urllib.request.Request(url,headers={'Authorization':f'Bearer {token}','Accept':'application/json'})
        with urllib.request.urlopen(request,timeout=15) as response:
            value=json.loads(response.read().decode());return value if isinstance(value,dict) else None
    except urllib.error.HTTPError as exc:
        if exc.code not in ignore_http:warnings.append(f'{label}: Microsoft Graph returned HTTP {exc.code}')
    except urllib.error.URLError as exc:warnings.append(f'{label}: Microsoft Graph connection failed ({type(exc.reason).__name__})')
    except Exception as exc:warnings.append(f'{label}: Microsoft Graph lookup failed ({type(exc).__name__})')
    return None

def _graph_risky_user(token,account,warnings):
    before=len(warnings);filt=f"id eq '{account['id']}'" if account['id'] else f"userPrincipalName eq '{account['upn'].replace(chr(39),chr(39)*2)}'";select='id,userPrincipalName,userDisplayName,riskLevel,riskState,riskDetail,riskLastUpdatedDateTime'
    data=_graph_get(token,_graph_url('identityProtection/riskyUsers',{'$select':select,'$filter':filt}),warnings,'Risky user lookup');values=data.get('value',[]) if data else [];return (values[0] if values and isinstance(values[0],dict) else {}),data is not None and len(warnings)==before
def _graph_risk_detections(token,account,warnings):
    if account['id']:filt=f"userId eq '{account['id']}'"
    elif account['upn']:filt=f"userPrincipalName eq '{account['upn'].replace(chr(39),chr(39)*2)}'"
    else:return [],True
    before=len(warnings);select='id,userId,userPrincipalName,riskEventType,riskLevel,riskState,riskDetail,source,detectionTimingType,activity,ipAddress,activityDateTime,detectedDateTime,lastUpdatedDateTime';data=_graph_get(token,_graph_url('identityProtection/riskDetections',{'$select':select,'$filter':filt,'$top':'50'}),warnings,'Risk detections')
    if data is None:return [],False
    rows=[]
    for item in data.get('value',[]):
        if isinstance(item,dict):rows.append({'RiskEventType':item.get('riskEventType'),'RiskLevel':item.get('riskLevel'),'RiskState':item.get('riskState'),'RiskDetail':item.get('riskDetail'),'Activity':item.get('activity'),'Source':item.get('source'),'DetectionTimingType':item.get('detectionTimingType'),'IPAddress':item.get('ipAddress'),'ActivityDateTime':item.get('activityDateTime'),'DetectedDateTime':item.get('detectedDateTime'),'LastUpdatedDateTime':item.get('lastUpdatedDateTime')})
    rows.sort(key=lambda x:str(x.get('DetectedDateTime') or x.get('ActivityDateTime') or ''),reverse=True);return rows,len(warnings)==before

def _graph_profile(token,account,warnings):
    key=account['id'] or account['upn'];
    if not key:return {},''
    select='id,userPrincipalName,displayName,city,country,department,jobTitle,officeLocation,companyName';data=_graph_get(token,_graph_url('users/'+urllib.parse.quote(key,safe='@.-_'),{'$select':select}),warnings,'User profile') or {};user_id=str(data.get('id') or account['id'] or '');manager={}
    if user_id:
        manager_data=_graph_get(token,_graph_url('users/'+urllib.parse.quote(user_id,safe='-_')+'/manager',{'$select':'id,displayName,userPrincipalName'}),warnings,'Manager lookup',ignore_http=(404,));manager=manager_data if isinstance(manager_data,dict) else {}
    return {'City':data.get('city'),'Country':data.get('country'),'Department':data.get('department'),'JobTitle':data.get('jobTitle'),'Office':data.get('officeLocation'),'Company':data.get('companyName'),'DisplayName':data.get('displayName'),'ManagerUPN':manager.get('userPrincipalName'),'ManagerName':manager.get('displayName')},user_id

def _graph_registration(token,user_id,warnings):
    if not user_id:return {}
    data=_graph_get(token,_graph_url('reports/authenticationMethods/userRegistrationDetails/'+urllib.parse.quote(user_id,safe='-_'),{'$select':'isMfaRegistered,isSsprEnabled,isSsprRegistered'}),warnings,'Authentication registration') or {};return {'MfaRegistered':data.get('isMfaRegistered'),'SSPREnabled':data.get('isSsprEnabled'),'SSPRRegistered':data.get('isSsprRegistered')}
def _graph_roles(token,user_id,warnings):
    if not user_id:return None
    assignments=_graph_get(token,_graph_url('roleManagement/directory/roleAssignments',{'$select':'roleDefinitionId','$filter':f"principalId eq '{user_id}'"}),warnings,'Directory role assignments')
    if assignments is None:return None
    names=[];cache={}
    for assignment in assignments.get('value',[]):
        role_id=assignment.get('roleDefinitionId') if isinstance(assignment,dict) else None
        if not role_id:continue
        if role_id not in cache:
            role=_graph_get(token,_graph_url('roleManagement/directory/roleDefinitions/'+urllib.parse.quote(str(role_id),safe='-_'),{'$select':'displayName'}),warnings,'Directory role definition') or {};cache[role_id]=role.get('displayName')
        if cache.get(role_id):names.append(str(cache[role_id]))
    return sorted(set(names))

def query_aad_risks(req):
    accounts=_accounts(req.base);days=max(1,min(int(req.lookback_days),90));credential=DefaultAzureCredential(exclude_interactive_browser_credential=True);token=credential.get_token('https://graph.microsoft.com/.default').token;logs=LogsQueryClient(credential);details=[];warnings=[];all_events=[];risk_user_available=True;risk_events_available=True
    for account in accounts:
        aw=[];failed=fraud=0;upn=account['upn'];profile,profile_uid=_graph_profile(token,account,aw);uid=profile_uid or account['id'];incident_account={'id':uid,'upn':upn};risky,risky_ok=_graph_risky_user(token,incident_account,aw);events,events_ok=_graph_risk_detections(token,incident_account,aw);risk_user_available=risk_user_available and risky_ok;risk_events_available=risk_events_available and events_ok
        for event in events:all_events.append({'UserPrincipalName':upn,'UserId':uid,**event})
        registration=_graph_registration(token,uid,aw);roles=_graph_roles(token,uid,aw);risk=str(risky.get('riskLevel') or ('none' if risky_ok else 'unknown')).lower();risk='unknown' if risk in ('hidden','unknownfuturevalue') else risk
        if upn and (req.mfa_failure_lookup or req.mfa_fraud_lookup):
            query=_mfa_telemetry_query(upn,days,req.mfa_failure_lookup,req.mfa_fraud_lookup)
            try:
                result=logs.query_workspace(req.workspace_id,query,timespan=timedelta(days=days),server_timeout=20)
                if result.status==LogsQueryStatus.SUCCESS and result.tables:
                    t=result.tables[0];names=_column_names(t.columns)
                    for row in t.rows:
                        d=dict(zip(names,row));failed=int(d.get('Count',0)) if d.get('Kind')=='failed' else failed;fraud=int(d.get('Count',0)) if d.get('Kind')=='fraud' else fraud
                elif result.status!=LogsQueryStatus.SUCCESS:aw.append('MFA telemetry query did not complete successfully')
            except Exception as exc:aw.append(f'MFA telemetry query failed ({type(exc).__name__}: {str(exc)[:160]})')
        detail={'UserFailedMFACount':failed,'UserMFAFraudCount':fraud,'UserId':uid,'UserPrincipalName':upn,'UserRiskLevel':risk,'UserRiskState':risky.get('riskState') if risky else None,'UserRiskDetail':risky.get('riskDetail') if risky else None,'UserRiskLastUpdated':risky.get('riskLastUpdatedDateTime') if risky else None,'RiskEventCount':len(events),'RiskUserAvailable':risky_ok,'RiskEventsAvailable':events_ok,'AADRoles':roles,**profile,**registration}
        if aw:detail['EnrichmentWarnings']=sorted(set(aw))
        details.append(detail);warnings.extend(aw)
    highest=max((x['UserRiskLevel'] for x in details),key=lambda x:RANK.get(x,0),default='unknown');return {'AnalyzedEntities':len(details),'FailedMFATotalCount':sum(x['UserFailedMFACount'] for x in details),'HighestRiskLevel':highest,'MFAFraudTotalCount':sum(x['UserMFAFraudCount'] for x in details),'RiskEventCount':len(all_events),'RiskEvents':all_events,'RiskUserAvailable':risk_user_available,'RiskEventsAvailable':risk_events_available,'ModuleName':'AADRisksModule','DetailedResults':details,'EnrichmentWarnings':sorted(set(warnings))}
