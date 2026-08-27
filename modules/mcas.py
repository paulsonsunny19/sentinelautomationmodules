from __future__ import annotations
from dataclasses import dataclass
from typing import Any
import json, os, urllib.parse, urllib.request
from azure.identity import DefaultAzureCredential

@dataclass(frozen=True)
class MCASRequest:
    base: dict[str, Any]
    score_threshold: int = 0
    portal_url: str | None = None


def _accounts(base:dict[str,Any])->list[dict[str,str]]:
    out=[]
    for x in base.get('Accounts',[]):
        r=x.get('RawEntity',x); uid=x.get('AADUserId') or r.get('aadUserId') or r.get('objectGuid'); upn=x.get('UserPrincipalName') or r.get('userPrincipalName') or r.get('upn')
        if uid or upn: out.append({'id':str(uid or ''),'upn':str(upn or '')})
    return out


def _request(credential:DefaultAzureCredential,url:str)->dict[str,Any]:
    token=credential.get_token('https://api.cloudapp.net/.default').token
    req=urllib.request.Request(url,headers={'Authorization':f'Bearer {token}','Accept':'application/json'})
    with urllib.request.urlopen(req,timeout=20) as response:return json.loads(response.read().decode())


def query_mcas(req:MCASRequest)->dict[str,Any]:
    accounts=_accounts(req.base); threshold=int(req.score_threshold); credential=DefaultAzureCredential(exclude_interactive_browser_credential=True)
    portal=(req.portal_url or os.getenv('STAT_MCAS_PORTAL_URL') or '').rstrip('/'); details=[]
    if not portal:
        # Current deployments should explicitly configure the tenant's Defender for Cloud Apps portal URL.
        return {'AboveThreholdCount':0,'AboveThresholdCount':0,'AnalyzedEntities':len(accounts),'DetailedResults':[],'MaximumScore':0,'ModuleName':'MCASModule','ConfigurationRequired':True,'ConfigurationMessage':'Set STAT_MCAS_PORTAL_URL to the Defender for Cloud Apps tenant portal URL.'}
    api_base=portal.replace('.portal.cloudappsecurity.com','.portal.cloudappsecurity.com/api/v1') if '/api/' not in portal else portal
    for account in accounts:
        score=0; history=[]
        # STAT v1/v2 used the MCAS investigation score API. Keep the contract while using managed identity.
        candidates=[]
        if account['id']: candidates.append(api_base+'/entities/'+urllib.parse.quote(account['id'],safe='')+'/investigationScore')
        if account['upn']: candidates.append(api_base+'/entities/'+urllib.parse.quote(account['upn'],safe='')+'/investigationScore')
        for url in candidates:
            try:
                data=_request(credential,url); score=int(data.get('score') or data.get('threatScore') or data.get('investigationScore') or 0); history=data.get('history') or data.get('threatScoreHistory') or []; break
            except Exception: continue
        details.append({'ThreatScore':score,'UserId':account['id'],'UserPrincipalName':account['upn'],'ThreatScoreHistory':history})
    maximum=max((x['ThreatScore'] for x in details),default=0); above=sum(1 for x in details if x['ThreatScore']>=threshold)
    return {'AboveThreholdCount':above,'AboveThresholdCount':above,'AnalyzedEntities':len(details),'DetailedResults':details,'MaximumScore':maximum,'ModuleName':'MCASModule'}
