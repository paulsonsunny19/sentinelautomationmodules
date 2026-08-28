from __future__ import annotations
from dataclasses import dataclass
from typing import Any
import ipaddress
import json, urllib.parse, urllib.request
from azure.identity import DefaultAzureCredential

@dataclass(frozen=True)
class MDERequest:
    base: dict[str, Any]
    lookback_days: int = 14

RANK={'unknown':0,'none':1,'low':2,'medium':3,'high':4}

def _highest(values:list[str])->str:
    return max((str(v or 'Unknown') for v in values),key=lambda x:RANK.get(x.lower(),0),default='Unknown')

def _api(credential:DefaultAzureCredential,path:str)->dict[str,Any]:
    token=credential.get_token('https://api.securitycenter.microsoft.com/.default').token
    req=urllib.request.Request('https://api.securitycenter.microsoft.com/api/'+path,headers={'Authorization':f'Bearer {token}','Accept':'application/json'})
    with urllib.request.urlopen(req,timeout=20) as r:return json.loads(r.read().decode())

def _machines(credential:DefaultAzureCredential,filter_expr:str)->list[dict[str,Any]]:
    try:return _api(credential,'machines?$filter='+urllib.parse.quote(filter_expr,safe=" ='@.-")).get('value',[])
    except Exception:return []

def _advanced_query(credential:DefaultAzureCredential,query:str)->list[dict[str,Any]]:
    try:
        token=credential.get_token('https://api.securitycenter.microsoft.com/.default').token
        body=json.dumps({'Query':query}).encode()
        request=urllib.request.Request('https://api.securitycenter.microsoft.com/api/advancedqueries/run',data=body,method='POST',headers={'Authorization':f'Bearer {token}','Content-Type':'application/json','Accept':'application/json'})
        with urllib.request.urlopen(request,timeout=20) as response:
            data=json.loads(response.read().decode())
            return [x for x in data.get('Results',[]) if isinstance(x,dict)]
    except Exception:return []

def _public_ip(value:Any)->str|None:
    try:
        ip=ipaddress.ip_address(str(value)); return str(ip) if ip.is_global else None
    except (ValueError,TypeError): return None

def _ip_geo(credential:DefaultAzureCredential,ip:str,days:int)->dict[str,Any]:
    # Defender XDR enriches public RemoteIP observations with GeoIP fields. We query only
    # the incident IP and return a bounded, normalized result; no third-party service is used.
    safe=ip.replace("'","''")
    query=(f"DeviceNetworkEvents | where Timestamp > ago({days}d) | where RemoteIP == '{safe}' "
           "| summarize arg_max(Timestamp, RemoteIPCountry, RemoteIPState, RemoteIPCity, RemoteIPOrganization, RemoteIPOrganizationType, RemoteIPASN) by RemoteIP "
           "| project IP=RemoteIP, Country=RemoteIPCountry, State=RemoteIPState, City=RemoteIPCity, Organization=RemoteIPOrganization, OrganizationType=RemoteIPOrganizationType, ASN=RemoteIPASN")
    rows=_advanced_query(credential,query)
    return rows[0] if rows else {}

def query_mde(req:MDERequest)->dict[str,Any]:
    credential=DefaultAzureCredential(exclude_interactive_browser_credential=True); days=max(1,min(int(req.lookback_days),30))
    account_results=[]; ip_results=[]; host_results=[]; ip_enrichment=[]; warnings=[]
    for x in req.base.get('Accounts',[]):
        raw=x.get('RawEntity',x); sid=x.get('ObjectSID') or raw.get('sid'); upn=x.get('UserPrincipalName') or raw.get('userPrincipalName'); uid=x.get('AADUserId') or raw.get('aadUserId'); devices=[]
        if sid:
            query=f"DeviceLogonEvents | where Timestamp > ago({days}d) | where AccountSid == '{str(sid).replace(chr(39),chr(39)*2)}' | where LogonType == 'Interactive' | summarize by DeviceId"
            for row in _advanced_query(credential,query):
                mid=row.get('DeviceId')
                if mid:
                    try: devices.append(_api(credential,'machines/'+urllib.parse.quote(str(mid),safe='')))
                    except Exception: pass
        account_results.append({'UserDevices':devices,'UserHighestExposureLevel':_highest([d.get('exposureLevel') for d in devices]),'UserHighestRiskScore':_highest([d.get('riskScore') for d in devices]),'UserId':uid,'UserPrincipalName':upn,'UserSid':sid})
    for x in req.base.get('IPs',[]):
        raw=x.get('RawEntity',x); ip=x.get('Address') or raw.get('address'); machines=_machines(credential,f"lastIpAddress eq '{ip}'") if ip else []
        for m in machines: m['EntityIPAddress']=ip
        ip_results.extend(machines)
        public=_public_ip(ip)
        if public:
            geo=_ip_geo(credential,public,days)
            ip_enrichment.append({'IP':public,'City':geo.get('City'),'State':geo.get('State'),'Country':geo.get('Country'),'Organization':geo.get('Organization'),'OrganizationType':geo.get('OrganizationType'),'ASN':geo.get('ASN'),'Source':'Microsoft Defender XDR'})
            if not geo: warnings.append(f'IP enrichment: no Defender XDR GeoIP observation returned for {public}')
        elif ip:
            ip_enrichment.append({'IP':str(ip),'City':None,'State':None,'Country':None,'Organization':None,'OrganizationType':None,'ASN':None,'Source':'Private/reserved IP - GeoIP not applicable'})
    for x in req.base.get('Hosts',[]):
        raw=x.get('RawEntity',x); mid=raw.get('mdatpDeviceId') or raw.get('MdatpDeviceId'); fqdn=x.get('FQDN') or x.get('Hostname'); machines=[]
        if mid:
            try: machines=[_api(credential,'machines/'+urllib.parse.quote(str(mid),safe=''))]
            except Exception: pass
        elif fqdn: machines=_machines(credential,f"computerDnsName eq '{str(fqdn).replace(chr(39),chr(39)*2)}'")
        host_results.extend(machines)
    result={'AnalyzedEntities':len(account_results)+len(req.base.get('IPs',[]))+len(req.base.get('Hosts',[])),'IPsHighestExposureLevel':_highest([x.get('exposureLevel') for x in ip_results]),'IPsHighestRiskScore':_highest([x.get('riskScore') for x in ip_results]),'UsersHighestExposureLevel':_highest([x.get('UserHighestExposureLevel') for x in account_results]),'UsersHighestRiskScore':_highest([x.get('UserHighestRiskScore') for x in account_results]),'HostsHighestExposureLevel':_highest([x.get('exposureLevel') for x in host_results]),'HostsHighestRiskScore':_highest([x.get('riskScore') for x in host_results]),'IPEnrichment':ip_enrichment,'ModuleName':'MDEModule','DetailedResults':{'Accounts':account_results,'IPs':ip_results,'Hosts':host_results}}
    if warnings: result['EnrichmentWarnings']=sorted(set(warnings))
    return result
