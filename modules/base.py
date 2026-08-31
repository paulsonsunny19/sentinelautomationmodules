from __future__ import annotations
from typing import Any
import ipaddress, json, urllib.error, urllib.parse, urllib.request
from azure.identity import DefaultAzureCredential

# Primary workspace-scoped Sentinel GeoIP API.
SENTINEL_ENRICHMENT_API_VERSION = '2025-07-01-preview'
# Compatibility fallback used by the original Sentinel GeoIP surface.
SENTINEL_LEGACY_ENRICHMENT_API_VERSION = '2024-01-01-preview'

def _props(entity:dict[str,Any])->dict[str,Any]:
    value=entity.get('properties'); return value if isinstance(value,dict) else entity

def _kind(entity:dict[str,Any])->str:return str(entity.get('kind') or _props(entity).get('kind') or '').lower()
def _raw(entity:dict[str,Any])->dict[str,Any]:
    raw=dict(_props(entity)); raw.pop('kind',None); return raw

def _arm_scope(incident_arm_id:str)->tuple[str|None,str|None,str|None]:
    parts=[urllib.parse.unquote(x) for x in str(incident_arm_id or '').strip('/').split('/')]; lower=[x.lower() for x in parts]
    def after(name):
        try:return parts[lower.index(name)+1]
        except (ValueError,IndexError):return None
    subscription=after('subscriptions'); resource_group=after('resourcegroups')
    workspace=None
    try:
        wi=lower.index('workspaces'); workspace=parts[wi+1]
    except (ValueError,IndexError): pass
    return subscription,resource_group,workspace

def _parsed_ip(value:Any):
    try:return ipaddress.ip_address(str(value).strip())
    except (ValueError,TypeError):return None

def _public_ip(value:Any)->str|None:
    parsed=_parsed_ip(value)
    return str(parsed) if parsed and parsed.is_global else None

def _normalize_geodata(data:Any)->dict[str,Any]:
    if not isinstance(data,dict): return {}
    props=data.get('properties')
    if isinstance(props,dict): data=props
    useful=('city','state','country','organization','organizationType','asn','carrier','region','continent','latitude','longitude','ipAddr','ipRoutingType')
    return {k:data.get(k) for k in useful if data.get(k) not in (None,'')}

def _http_error_detail(exc:urllib.error.HTTPError)->str:
    try:
        payload=json.loads(exc.read().decode())
        err=payload.get('error') if isinstance(payload,dict) else None
        if isinstance(err,dict):
            code=str(err.get('code') or '').strip(); message=' '.join(str(err.get('message') or '').split())[:220]
            if code and message:return f'{code}: {message}'
            if code:return code
            if message:return message
    except Exception: pass
    return ''

def _request_json(request:urllib.request.Request)->tuple[dict[str,Any],str|None]:
    try:
        with urllib.request.urlopen(request,timeout=15) as response:
            data=json.loads(response.read().decode())
            geo=_normalize_geodata(data)
            if geo:return geo,None
            return {},'returned an empty or unrecognized geodata payload'
    except urllib.error.HTTPError as exc:
        detail=_http_error_detail(exc)
        return {},f'HTTP {exc.code}'+(f' ({detail})' if detail else '')
    except urllib.error.URLError as exc:return {},f'connection failed ({type(exc.reason).__name__})'
    except Exception as exc:return {},f'lookup failed ({type(exc).__name__})'

def _sentinel_geodata(credential:DefaultAzureCredential,subscription:str,resource_group:str,workspace:str,ip:str)->tuple[dict[str,Any],str|None]:
    token=credential.get_token('https://management.azure.com/.default').token
    headers={'Authorization':f'Bearer {token}','Accept':'application/json'}
    primary_url=(f'https://management.azure.com/subscriptions/{urllib.parse.quote(subscription,safe="")}/resourceGroups/{urllib.parse.quote(resource_group,safe="")}'
         f'/providers/Microsoft.OperationalInsights/workspaces/{urllib.parse.quote(workspace,safe="")}'
         f'/providers/Microsoft.SecurityInsights/enrichment/main/listGeodataByIp?api-version={SENTINEL_ENRICHMENT_API_VERSION}')
    primary=urllib.request.Request(primary_url,data=json.dumps({'ipAddress':ip}).encode(),method='POST',headers={**headers,'Content-Type':'application/json'})
    geo,primary_error=_request_json(primary)
    if geo:return geo,None

    # Keep a compatibility path matching the long-standing Sentinel GeoIP endpoint.
    legacy_url=(f'https://management.azure.com/subscriptions/{urllib.parse.quote(subscription,safe="")}/resourceGroups/{urllib.parse.quote(resource_group,safe="")}'
        f'/providers/Microsoft.SecurityInsights/enrichment/ip/geodata/?api-version={SENTINEL_LEGACY_ENRICHMENT_API_VERSION}'
        f'&ipAddress={urllib.parse.quote(ip,safe="")}')
    legacy=urllib.request.Request(legacy_url,method='GET',headers=headers)
    geo,legacy_error=_request_json(legacy)
    if geo:return geo,None
    return {},f'Sentinel GeoIP failed for {ip}: workspace API {primary_error}; compatibility API {legacy_error}'

def normalize_entities(entities:list[dict[str,Any]],incident_arm_id:str,workspace_id:str)->dict[str,Any]:
    accounts=[];ips=[];hosts=[];files=[];hashes=[];domains=[];urls=[];other=[]
    for entity in entities:
        if not isinstance(entity,dict):continue
        p=_props(entity);kind=_kind(entity);raw=_raw(entity)
        if kind=='account':accounts.append({'UserPrincipalName':p.get('userPrincipalName') or p.get('upn') or p.get('friendlyName'),'AADUserId':p.get('aadUserId') or p.get('id'),'Name':p.get('accountName') or p.get('name'),'NTDomain':p.get('ntDomain'),'RawEntity':raw})
        elif kind in {'ip','ipaddress'}:
            address=p.get('address') or p.get('ipAddress') or p.get('friendlyName'); parsed=_parsed_ip(address)
            ips.append({'Address':str(parsed) if parsed else address,'IsPublic':bool(parsed and parsed.is_global),'GeoData':{},'GeoEnriched':False,'RawEntity':raw})
        elif kind=='host':
            hostname=p.get('hostName') or p.get('hostname') or p.get('friendlyName');dns=p.get('dnsDomain');hosts.append({'Hostname':hostname,'DnsDomain':dns,'FQDN':f'{hostname}.{dns}' if hostname and dns else hostname,'RawEntity':raw})
        elif kind=='file':files.append({'Name':p.get('fileName') or p.get('name') or p.get('friendlyName'),'Directory':p.get('directory'),'RawEntity':raw})
        elif kind in {'filehash','filehashvalue'}:hashes.append({'HashValue':p.get('hashValue') or p.get('value') or p.get('friendlyName'),'Algorithm':p.get('algorithm'),'RawEntity':raw})
        elif kind in {'dnsresolution','dnsdomain','domain'}:domains.append({'DomainName':p.get('domainName') or p.get('friendlyName'),'RawEntity':raw})
        elif kind=='url':urls.append({'Url':p.get('url') or p.get('friendlyName'),'RawEntity':raw})
        else:other.append(entity)
    return {'IncidentARMId':incident_arm_id,'WorkspaceId':workspace_id,'EntitiesCount':len(entities),'Accounts':accounts,'AccountsCount':len(accounts),'IPs':ips,'IPsCount':len(ips),'Hosts':hosts,'HostsCount':len(hosts),'Files':files,'FilesCount':len(files),'FileHashes':hashes,'FileHashesCount':len(hashes),'Domains':domains,'DomainsCount':len(domains),'URLs':urls,'URLsCount':len(urls),'OtherEntities':other,'OtherEntitiesCount':len(other)}

def normalize(entities:list[dict[str,Any]],incident_arm_id:str,workspace_id:str,tenant_id:str|None=None,tenant_display_name:str|None=None)->dict[str,Any]:
    result=normalize_entities(entities,incident_arm_id,workspace_id)
    if tenant_id:result['TenantId']=tenant_id
    if tenant_display_name:result['TenantDisplayName']=tenant_display_name
    subscription,resource_group,workspace=_arm_scope(incident_arm_id);warnings=[];public=[x for x in result['IPs'] if x.get('IsPublic')]
    if public and subscription and resource_group and workspace:
        credential=DefaultAzureCredential(exclude_interactive_browser_credential=True);cache={}
        for entity in public:
            ip=_public_ip(entity.get('Address'))
            if not ip:continue
            if ip not in cache:cache[ip]=_sentinel_geodata(credential,subscription,resource_group,workspace,ip)
            geo,warning=cache[ip];entity['GeoData']=geo;entity['GeoEnriched']=bool(geo)
            if warning:warnings.append(warning)
    elif public:warnings.append('Sentinel GeoIP skipped: incident ARM ID did not contain subscription/resource group/workspace scope')
    result['PublicIPsCount']=len(public)
    result['GeoEnrichedIPsCount']=sum(1 for x in result['IPs'] if x.get('GeoEnriched'))
    if warnings:result['EnrichmentWarnings']=sorted(set(warnings))
    return result
