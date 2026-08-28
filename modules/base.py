from __future__ import annotations

from typing import Any
import ipaddress
import json
import urllib.error
import urllib.parse
import urllib.request

from azure.identity import DefaultAzureCredential


def _props(entity: dict[str, Any]) -> dict[str, Any]:
    value = entity.get("properties")
    return value if isinstance(value, dict) else entity


def _kind(entity: dict[str, Any]) -> str:
    return str(entity.get("kind") or _props(entity).get("kind") or "").lower()


def _raw(entity: dict[str, Any]) -> dict[str, Any]:
    p = _props(entity)
    raw = dict(p)
    raw.pop("kind", None)
    return raw


def _arm_scope(incident_arm_id: str) -> tuple[str | None, str | None]:
    parts=[urllib.parse.unquote(x) for x in str(incident_arm_id or '').strip('/').split('/')]
    lower=[x.lower() for x in parts]
    try: subscription=parts[lower.index('subscriptions')+1]
    except (ValueError,IndexError): subscription=None
    try: resource_group=parts[lower.index('resourcegroups')+1]
    except (ValueError,IndexError): resource_group=None
    return subscription,resource_group


def _public_ip(value: Any) -> str | None:
    try:
        parsed=ipaddress.ip_address(str(value))
        return str(parsed) if parsed.is_global else None
    except (ValueError,TypeError):
        return None


def _sentinel_geodata(credential: DefaultAzureCredential, subscription: str, resource_group: str, ip: str) -> tuple[dict[str,Any],str | None]:
    """Use Microsoft Sentinel's native IP geodata enrichment API.

    This returns the same field family documented by original STAT Base: ASN, carrier,
    city, continent, country, routing type, coordinates, organization/type, region and state.
    """
    token=credential.get_token('https://management.azure.com/.default').token
    url=(f'https://management.azure.com/subscriptions/{urllib.parse.quote(subscription,safe="")}'
         f'/resourceGroups/{urllib.parse.quote(resource_group,safe="")}'
         '/providers/Microsoft.SecurityInsights/enrichment/ip/geodata/'
         f'?api-version=2024-01-01-preview&ipAddress={urllib.parse.quote(ip,safe=".:")}' )
    request=urllib.request.Request(url,headers={'Authorization':f'Bearer {token}','Accept':'application/json'})
    try:
        with urllib.request.urlopen(request,timeout=15) as response:
            data=json.loads(response.read().decode())
            return (data if isinstance(data,dict) else {}),None
    except urllib.error.HTTPError as exc:
        return {},f'Sentinel GeoIP returned HTTP {exc.code} for {ip}'
    except urllib.error.URLError as exc:
        return {},f'Sentinel GeoIP connection failed for {ip} ({type(exc.reason).__name__})'
    except Exception as exc:
        return {},f'Sentinel GeoIP lookup failed for {ip} ({type(exc).__name__})'


def normalize_entities(entities: list[dict[str, Any]], incident_arm_id: str, workspace_id: str) -> dict[str, Any]:
    accounts=[]; ips=[]; hosts=[]; files=[]; hashes=[]; domains=[]; urls=[]; other=[]
    for entity in entities:
        if not isinstance(entity,dict): continue
        p=_props(entity); kind=_kind(entity); raw=_raw(entity)
        if kind=='account':
            accounts.append({'UserPrincipalName':p.get('userPrincipalName') or p.get('upn') or p.get('friendlyName'),'AADUserId':p.get('aadUserId') or p.get('id'),'Name':p.get('accountName') or p.get('name'),'NTDomain':p.get('ntDomain'),'RawEntity':raw})
        elif kind in {'ip','ipaddress'}:
            ips.append({'Address':p.get('address') or p.get('ipAddress') or p.get('friendlyName'),'GeoData':{},'RawEntity':raw})
        elif kind=='host':
            hostname=p.get('hostName') or p.get('hostname') or p.get('friendlyName'); dns=p.get('dnsDomain')
            hosts.append({'Hostname':hostname,'DnsDomain':dns,'FQDN':f'{hostname}.{dns}' if hostname and dns else hostname,'RawEntity':raw})
        elif kind=='file': files.append({'Name':p.get('fileName') or p.get('name') or p.get('friendlyName'),'Directory':p.get('directory'),'RawEntity':raw})
        elif kind in {'filehash','filehashvalue'}: hashes.append({'HashValue':p.get('hashValue') or p.get('value') or p.get('friendlyName'),'Algorithm':p.get('algorithm'),'RawEntity':raw})
        elif kind in {'dnsresolution','dnsdomain','domain'}: domains.append({'DomainName':p.get('domainName') or p.get('friendlyName'),'RawEntity':raw})
        elif kind=='url': urls.append({'Url':p.get('url') or p.get('friendlyName'),'RawEntity':raw})
        else: other.append(entity)
    return {'IncidentARMId':incident_arm_id,'WorkspaceId':workspace_id,'EntitiesCount':len(entities),'Accounts':accounts,'AccountsCount':len(accounts),'IPs':ips,'IPsCount':len(ips),'Hosts':hosts,'HostsCount':len(hosts),'Files':files,'FilesCount':len(files),'FileHashes':hashes,'FileHashesCount':len(hashes),'Domains':domains,'DomainsCount':len(domains),'URLs':urls,'URLsCount':len(urls),'OtherEntities':other,'OtherEntitiesCount':len(other)}


def normalize(entities: list[dict[str,Any]], incident_arm_id: str, workspace_id: str, tenant_id: str | None=None, tenant_display_name: str | None=None) -> dict[str,Any]:
    """Normalize and enrich entities using the original STAT Base architecture."""
    result=normalize_entities(entities,incident_arm_id,workspace_id)
    if tenant_id: result['TenantId']=tenant_id
    if tenant_display_name: result['TenantDisplayName']=tenant_display_name
    subscription,resource_group=_arm_scope(incident_arm_id); warnings=[]
    public=[x for x in result['IPs'] if _public_ip(x.get('Address'))]
    if public and subscription and resource_group:
        credential=DefaultAzureCredential(exclude_interactive_browser_credential=True)
        cache={}
        for entity in public:
            ip=_public_ip(entity.get('Address'))
            if not ip: continue
            if ip not in cache: cache[ip]=_sentinel_geodata(credential,subscription,resource_group,ip)
            geo,warning=cache[ip]; entity['GeoData']=geo
            if warning: warnings.append(warning)
    elif public:
        warnings.append('Sentinel GeoIP skipped: incident ARM ID did not contain subscription/resource group scope')
    if warnings: result['EnrichmentWarnings']=sorted(set(warnings))
    return result
