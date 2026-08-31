from __future__ import annotations

from dataclasses import dataclass
from typing import Any
import ipaddress
import json
import urllib.error
import urllib.parse
import urllib.request

from azure.identity import DefaultAzureCredential

SENTINEL_ENRICHMENT_API_VERSION = '2025-07-01-preview'
SENTINEL_LEGACY_ENRICHMENT_API_VERSION = '2024-01-01-preview'


@dataclass(frozen=True)
class IPEnrichmentRequest:
    base: dict[str, Any]


def _arm_scope(incident_arm_id: str) -> tuple[str | None, str | None, str | None]:
    parts = [urllib.parse.unquote(x) for x in str(incident_arm_id or '').strip('/').split('/')]
    lower = [x.lower() for x in parts]

    def after(name: str):
        try:
            return parts[lower.index(name) + 1]
        except (ValueError, IndexError):
            return None

    subscription = after('subscriptions')
    resource_group = after('resourcegroups')
    workspace = None
    try:
        wi = lower.index('workspaces')
        workspace = parts[wi + 1]
    except (ValueError, IndexError):
        pass
    return subscription, resource_group, workspace


def _public_ip(value: Any) -> str | None:
    try:
        parsed = ipaddress.ip_address(str(value).strip())
    except (ValueError, TypeError):
        return None
    return str(parsed) if parsed.is_global else None


def _normalize_geodata(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        return {}
    props = data.get('properties')
    if isinstance(props, dict):
        data = props
    useful = (
        'city', 'state', 'country', 'organization', 'organizationType', 'asn',
        'carrier', 'region', 'continent', 'latitude', 'longitude', 'ipAddr',
        'ipRoutingType',
    )
    return {k: data.get(k) for k in useful if data.get(k) not in (None, '')}


def _http_error_detail(exc: urllib.error.HTTPError) -> str:
    try:
        payload = json.loads(exc.read().decode())
        err = payload.get('error') if isinstance(payload, dict) else None
        if isinstance(err, dict):
            code = str(err.get('code') or '').strip()
            message = ' '.join(str(err.get('message') or '').split())[:220]
            if code and message:
                return f'{code}: {message}'
            return code or message
    except Exception:
        pass
    return ''


def _request_json(request: urllib.request.Request) -> tuple[dict[str, Any], str | None]:
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            data = json.loads(response.read().decode())
            geo = _normalize_geodata(data)
            return (geo, None) if geo else ({}, 'returned an empty or unrecognized geodata payload')
    except urllib.error.HTTPError as exc:
        detail = _http_error_detail(exc)
        return {}, f'HTTP {exc.code}' + (f' ({detail})' if detail else '')
    except urllib.error.URLError as exc:
        return {}, f'connection failed ({type(exc.reason).__name__})'
    except Exception as exc:
        return {}, f'lookup failed ({type(exc).__name__})'


def _sentinel_geodata(
    credential: DefaultAzureCredential,
    subscription: str,
    resource_group: str,
    workspace: str,
    ip: str,
) -> tuple[dict[str, Any], str | None]:
    token = credential.get_token('https://management.azure.com/.default').token
    headers = {'Authorization': f'Bearer {token}', 'Accept': 'application/json'}
    primary_url = (
        f'https://management.azure.com/subscriptions/{urllib.parse.quote(subscription, safe="")}'
        f'/resourceGroups/{urllib.parse.quote(resource_group, safe="")}'
        f'/providers/Microsoft.OperationalInsights/workspaces/{urllib.parse.quote(workspace, safe="")}'
        f'/providers/Microsoft.SecurityInsights/enrichment/main/listGeodataByIp'
        f'?api-version={SENTINEL_ENRICHMENT_API_VERSION}'
    )
    primary = urllib.request.Request(
        primary_url,
        data=json.dumps({'ipAddress': ip}).encode(),
        method='POST',
        headers={**headers, 'Content-Type': 'application/json'},
    )
    geo, primary_error = _request_json(primary)
    if geo:
        return geo, None

    legacy_url = (
        f'https://management.azure.com/subscriptions/{urllib.parse.quote(subscription, safe="")}'
        f'/resourceGroups/{urllib.parse.quote(resource_group, safe="")}'
        f'/providers/Microsoft.SecurityInsights/enrichment/ip/geodata/'
        f'?api-version={SENTINEL_LEGACY_ENRICHMENT_API_VERSION}'
        f'&ipAddress={urllib.parse.quote(ip, safe="")}'
    )
    legacy = urllib.request.Request(legacy_url, method='GET', headers=headers)
    geo, legacy_error = _request_json(legacy)
    if geo:
        return geo, None
    return {}, (
        f'Sentinel GeoIP failed for {ip}: workspace API {primary_error}; '
        f'compatibility API {legacy_error}'
    )


def query_ip_enrichment(req: IPEnrichmentRequest) -> dict[str, Any]:
    ips: list[str] = []
    for item in req.base.get('IPs', []):
        if not isinstance(item, dict):
            continue
        raw = item.get('RawEntity') if isinstance(item.get('RawEntity'), dict) else item
        ip = _public_ip(item.get('Address') or raw.get('address') or raw.get('ipAddress'))
        if ip and ip not in ips:
            ips.append(ip)

    result: dict[str, Any] = {
        'ModuleName': 'IPEnrichmentModule',
        'IPsAnalyzedCount': len(ips),
        'IPsEnrichedCount': 0,
        'DetailedResults': [],
    }
    if not ips:
        return result

    subscription, resource_group, workspace = _arm_scope(req.base.get('IncidentARMId', ''))
    if not (subscription and resource_group and workspace):
        result['EnrichmentWarnings'] = [
            'Sentinel GeoIP skipped: incident ARM ID did not contain subscription/resource group/workspace scope'
        ]
        return result

    credential = DefaultAzureCredential(exclude_interactive_browser_credential=True)
    warnings: list[str] = []
    details: list[dict[str, Any]] = []
    for ip in ips:
        geo, warning = _sentinel_geodata(credential, subscription, resource_group, workspace, ip)
        detail = {
            'IPAddress': ip,
            'Enriched': bool(geo),
            'Source': 'Microsoft Sentinel GeoData' if geo else 'Microsoft Sentinel GeoData (unavailable)',
            **geo,
        }
        if warning:
            detail['Warning'] = warning
            warnings.append(warning)
        details.append(detail)

    result['DetailedResults'] = details
    result['IPsEnrichedCount'] = sum(1 for item in details if item.get('Enriched'))
    if warnings:
        result['EnrichmentWarnings'] = sorted(set(warnings))
    return result
