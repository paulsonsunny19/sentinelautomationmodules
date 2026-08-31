from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Any
import ipaddress

from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient, LogsQueryStatus


@dataclass(frozen=True)
class IPBaselineRequest:
    workspace_id: str
    base: dict[str, Any]
    lookback_days: int = 30


def _public_ips(base: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for item in base.get('IPs', []):
        value = item.get('Address') if isinstance(item, dict) else None
        try:
            parsed = ipaddress.ip_address(str(value))
        except (ValueError, TypeError):
            continue
        if parsed.is_global:
            values.append(str(parsed))
    return list(dict.fromkeys(values))


def classify_baseline(connections: int, devices: int, active_days: int) -> tuple[str, int, str]:
    """Return (state, score, rationale).

    Absence is deliberately informational only because the module cannot infer
    estate telemetry coverage from DeviceNetworkEvents alone.
    """
    if connections <= 0:
        return (
            'not_observed',
            0,
            'No prior connection was observed; absence is not scored because telemetry coverage is unknown.',
        )
    if devices >= 50 and active_days >= 20:
        return (
            'established_estate_peer',
            0,
            f'Observed from {devices} devices across {active_days} active days; treated as context, not a benign downgrade.',
        )
    if devices == 1 and active_days <= 2:
        return (
            'isolated_new_peer',
            5,
            f'Observed from one device across {active_days} active day(s), indicating weak estate prevalence.',
        )
    return (
        'observed_peer',
        0,
        f'Observed from {devices} devices across {active_days} active days.',
    )


def _empty(ips: list[str], warning: str | None = None) -> dict[str, Any]:
    details = []
    for ip in ips:
        state, score, rationale = classify_baseline(0, 0, 0)
        details.append({
            'IPAddress': ip,
            'Connections': 0,
            'Devices': 0,
            'ActiveDays': 0,
            'FirstSeen': None,
            'LastSeen': None,
            'BaselineState': state,
            'Score': score,
            'Rationale': rationale,
        })
    result: dict[str, Any] = {
        'ModuleName': 'IPNetworkBaselineModule',
        'IPsAnalyzedCount': len(ips),
        'IPsObservedCount': 0,
        'IsolatedNewPeerCount': 0,
        'EstablishedEstatePeerCount': 0,
        'DetailedResults': details,
        'ScoringData': [],
    }
    if warning:
        result['EnrichmentWarnings'] = [warning]
    return result


def query_ip_baseline(req: IPBaselineRequest) -> dict[str, Any]:
    days = max(1, min(int(req.lookback_days), 30))
    ips = _public_ips(req.base)
    if not ips:
        return _empty([])

    quoted = ','.join("'" + value.replace("'", "''") + "'" for value in ips)
    query = f'''let TargetIPs=dynamic([{quoted}]);
DeviceNetworkEvents
| where Timestamp >= ago({days}d)
| where RemoteIP in (TargetIPs)
| summarize Connections=count(), Devices=dcount(DeviceId), ActiveDays=dcount(startofday(Timestamp)), FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by IPAddress=RemoteIP'''

    try:
        client = LogsQueryClient(DefaultAzureCredential(exclude_interactive_browser_credential=True))
        response = client.query_workspace(
            req.workspace_id,
            query,
            timespan=timedelta(days=days),
            server_timeout=20,
        )
        if response.status == LogsQueryStatus.PARTIAL:
            return _empty(ips, 'IP network baseline query returned a partial result; no prevalence score was applied')
        rows: list[dict[str, Any]] = []
        for table in response.tables:
            names = [str(getattr(column, 'name', column)) for column in table.columns]
            rows.extend(dict(zip(names, row)) for row in table.rows)
    except Exception as exc:
        return _empty(ips, f'IP network baseline unavailable ({type(exc).__name__}: {str(exc)[:160]})')

    by_ip = {str(row.get('IPAddress')): row for row in rows if row.get('IPAddress')}
    details: list[dict[str, Any]] = []
    scoring: list[dict[str, Any]] = []
    isolated = 0
    established = 0
    observed = 0

    for ip in ips:
        row = by_ip.get(ip, {})
        connections = int(row.get('Connections', 0) or 0)
        devices = int(row.get('Devices', 0) or 0)
        active_days = int(row.get('ActiveDays', 0) or 0)
        state, score, rationale = classify_baseline(connections, devices, active_days)
        if connections > 0:
            observed += 1
        if state == 'isolated_new_peer':
            isolated += 1
        elif state == 'established_estate_peer':
            established += 1
        detail = {
            'IPAddress': ip,
            'Connections': connections,
            'Devices': devices,
            'ActiveDays': active_days,
            'FirstSeen': row.get('FirstSeen'),
            'LastSeen': row.get('LastSeen'),
            'BaselineState': state,
            'Score': score,
            'Rationale': rationale,
        }
        details.append(detail)
        if score:
            scoring.append({'Score': int(score), 'ScoreLabel': f'IP baseline: {ip} {state}'})

    return {
        'ModuleName': 'IPNetworkBaselineModule',
        'IPsAnalyzedCount': len(ips),
        'IPsObservedCount': observed,
        'IsolatedNewPeerCount': isolated,
        'EstablishedEstatePeerCount': established,
        'DetailedResults': details,
        'ScoringData': scoring,
    }
