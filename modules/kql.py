"""KQLModule / Run-KQLQuery.

This endpoint intentionally accepts caller-supplied KQL. Input validation
blocks obvious control-command and outbound-data primitives, but the real
security boundary remains the Function managed identity: keep it read-only
and scoped to the intended Log Analytics workspace.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient, LogsQueryStatus

from .kql_safety import assert_no_dangerous_constructs, datatable_literal, escape_kql_string


@dataclass(frozen=True)
class KQLRequest:
    workspace_id: str
    base: dict[str, Any]
    query: str
    lookback_days: int = 14
    query_description: str | None = None


def _prefix(base: dict[str, Any]) -> str:
    accounts = []
    for item in base.get('Accounts', []):
        raw = item.get('RawEntity', item)
        accounts.append([
            item.get('UserPrincipalName') or raw.get('userPrincipalName'),
            item.get('SamAccountName') or raw.get('accountName'),
            item.get('ObjectSID') or raw.get('sid'),
            item.get('AADUserId') or raw.get('aadUserId'),
            item.get('ManagerUPN'),
        ])

    ips = []
    for item in base.get('IPs', []):
        raw = item.get('RawEntity', item)
        geo = item.get('GeoData') if isinstance(item.get('GeoData'), dict) else {}
        ips.append([
            item.get('Address') or raw.get('address'),
            geo.get('latitude') or geo.get('Latitude'),
            geo.get('longitude') or geo.get('Longitude'),
            geo.get('country') or geo.get('CountryName') or geo.get('Country'),
            geo.get('state') or geo.get('State'),
        ])

    hosts = []
    for item in base.get('Hosts', []):
        hosts.append([item.get('FQDN'), item.get('Hostname')])

    return '\n'.join([
        datatable_literal(
            'accountEntities',
            ['UserPrincipalName', 'SamAccountName', 'ObjectSID', 'AADUserId', 'ManagerUPN'],
            accounts,
        ),
        datatable_literal(
            'ipEntities',
            ['IPAddress', 'Latitude', 'Longitude', 'Country', 'State'],
            ips,
        ),
        datatable_literal('hostEntities', ['FQDN', 'Hostname'], hosts),
        f"let incidentArmId={escape_kql_string(base.get('IncidentARMId', ''))};",
    ])


def _column_names(columns):
    return [str(getattr(column, 'name', column)) for column in columns]


def run_kql(req: KQLRequest) -> dict[str, Any]:
    if not req.query:
        raise ValueError('KQL query is required')
    assert_no_dangerous_constructs(req.query, label='query', max_length=50000)

    days = max(1, min(int(req.lookback_days), 90))
    full = f'{_prefix(req.base)}\n{req.query}'
    client = LogsQueryClient(DefaultAzureCredential(exclude_interactive_browser_credential=True))
    result = client.query_workspace(req.workspace_id, full, timespan=timedelta(days=days), server_timeout=30)

    rows = []
    count = 0
    if result.status == LogsQueryStatus.SUCCESS and result.tables:
        table = result.tables[0]
        names = _column_names(table.columns)
        count = len(table.rows)
        rows = [dict(zip(names, row)) for row in table.rows[:10]]

    return {
        'DetailedResults': rows,
        'ModuleName': 'KQLModule',
        'ResultsCount': count,
        'ItemCount': count,
        'ResultsFound': count > 0,
        'QueryDescription': req.query_description,
    }
