from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient, LogsQueryStatus


@dataclass(frozen=True)
class RelatedAlertsRequest:
    workspace_id: str
    entity_value: str
    entity_column: str
    lookback_hours: int = 24


ALLOWED_ENTITY_COLUMNS = {"AccountUpn", "AccountName", "IPAddress", "HostName"}


def query_related_alerts(request: RelatedAlertsRequest) -> list[dict[str, Any]]:
    if request.entity_column not in ALLOWED_ENTITY_COLUMNS:
        raise ValueError("Unsupported entity column")
    if not 1 <= request.lookback_hours <= 168:
        raise ValueError("lookback_hours must be between 1 and 168")

    client = LogsQueryClient(DefaultAzureCredential(exclude_interactive_browser_credential=True))
    query = f"""
    declare query_parameters(entity:string);
    SecurityAlert
    | where TimeGenerated >= ago({request.lookback_hours}h)
    | extend EntitiesText = tostring(Entities)
    | where EntitiesText has entity
    | project TimeGenerated, SystemAlertId, AlertName, AlertSeverity, ProviderName,
              CompromisedEntity, Entities, ExtendedProperties
    | order by TimeGenerated desc
    | take 200
    """
    result = client.query_workspace(
        workspace_id=request.workspace_id,
        query=query,
        timespan=timedelta(hours=request.lookback_hours),
        server_timeout=30,
        query_parameters={"entity": request.entity_value},
    )
    if result.status == LogsQueryStatus.PARTIAL:
        raise RuntimeError(f"Log Analytics partial query failure: {result.partial_error}")
    rows: list[dict[str, Any]] = []
    for table in result.tables:
        names = [column.name for column in table.columns]
        rows.extend(dict(zip(names, row)) for row in table.rows)
    return rows
