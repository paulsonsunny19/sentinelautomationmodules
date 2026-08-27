from __future__ import annotations
from typing import Any
from azure.core.exceptions import HttpResponseError
from azure.identity import DefaultAzureCredential
from azure.mgmt.securityinsight import SecurityInsights


def _client(subscription_id: str) -> SecurityInsights:
    credential = DefaultAzureCredential(exclude_interactive_browser_credential=True)
    return SecurityInsights(credential, subscription_id)


def get_incident(subscription_id: str, resource_group: str, workspace_name: str, incident_id: str) -> dict[str, Any]:
    incident = _client(subscription_id).incidents.get(resource_group, workspace_name, incident_id)
    data = incident.as_dict()
    data["id"] = incident.id
    data["name"] = incident.name
    return data


def list_incident_alerts(subscription_id: str, resource_group: str, workspace_name: str, incident_id: str) -> list[dict[str, Any]]:
    result = _client(subscription_id).incidents.list_alerts(resource_group, workspace_name, incident_id)
    alerts: list[dict[str, Any]] = []
    for alert in result.value or []:
        item = alert.as_dict()
        item["id"] = getattr(alert, "id", None)
        item["name"] = getattr(alert, "name", None)
        alerts.append(item)
    return alerts


def safe_incident_context(subscription_id: str, resource_group: str, workspace_name: str, incident_id: str) -> dict[str, Any]:
    try:
        return {"incident": get_incident(subscription_id, resource_group, workspace_name, incident_id), "alerts": list_incident_alerts(subscription_id, resource_group, workspace_name, incident_id)}
    except HttpResponseError as exc:
        status = exc.status_code if exc.status_code else 502
        raise RuntimeError(f"Sentinel API failed with HTTP {status}") from exc
