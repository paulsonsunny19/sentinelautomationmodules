from __future__ import annotations
import json
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


def _entity_key(entity: dict[str, Any]) -> str:
    entity_id = entity.get("id") or entity.get("Id")
    if entity_id:
        return f"id:{str(entity_id).lower()}"
    return json.dumps(entity, sort_keys=True, default=str, separators=(",", ":"))


def _extract_entities(value: Any, output: list[dict[str, Any]], seen: set[str]) -> None:
    """Collect Sentinel entity resources embedded in incident/alert payloads.

    Sentinel payload shapes differ between alert providers and SDK versions, so
    walk only explicit entity-bearing properties rather than treating arbitrary
    dictionaries as entities.
    """
    if isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                key = _entity_key(item)
                if key not in seen:
                    seen.add(key)
                    output.append(item)
        return
    if not isinstance(value, dict):
        return
    for key, child in value.items():
        normalized = str(key).replace("_", "").lower()
        if normalized in {"entities", "relatedentities"}:
            _extract_entities(child, output, seen)
        elif isinstance(child, dict):
            _extract_entities(child, output, seen)


def incident_entities(incident: dict[str, Any], alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    entities: list[dict[str, Any]] = []
    seen: set[str] = set()
    _extract_entities(incident, entities, seen)
    for alert in alerts:
        _extract_entities(alert, entities, seen)
    return entities


def safe_incident_context(subscription_id: str, resource_group: str, workspace_name: str, incident_id: str) -> dict[str, Any]:
    try:
        incident = get_incident(subscription_id, resource_group, workspace_name, incident_id)
        alerts = list_incident_alerts(subscription_id, resource_group, workspace_name, incident_id)
        return {
            "incident": incident,
            "alerts": alerts,
            "entities": incident_entities(incident, alerts),
        }
    except HttpResponseError as exc:
        status = exc.status_code if exc.status_code else 502
        raise RuntimeError(f"Sentinel API failed with HTTP {status}") from exc
