from __future__ import annotations

import json
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from azure.core.exceptions import HttpResponseError
from azure.identity import DefaultAzureCredential
from azure.mgmt.securityinsight import SecurityInsights

ARM_SCOPE = "https://management.azure.com/.default"
SENTINEL_API_VERSION = "2025-09-01"


def _credential() -> DefaultAzureCredential:
    return DefaultAzureCredential(exclude_interactive_browser_credential=True)


def _client(subscription_id: str) -> SecurityInsights:
    return SecurityInsights(_credential(), subscription_id)


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


def _dedupe_entities(entities: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    seen: set[str] = set()
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        key = _entity_key(entity)
        if key not in seen:
            seen.add(key)
            output.append(entity)
    return output


def _extract_entities(value: Any, output: list[dict[str, Any]], seen: set[str]) -> None:
    """Collect explicitly embedded entity arrays as a compatibility fallback."""
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


def embedded_incident_entities(incident: dict[str, Any], alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    entities: list[dict[str, Any]] = []
    seen: set[str] = set()
    _extract_entities(incident, entities, seen)
    for alert in alerts:
        _extract_entities(alert, entities, seen)
    return entities


def list_incident_entities(subscription_id: str, resource_group: str, workspace_name: str, incident_id: str) -> list[dict[str, Any]]:
    """Get the authoritative entity set from Sentinel's incident entities endpoint."""
    token = _credential().get_token(ARM_SCOPE).token
    url = (
        "https://management.azure.com/subscriptions/"
        f"{quote(subscription_id, safe='')}/resourceGroups/{quote(resource_group, safe='')}"
        "/providers/Microsoft.OperationalInsights/workspaces/"
        f"{quote(workspace_name, safe='')}/providers/Microsoft.SecurityInsights/incidents/"
        f"{quote(incident_id, safe='')}/entities?api-version={SENTINEL_API_VERSION}"
    )
    request = Request(
        url,
        data=b"{}",
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
    )
    try:
        with urlopen(request, timeout=30) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        raise RuntimeError(f"Sentinel incident entities API failed with HTTP {exc.code}") from exc
    except URLError as exc:
        raise RuntimeError("Sentinel incident entities API connection failed") from exc

    entities = payload.get("entities", []) if isinstance(payload, dict) else []
    if not isinstance(entities, list):
        raise RuntimeError("Sentinel incident entities API returned an invalid response")
    return _dedupe_entities(entities)


def safe_incident_context(subscription_id: str, resource_group: str, workspace_name: str, incident_id: str) -> dict[str, Any]:
    try:
        incident = get_incident(subscription_id, resource_group, workspace_name, incident_id)
        alerts = list_incident_alerts(subscription_id, resource_group, workspace_name, incident_id)
        entities = list_incident_entities(subscription_id, resource_group, workspace_name, incident_id)
        if not entities:
            entities = embedded_incident_entities(incident, alerts)
        return {
            "incident": incident,
            "alerts": alerts,
            "entities": entities,
        }
    except HttpResponseError as exc:
        status = exc.status_code if exc.status_code else 502
        raise RuntimeError(f"Sentinel API failed with HTTP {status}") from exc
