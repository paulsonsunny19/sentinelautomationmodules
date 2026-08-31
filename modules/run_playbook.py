"""Privileged RunPlaybook compatibility module.

This endpoint can start another Consumption Logic App, so it is intentionally
opt-in and exact-allow-listed. It supports the upstream STAT pattern where the
target workflow exposes a Request/manual trigger and accepts an IncidentARMId
JSON property.

Unlike the earlier direct ``/triggers/manual/run`` approach, STAT Next first
asks Azure Resource Manager for the trigger callback URL. That matches the
permissions in the Microsoft Sentinel Playbook Operator built-in role, which
allows reading a workflow and listing a trigger callback URL without granting
Logic App Contributor.

The returned signed callback URL is treated as a secret: it is never logged or
returned to the caller.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
import uuid

from azure.identity import DefaultAzureCredential

from .kql_safety import assert_allowed_logic_app_resource_id

ARM_SCOPE = 'https://management.azure.com/.default'
ARM_API_VERSION = '2016-06-01'
TRIGGER_NAME = 'manual'
_ALLOWED_CALLBACK_SUFFIXES = (
    '.logic.azure.com',
    '.logic.azure.us',
    '.logic.azure.cn',
    '.logic.azure.de',
)
_INCIDENT_ARM_ID = re.compile(
    r'^/subscriptions/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
    r'/resourceGroups/[^/]+'
    r'/providers/Microsoft\.OperationalInsights/workspaces/[^/]+'
    r'/providers/Microsoft\.SecurityInsights/incidents/[^/]+$',
    flags=re.IGNORECASE,
)


@dataclass(frozen=True)
class RunPlaybookRequest:
    logic_app_resource_id: str
    tenant_id: str
    incident_arm_id: str


def _allowed_resource_ids() -> list[str]:
    return [
        item.strip()
        for item in os.environ.get('RUN_PLAYBOOK_ALLOWED_RESOURCE_IDS', '').split(',')
        if item.strip()
    ]


def _validate_tenant_id(value: str) -> str:
    try:
        parsed = uuid.UUID(str(value or ''))
    except (ValueError, AttributeError, TypeError) as exc:
        raise ValueError('tenantId must be a valid GUID') from exc
    return str(parsed)


def _validate_incident_arm_id(value: str) -> str:
    incident_id = str(value or '').strip().rstrip('/')
    if not _INCIDENT_ARM_ID.fullmatch(incident_id):
        raise ValueError('base.IncidentARMId must be a full Microsoft Sentinel incident ARM resource ID')
    return incident_id


def _arm_request(url: str, token: str) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        data=b'{}',
        method='POST',
        headers={
            'Authorization': f'Bearer {token}',
            'Accept': 'application/json',
            'Content-Type': 'application/json',
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            payload = response.read()
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise ValueError('The allow-listed Logic App or manual trigger was not found') from exc
        if exc.code == 403:
            raise RuntimeError('RunPlaybook identity is missing Microsoft Sentinel Playbook Operator on the target playbook resource group') from exc
        raise RuntimeError(f'Unable to obtain the Logic App trigger callback URL (HTTP {exc.code})') from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f'Unable to contact Azure Resource Manager ({type(exc.reason).__name__})') from exc

    try:
        result = json.loads(payload.decode('utf-8') or '{}')
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError('Azure Resource Manager returned an invalid callback response') from exc
    return result if isinstance(result, dict) else {}


def _validate_callback_url(value: Any) -> str:
    callback = str(value or '')
    parsed = urllib.parse.urlsplit(callback)
    hostname = (parsed.hostname or '').lower()
    if parsed.scheme.lower() != 'https' or not hostname:
        raise RuntimeError('Azure Resource Manager returned a non-HTTPS Logic App callback URL')
    if not any(hostname.endswith(suffix) for suffix in _ALLOWED_CALLBACK_SUFFIXES):
        raise RuntimeError('Azure Resource Manager returned an unexpected Logic App callback host')
    if not parsed.query:
        raise RuntimeError('Azure Resource Manager returned an unsigned Logic App callback URL')
    return callback


def _invoke_callback(callback_url: str, incident_arm_id: str) -> None:
    payload = json.dumps({'IncidentARMId': incident_arm_id}).encode('utf-8')
    request = urllib.request.Request(
        callback_url,
        data=payload,
        method='POST',
        headers={'Accept': 'application/json', 'Content-Type': 'application/json'},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            response.read()
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f'Allow-listed playbook callback failed (HTTP {exc.code})') from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f'Allow-listed playbook callback connection failed ({type(exc.reason).__name__})') from exc


def run_playbook(req: RunPlaybookRequest) -> dict[str, Any]:
    tenant_id = _validate_tenant_id(req.tenant_id)
    incident_arm_id = _validate_incident_arm_id(req.incident_arm_id)
    assert_allowed_logic_app_resource_id(req.logic_app_resource_id, _allowed_resource_ids())

    credential = DefaultAzureCredential(exclude_interactive_browser_credential=True)
    token = credential.get_token(ARM_SCOPE, tenant_id=tenant_id).token

    resource_id = req.logic_app_resource_id.strip().rstrip('/')
    callback_endpoint = (
        f'https://management.azure.com{resource_id}/triggers/{TRIGGER_NAME}/listCallbackUrl'
        f'?api-version={ARM_API_VERSION}'
    )
    callback_info = _arm_request(callback_endpoint, token)
    callback_url = _validate_callback_url(callback_info.get('value'))
    _invoke_callback(callback_url, incident_arm_id)

    return {
        'ModuleName': 'RunPlaybook',
        'Started': True,
        'LogicAppResourceId': resource_id,
        'TriggerName': TRIGGER_NAME,
    }
