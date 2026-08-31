import json

import pytest

from modules.run_playbook import RunPlaybookRequest, run_playbook


_LOGIC_APP = '/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/playbooks/providers/Microsoft.Logic/workflows/contain-host'
_TENANT = '22222222-2222-2222-2222-222222222222'
_INCIDENT = '/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/sentinel/providers/Microsoft.OperationalInsights/workspaces/sec/providers/Microsoft.SecurityInsights/incidents/33333333-3333-3333-3333-333333333333'


def _request(resource_id=_LOGIC_APP, tenant_id=_TENANT, incident_id=_INCIDENT):
    return RunPlaybookRequest(resource_id, tenant_id, incident_id)


def test_run_playbook_is_disabled_when_exact_allowlist_is_unset(monkeypatch):
    monkeypatch.delenv('RUN_PLAYBOOK_ALLOWED_RESOURCE_IDS', raising=False)
    with pytest.raises(ValueError, match='disabled'):
        run_playbook(_request())


def test_run_playbook_rejects_prefix_lookalike(monkeypatch):
    monkeypatch.setenv('RUN_PLAYBOOK_ALLOWED_RESOURCE_IDS', _LOGIC_APP)
    with pytest.raises(ValueError, match='exact RunPlaybook allow-list'):
        run_playbook(_request(resource_id=_LOGIC_APP + '-copy'))


def test_run_playbook_rejects_invalid_tenant_before_token(monkeypatch):
    monkeypatch.setenv('RUN_PLAYBOOK_ALLOWED_RESOURCE_IDS', _LOGIC_APP)
    with pytest.raises(ValueError, match='tenantId'):
        run_playbook(_request(tenant_id='not-a-guid'))


def test_run_playbook_rejects_non_sentinel_incident_id(monkeypatch):
    monkeypatch.setenv('RUN_PLAYBOOK_ALLOWED_RESOURCE_IDS', _LOGIC_APP)
    with pytest.raises(ValueError, match='IncidentARMId'):
        run_playbook(_request(incident_id='/subscriptions/x/resourceGroups/y'))


def test_run_playbook_uses_playbook_operator_callback_flow(monkeypatch):
    monkeypatch.setenv('RUN_PLAYBOOK_ALLOWED_RESOURCE_IDS', _LOGIC_APP.upper())

    class Credential:
        def get_token(self, scope, tenant_id=None):
            assert scope == 'https://management.azure.com/.default'
            assert tenant_id == _TENANT
            return type('Token', (), {'token': 'arm-token'})()

    class Response:
        def __init__(self, payload=b''):
            self.payload = payload
        def __enter__(self):
            return self
        def __exit__(self, *_args):
            return False
        def read(self):
            return self.payload

    callback = 'https://prod-00.westeurope.logic.azure.com/workflows/abc/triggers/manual/paths/invoke?api-version=2016-06-01&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=secret'
    calls = []

    def fake_urlopen(request, timeout):
        calls.append((request, timeout))
        if len(calls) == 1:
            assert request.get_method() == 'POST'
            assert request.full_url.endswith('/triggers/manual/listCallbackUrl?api-version=2016-06-01')
            assert request.headers['Authorization'] == 'Bearer arm-token'
            return Response(json.dumps({'value': callback, 'method': 'POST'}).encode())
        assert request.get_method() == 'POST'
        assert request.full_url == callback
        assert 'Authorization' not in request.headers
        assert json.loads(request.data.decode()) == {'IncidentARMId': _INCIDENT}
        return Response()

    monkeypatch.setattr('modules.run_playbook.DefaultAzureCredential', lambda **_kwargs: Credential())
    monkeypatch.setattr('modules.run_playbook.urllib.request.urlopen', fake_urlopen)

    result = run_playbook(_request())
    assert result == {
        'ModuleName': 'RunPlaybook',
        'Started': True,
        'LogicAppResourceId': _LOGIC_APP,
        'TriggerName': 'manual',
    }
    assert len(calls) == 2
    assert all('sig=secret' not in str(value) for value in result.values())


def test_run_playbook_rejects_unexpected_callback_host(monkeypatch):
    monkeypatch.setenv('RUN_PLAYBOOK_ALLOWED_RESOURCE_IDS', _LOGIC_APP)

    class Credential:
        def get_token(self, *_args, **_kwargs):
            return type('Token', (), {'token': 'arm-token'})()

    class Response:
        def __enter__(self):
            return self
        def __exit__(self, *_args):
            return False
        def read(self):
            return json.dumps({'value': 'https://example.com/invoke?sig=secret'}).encode()

    monkeypatch.setattr('modules.run_playbook.DefaultAzureCredential', lambda **_kwargs: Credential())
    monkeypatch.setattr('modules.run_playbook.urllib.request.urlopen', lambda *_args, **_kwargs: Response())

    with pytest.raises(RuntimeError, match='unexpected Logic App callback host'):
        run_playbook(_request())
