from function_app import _run_playbook_request


def test_run_playbook_request_uses_incident_scope_from_base_only():
    base_incident = '/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/sentinel/providers/Microsoft.OperationalInsights/workspaces/sec/providers/Microsoft.SecurityInsights/incidents/22222222-2222-2222-2222-222222222222'
    attacker_incident = '/subscriptions/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/resourceGroups/other/providers/Microsoft.OperationalInsights/workspaces/other/providers/Microsoft.SecurityInsights/incidents/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'

    request = _run_playbook_request({
        'base': {'IncidentARMId': base_incident},
        'logicAppResourceId': '/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/playbooks/providers/Microsoft.Logic/workflows/respond',
        'tenantId': '33333333-3333-3333-3333-333333333333',
        'incidentArmId': attacker_incident,
    })

    assert request.incident_arm_id == base_incident
    assert request.incident_arm_id != attacker_incident


def test_run_playbook_request_does_not_fall_back_to_top_level_incident_id():
    request = _run_playbook_request({
        'base': {},
        'logicAppResourceId': '/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/playbooks/providers/Microsoft.Logic/workflows/respond',
        'tenantId': '33333333-3333-3333-3333-333333333333',
        'incidentArmId': '/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/sentinel/providers/Microsoft.OperationalInsights/workspaces/sec/providers/Microsoft.SecurityInsights/incidents/22222222-2222-2222-2222-222222222222',
    })

    assert request.incident_arm_id == ''
