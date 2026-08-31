from pathlib import Path


SCRIPT = Path('infrastructure/grant-api-permissions.ps1')


def test_identity_enrichment_graph_roles_are_documented_in_grant_script():
    text = SCRIPT.read_text(encoding='utf-8')
    for role in (
        'User.Read.All',
        'IdentityRiskyUser.Read.All',
        'IdentityRiskEvent.Read.All',
        'AuditLog.Read.All',
        'RoleManagement.Read.Directory',
    ):
        assert f"Grant-AppRole $graphAppId '{role}'" in text


def test_graph_identity_roles_are_read_only():
    text = SCRIPT.read_text(encoding='utf-8')
    assert 'User.ReadWrite.All' not in text
    assert 'Directory.ReadWrite.All' not in text
    assert 'RoleManagement.ReadWrite.Directory' not in text
