import json

from modules.oof import OOFRequest, _accounts, _plain, query_oof


def test_accounts_extracts_and_deduplicates_upns():
    base = {'Accounts': [
        {'UserPrincipalName': 'a@contoso.com'},
        {'RawEntity': {'userPrincipalName': 'b@contoso.com'}},
        {'UserPrincipalName': 'A@CONTOSO.COM'},
    ]}
    assert _accounts(base) == ['a@contoso.com', 'b@contoso.com']


def test_plain_strips_html_and_limits_length():
    assert _plain('<p>Hello <b>World</b></p>') == 'Hello World'
    assert len(_plain('x' * 10000)) == 500


def test_no_accounts_short_circuits_without_graph(monkeypatch):
    def should_not_create_credential(**_kwargs):
        raise AssertionError('credential should not be created')

    monkeypatch.setattr('modules.oof.DefaultAzureCredential', should_not_create_credential)
    result = query_oof(OOFRequest({'Accounts': []}))
    assert result['ModuleName'] == 'OOFModule'
    assert result['UsersAnalyzed'] == 0


def test_graph_automatic_replies_are_classified(monkeypatch):
    class Credential:
        def __init__(self, **_kwargs): pass
        def get_token(self, _scope):
            return type('Token', (), {'token': 'test-token'})()

    class Response:
        def __enter__(self): return self
        def __exit__(self, *_args): return False
        def read(self):
            return json.dumps({
                'status': 'scheduled',
                'internalReplyMessage': '<p>Back tomorrow</p>',
                'externalReplyMessage': '<p>Contact SOC</p>',
            }).encode()

    monkeypatch.setattr('modules.oof.DefaultAzureCredential', Credential)
    monkeypatch.setattr('modules.oof.urllib.request.urlopen', lambda *_args, **_kwargs: Response())

    result = query_oof(OOFRequest({'Accounts': [{'UserPrincipalName': 'user@contoso.com'}]}))
    assert result['UsersAnalyzed'] == 1
    assert result['UsersOutOfOffice'] == 1
    assert result['UsersUnknown'] == 0
    assert result['DetailedResults'][0]['OOFStatus'] == 'enabled'
    assert result['DetailedResults'][0]['InternalMessage'] == 'Back tomorrow'


def test_graph_http_failure_is_warning_not_module_failure(monkeypatch):
    class Credential:
        def __init__(self, **_kwargs): pass
        def get_token(self, _scope):
            return type('Token', (), {'token': 'test-token'})()

    def forbidden(*_args, **_kwargs):
        import urllib.error
        raise urllib.error.HTTPError('https://graph.microsoft.com', 403, 'Forbidden', {}, None)

    monkeypatch.setattr('modules.oof.DefaultAzureCredential', Credential)
    monkeypatch.setattr('modules.oof.urllib.request.urlopen', forbidden)

    result = query_oof(OOFRequest({'Accounts': [{'UserPrincipalName': 'user@contoso.com'}]}))
    assert result['UsersUnknown'] == 1
    assert any('HTTP 403' in warning for warning in result['EnrichmentWarnings'])
