import pytest

from modules.kql_safety import (
    assert_no_dangerous_constructs,
    assert_safe_watchlist_alias,
    assert_safe_watchlist_key,
    datatable_literal,
)


def test_denies_control_command_at_start():
    with pytest.raises(ValueError):
        assert_no_dangerous_constructs('.show database', label='query')


def test_denies_control_command_after_statement():
    with pytest.raises(ValueError):
        assert_no_dangerous_constructs('SecurityAlert | take 1; .show database', label='query')


def test_allows_normal_statement_separator():
    assert_no_dangerous_constructs(
        'let x = 1; SecurityAlert | where TimeGenerated > ago(1d)',
        label='query',
    )


@pytest.mark.parametrize('query', [
    'externaldata(x:string)[@"https://example.invalid/data"]',
    'external_table("External")',
    'evaluate http_request("https://example.invalid")',
    'evaluate http_request_post("https://example.invalid", dynamic({}), dynamic({}))',
    'evaluate python(typeof(*), "print(1)")',
])
def test_denies_outbound_or_code_execution_primitives(query):
    with pytest.raises(ValueError):
        assert_no_dangerous_constructs(query, label='query')


def test_watchlist_alias_validation():
    assert_safe_watchlist_alias('TrustedNetworks')
    assert_safe_watchlist_alias('trusted-networks_1')
    with pytest.raises(ValueError):
        assert_safe_watchlist_alias('x") | union SecurityAlert //')


def test_watchlist_key_validation():
    assert_safe_watchlist_key('IPAddress')
    assert_safe_watchlist_key("['Key Name']")
    with pytest.raises(ValueError):
        assert_safe_watchlist_key('x]); .show tables')


def test_datatable_literal_escapes_entity_values():
    query = datatable_literal('entities', ['Value'], [['a"b\\c']])
    assert query == 'let entities=datatable(Value:string)["a\\"b\\\\c"];'
