import pytest

from modules.related_alerts import RelatedAlertsRequest, query_related_alerts


def test_where_filter_rejects_statement_injection():
    request = RelatedAlertsRequest(
        workspace_id='workspace',
        base={},
        alert_kql_filter='| where 1 == 1; .show database',
    )
    with pytest.raises(ValueError):
        query_related_alerts(request)


def test_where_filter_rejects_excessive_length():
    request = RelatedAlertsRequest(
        workspace_id='workspace',
        base={},
        alert_kql_filter='| where ' + ('x' * 2100),
    )
    with pytest.raises(ValueError, match='maximum permitted length'):
        query_related_alerts(request)
