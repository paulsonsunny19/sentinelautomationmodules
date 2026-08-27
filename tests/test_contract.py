from modules.related_alerts import ALLOWED_ENTITY_COLUMNS, RelatedAlertsRequest


def test_related_alert_entity_allowlist():
    assert "IPAddress" in ALLOWED_ENTITY_COLUMNS
    assert "AccountUpn" in ALLOWED_ENTITY_COLUMNS
    assert "arbitraryKql" not in ALLOWED_ENTITY_COLUMNS


def test_request_is_immutable():
    request = RelatedAlertsRequest(
        workspace_id="workspace",
        entity_value="10.0.0.1",
        entity_column="IPAddress",
    )
    assert request.lookback_hours == 24
