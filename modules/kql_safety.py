"""Shared validation helpers for caller-influenced KQL and resource identifiers.

These guards reduce obvious query-shape injection and outbound-data primitives.
They do not turn arbitrary KQL into a sandbox. The security boundary for the
free-form KQL endpoint remains the Function managed identity's read-only,
workspace-scoped permissions.
"""
from __future__ import annotations

import re
from typing import Any, Iterable

# Management/control commands are not valid enrichment queries. Deny a command
# at the beginning of a statement as well as one smuggled after a semicolon.
_DENIED_QUERY_PATTERNS = (
    r"(?m)^\s*\.",
    r";\s*\.",
    r"\bexternaldata\s*\(",
    r"\bexternal_table\s*\(",
    r"\bevaluate\s+(?:http_request|http_request_post|sql_request|cosmosdb_sql_request|azure_digital_twins_query)\s*\(",
    r"\bevaluate\s+(?:python|r)\s*\(",
)


def escape_kql_string(value: Any) -> str:
    """Return a double-quoted KQL string literal for a scalar value."""
    text = str(value if value is not None else "")
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def datatable_literal(name: str, columns: Iterable[str], rows: Iterable[Iterable[Any]]) -> str:
    """Build a small, escaped KQL datatable literal from trusted column names."""
    cols = list(columns)
    definition = ",".join(f"{column}:string" for column in cols)
    values = ",".join(
        ",".join(escape_kql_string(value) for value in row)
        for row in rows
    )
    return f"let {name}=datatable({definition})[{values}];"


def find_denied_construct(text: str, extra_denied: Iterable[str] = ()) -> str | None:
    for pattern in (*_DENIED_QUERY_PATTERNS, *extra_denied):
        if re.search(pattern, text, flags=re.IGNORECASE):
            return pattern
    return None


def assert_no_dangerous_constructs(
    text: str,
    *,
    label: str,
    extra_denied: Iterable[str] = (),
    max_length: int | None = None,
) -> None:
    if max_length is not None and len(text) > max_length:
        raise ValueError(f"{label} exceeds the maximum permitted length of {max_length} characters")
    hit = find_denied_construct(text, extra_denied)
    if hit:
        raise ValueError(f"{label} contains a disallowed construct")


_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,99}$")
_BRACKETED_KEY = re.compile(r"^\['[^'\]\\]{1,100}'\]$")
_LOGIC_APP_RESOURCE_ID = re.compile(
    r"^/subscriptions/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    r"/resourceGroups/[A-Za-z0-9._()\-]{1,90}"
    r"/providers/Microsoft\.Logic/workflows/[A-Za-z0-9._()\-]{1,80}$",
    flags=re.IGNORECASE,
)


def assert_safe_watchlist_alias(value: str) -> None:
    if not value or not _IDENTIFIER.fullmatch(value):
        raise ValueError(
            "watchlistAlias must start with a letter or underscore and contain only letters, digits, dash, or underscore (max 100 characters)"
        )


def assert_safe_watchlist_key(value: str) -> None:
    if not value or not (_IDENTIFIER.fullmatch(value) or _BRACKETED_KEY.fullmatch(value)):
        raise ValueError(
            "watchlistKey must be a simple column name or a bracketed ['Key Name'] column reference"
        )


def assert_allowed_logic_app_resource_id(resource_id: str, allowed_resource_ids: Iterable[str]) -> None:
    """Require a well-formed Consumption Logic App resource ID and exact allow-list membership.

    The RunPlaybook endpoint is intentionally default-deny: an empty allow-list
    means the privileged capability is disabled. Exact resource IDs are used
    instead of prefix matching so a similarly named workflow or resource group
    cannot inherit authorization accidentally.
    """
    candidate = str(resource_id or '').strip().rstrip('/')
    if not _LOGIC_APP_RESOURCE_ID.fullmatch(candidate):
        raise ValueError('logicAppResourceId is not a well-formed Consumption Logic App resource ID')

    allowed = {
        str(item or '').strip().rstrip('/').lower()
        for item in allowed_resource_ids
        if str(item or '').strip()
    }
    if not allowed:
        raise ValueError('RunPlaybook is disabled until RUN_PLAYBOOK_ALLOWED_RESOURCE_IDS is configured')
    if candidate.lower() not in allowed:
        raise ValueError('logicAppResourceId is not in the exact RunPlaybook allow-list')
