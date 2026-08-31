"""Read-only Microsoft Graph automatic-replies enrichment.

The native STAT Next incident playbook calls OOFModule for incident accounts and
passes the result into the final comment. The module requires the read-only
Microsoft Graph application permission MailboxSettings.Read on the Function App
managed identity. Missing permission degrades to warnings instead of failing the
triage workflow.
"""
from __future__ import annotations

from dataclasses import dataclass
from html import unescape
import json
import re
from typing import Any
import urllib.error
import urllib.parse
import urllib.request

from azure.identity import DefaultAzureCredential


@dataclass(frozen=True)
class OOFRequest:
    base: dict[str, Any]


def _first(*values):
    for value in values:
        if value is not None and value != '':
            return value
    return None


def _accounts(base: dict[str, Any]) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    for item in base.get('Accounts', []):
        if not isinstance(item, dict):
            continue
        raw = item.get('RawEntity') if isinstance(item.get('RawEntity'), dict) else item
        additional = raw.get('additionalData') or raw.get('AdditionalData')
        additional = additional if isinstance(additional, dict) else {}
        upn = _first(
            item.get('UserPrincipalName'),
            raw.get('userPrincipalName'),
            raw.get('upn'),
            additional.get('UserPrincipalName'),
            additional.get('userPrincipalName'),
        )
        if not upn:
            continue
        text = str(upn).strip()
        key = text.lower()
        if key and key not in seen:
            seen.add(key)
            values.append(text)
    return values


_TAG_RE = re.compile(r'<[^>]*>')


def _plain(html_or_text: Any) -> str:
    if html_or_text is None or html_or_text == '':
        return ''
    text = _TAG_RE.sub('', str(html_or_text))
    text = unescape(text).replace('\r', ' ').replace('\n', ' ')
    return ' '.join(text.split())[:500]


def _graph_get(token: str, url: str, warnings: list[str], upn: str) -> dict[str, Any] | None:
    try:
        request = urllib.request.Request(
            url,
            headers={'Authorization': f'Bearer {token}', 'Accept': 'application/json'},
        )
        with urllib.request.urlopen(request, timeout=15) as response:
            value = json.loads(response.read().decode())
            if isinstance(value, dict):
                return value
            warnings.append(f'Mailbox settings lookup returned an invalid payload for {upn}')
    except urllib.error.HTTPError as exc:
        warnings.append(f'Mailbox settings lookup for {upn}: Microsoft Graph returned HTTP {exc.code}')
    except urllib.error.URLError as exc:
        warnings.append(
            f'Mailbox settings lookup for {upn}: Microsoft Graph connection failed ({type(exc.reason).__name__})'
        )
    except Exception as exc:
        warnings.append(f'Mailbox settings lookup for {upn} failed ({type(exc).__name__})')
    return None


def _classify(status: Any) -> str:
    value = str(status or '').strip().lower()
    if value == 'disabled':
        return 'disabled'
    if value in {'alwaysenabled', 'scheduled', 'enabled'} or 'enabled' in value:
        return 'enabled'
    return 'unknown'


def _empty() -> dict[str, Any]:
    return {
        'ModuleName': 'OOFModule',
        'AllUsersInOffice': False,
        'AllUsersOutOfOffice': False,
        'DetailedResults': [],
        'UsersAnalyzed': 0,
        'UsersInOffice': 0,
        'UsersOutOfOffice': 0,
        'UsersUnknown': 0,
    }


def query_oof(req: OOFRequest) -> dict[str, Any]:
    upns = _accounts(req.base)
    if not upns:
        return _empty()

    warnings: list[str] = []
    try:
        credential = DefaultAzureCredential(exclude_interactive_browser_credential=True)
        token = credential.get_token('https://graph.microsoft.com/.default').token
    except Exception as exc:
        warning = f'Mailbox settings token acquisition failed ({type(exc).__name__})'
        return {
            'ModuleName': 'OOFModule',
            'AllUsersInOffice': False,
            'AllUsersOutOfOffice': False,
            'DetailedResults': [
                {'UPN': upn, 'OOFStatus': 'unknown', 'ExternalMessage': '', 'InternalMessage': ''}
                for upn in upns
            ],
            'UsersAnalyzed': len(upns),
            'UsersInOffice': 0,
            'UsersOutOfOffice': 0,
            'UsersUnknown': len(upns),
            'EnrichmentWarnings': [warning],
        }

    details: list[dict[str, Any]] = []
    in_office = 0
    out_of_office = 0
    unknown = 0

    for upn in upns:
        account_warnings: list[str] = []
        url = (
            'https://graph.microsoft.com/v1.0/users/'
            + urllib.parse.quote(upn, safe='@.-_')
            + '/mailboxSettings/automaticRepliesSetting'
        )
        data = _graph_get(token, url, account_warnings, upn)
        state = _classify((data or {}).get('status'))
        if state == 'disabled':
            in_office += 1
        elif state == 'enabled':
            out_of_office += 1
        else:
            unknown += 1

        detail = {
            'UPN': upn,
            'OOFStatus': state,
            'ExternalMessage': _plain((data or {}).get('externalReplyMessage')),
            'InternalMessage': _plain((data or {}).get('internalReplyMessage')),
        }
        if account_warnings:
            detail['EnrichmentWarnings'] = sorted(set(account_warnings))
        details.append(detail)
        warnings.extend(account_warnings)

    result = {
        'ModuleName': 'OOFModule',
        'AllUsersInOffice': out_of_office == 0 and unknown == 0,
        'AllUsersOutOfOffice': in_office == 0 and unknown == 0,
        'DetailedResults': details,
        'UsersAnalyzed': len(upns),
        'UsersInOffice': in_office,
        'UsersOutOfOffice': out_of_office,
        'UsersUnknown': unknown,
    }
    if warnings:
        result['EnrichmentWarnings'] = sorted(set(warnings))
    return result
