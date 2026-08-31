from modules.comment import build_comment


def test_comment_renders_optional_automatic_replies():
    comment = build_comment(
        {'EntitiesCount': 1},
        {'TotalScore': 0},
        oof={
            'ModuleName': 'OOFModule',
            'UsersAnalyzed': 1,
            'UsersInOffice': 0,
            'UsersOutOfOffice': 1,
            'UsersUnknown': 0,
            'DetailedResults': [{
                'UPN': 'user@contoso.com',
                'OOFStatus': 'enabled',
                'InternalMessage': 'Back tomorrow',
                'ExternalMessage': 'Contact SOC',
            }],
        },
    )
    assert comment['PartialEnrichment'] is False
    assert 'Automatic Replies' in comment['Message']
    assert 'user@contoso.com' in comment['Message']
    assert 'Back tomorrow' in comment['Message']


def test_oof_warning_marks_comment_partial():
    comment = build_comment(
        {'EntitiesCount': 1},
        {'TotalScore': 0},
        oof={
            'ModuleName': 'OOFModule',
            'UsersAnalyzed': 1,
            'UsersUnknown': 1,
            'EnrichmentWarnings': ['Mailbox settings lookup: Microsoft Graph returned HTTP 403'],
        },
    )
    assert comment['PartialEnrichment'] is True
    assert 'HTTP 403' in comment['Message']
