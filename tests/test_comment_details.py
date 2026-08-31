from modules.comment import build_comment


def test_comment_renders_related_alert_mde_and_ip_details():
    comment = build_comment(
        {'EntitiesCount': 2, 'IPs': [{'Address': '49.186.62.27', 'IsPublic': True}]},
        {'TotalScore': 5},
        related={
            'RelatedAlertsCount': 1,
            'DetailedResults': [{
                'DisplayName': 'Suspicious sign-in',
                'AlertSeverity': 'Medium',
                'ProviderName': 'Microsoft Entra ID Protection',
                'Tactics': ['InitialAccess'],
                'AccountEntityMatch': True,
                'StartTime': '2026-08-31T11:00:00Z',
                'SystemAlertId': 'alert-1',
            }],
        },
        mde={
            'AnalyzedEntities': 2,
            'DetailedResults': {
                'Accounts': [{
                    'UserPrincipalName': 'user@contoso.com',
                    'UserHighestRiskScore': 'Medium',
                    'UserHighestExposureLevel': 'Low',
                    'UserDevices': [{
                        'id': 'machine-1',
                        'computerDnsName': 'device01.contoso.com',
                        'riskScore': 'Medium',
                        'exposureLevel': 'Low',
                    }],
                }],
                'IPs': [{
                    'id': 'machine-1',
                    'computerDnsName': 'device01.contoso.com',
                    'riskScore': 'Medium',
                    'exposureLevel': 'Low',
                    'healthStatus': 'Active',
                    'osPlatform': 'Windows11',
                    'lastIpAddress': '10.0.0.5',
                    'lastExternalIpAddress': '49.186.62.27',
                    'EntityIPAddress': '49.186.62.27',
                }],
                'Hosts': [],
            },
        },
        ip_enrichment={
            'IPsAnalyzedCount': 1,
            'IPsEnrichedCount': 1,
            'DetailedResults': [{
                'IPAddress': '49.186.62.27',
                'city': 'Sydney',
                'country': 'Australia',
                'organization': 'Telstra',
                'asn': 1221,
                'Source': 'Microsoft Sentinel GeoData',
            }],
        },
    )
    message = comment['Message']
    assert 'Related Alert Details' in message
    assert 'Suspicious sign-in' in message
    assert 'MDE Device Details' in message
    assert 'device01.contoso.com' in message
    assert 'IP Enrichment' in message
    assert 'Sydney' in message
    assert comment['PartialEnrichment'] is False


def test_any_module_warning_marks_comment_partial():
    comment = build_comment(
        {'EntitiesCount': 1},
        {'TotalScore': 0},
        ti={'MatchedTIItemCount': 0, 'EnrichmentWarnings': ['TI query unavailable']},
    )
    assert comment['PartialEnrichment'] is True
    assert 'TI query unavailable' in comment['Message']
