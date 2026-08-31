import json
from pathlib import Path


def test_native_activation_calls_ip_enrichment_and_oof():
    template = json.loads(Path('infrastructure/playbook-activate.json').read_text())
    workflow = next(r for r in template['resources'] if r.get('type') == 'Microsoft.Logic/workflows')
    actions = workflow['properties']['definition']['actions']

    assert actions['IP_Enrichment']['inputs']['uri'].endswith("/stat_ip_enrichment')]")
    assert actions['OOF']['inputs']['uri'].endswith("/stat_oof')]")
    assert actions['IP_Enrichment']['runAfter'] == {'Build_STAT_Base': ['Succeeded']}
    assert actions['OOF']['runAfter'] == {'Build_STAT_Base': ['Succeeded']}

    score_after = actions['Score_STAT']['runAfter']
    assert 'IP_Enrichment' in score_after
    assert 'OOF' in score_after

    comment_body = actions['Build_STAT_Comment']['inputs']['body']
    assert comment_body['ipEnrichment'] == "@body('IP_Enrichment')"
    assert comment_body['oof'] == "@body('OOF')"


def test_function_exposes_standalone_ip_and_oof_routes():
    source = Path('function_app.py').read_text()
    assert "route='stat_ip_enrichment'" in source
    assert "route='stat_oof'" in source
    assert 'IPEnrichmentModule' in source
    assert 'OOFModule' in source
