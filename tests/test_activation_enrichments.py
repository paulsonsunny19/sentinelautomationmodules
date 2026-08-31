import json
from pathlib import Path


def test_native_activation_keeps_ip_enrichment_out_and_oof_in():
    template = json.loads(Path('infrastructure/playbook-activate.json').read_text())
    workflow = next(r for r in template['resources'] if r.get('type') == 'Microsoft.Logic/workflows')
    actions = workflow['properties']['definition']['actions']

    assert 'IP_Enrichment' not in actions
    assert actions['OOF']['inputs']['uri'].endswith("/stat_oof')]")
    assert actions['OOF']['runAfter'] == {'Build_STAT_Base': ['Succeeded']}

    score_after = actions['Score_STAT']['runAfter']
    assert 'IP_Enrichment' not in score_after
    assert 'OOF' in score_after

    comment_body = actions['Build_STAT_Comment']['inputs']['body']
    assert 'ipEnrichment' not in comment_body
    assert comment_body['oof'] == "@body('OOF')"


def test_function_exposes_standalone_ip_and_oof_routes():
    source = Path('function_app.py').read_text()
    assert "route='stat_ip_enrichment'" in source
    assert "route='stat_oof'" in source
    assert 'IPEnrichmentModule' in source
    assert 'OOFModule' in source


def test_native_comment_does_not_render_ip_enrichment():
    source = Path('modules/comment_native.py').read_text()
    assert 'IP GeoData remains available through the standalone stat_ip_enrichment API' in source
    assert "_IP_SUMMARY_ROW" in source
