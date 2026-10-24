from pathlib import Path
import yaml

def test_blueprint_provisions_shared_db_and_https_cookie():
    root=Path(__file__).resolve().parents[1]
    spec=yaml.safe_load((root/'render.yaml').read_text())
    assert spec['databases'][0]['plan']=='free'
    service=spec['services'][0]
    assert service['type']=='web'
    assert '--host 0.0.0.0' in service['startCommand']
    assert service['healthCheckPath']=='/api/health'
    assert any(x.get('key')=='COOKIE_SECURE' and x.get('value')=='true' for x in service['envVars'])
    assert any(x.get('key')=='DATABASE_URL' and x.get('fromDatabase',{}).get('property')=='connectionString' for x in service['envVars'])


def test_cloud_has_no_local_user_database_or_credentials():
    root=Path(__file__).resolve().parents[1]
    assert not list(root.glob('*.db'))
    assert (root/'.gitignore').is_file()
    assert (root/'static'/'index.html').is_file()
