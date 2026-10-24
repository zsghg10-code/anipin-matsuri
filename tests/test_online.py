"""End-to-end API checks against a clean, temporary SQLite DB."""
import importlib.util
import sys
from pathlib import Path
from uuid import uuid4
import pytest
from fastapi.testclient import TestClient

ROOT=Path(__file__).resolve().parents[1]

@pytest.fixture
def site(tmp_path,monkeypatch):
    monkeypatch.setenv('DATABASE_URL','sqlite:///'+str(tmp_path/'anipin-test.db'))
    name='anipin_test_'+uuid4().hex
    spec=importlib.util.spec_from_file_location(name,ROOT/'server.py')
    mod=importlib.util.module_from_spec(spec)
    sys.modules[name]=mod
    spec.loader.exec_module(mod)
    with TestClient(mod.app) as c1, TestClient(mod.app) as c2:
        yield mod,c1,c2
    mod.engine.dispose()
    sys.modules.pop(name,None)

def register(c,name):
    x=c.post('/api/register',json={'nickname':name,'password':'testpassword891'})
    assert x.status_code==200,x.text
    return x.json()

def finish(c,game):
    for i in range(5):
        assert game['status']=='active'
        assert 'hint' not in game.get('question',{})
        r=c.post(f"/api/games/{game['id']}/answer",json={'lat':35.3,'lon':139.5,'hint':False})
        assert r.status_code==200,r.text
        game=r.json()
        assert game['last_result'] is not None
        game=c.post(f"/api/games/{game['id']}/next").json()
    assert game['status']=='finished' and len(game['results'])==5
    return game

def test_health_and_assets(site):
    _,c,_=site
    assert c.get('/api/health').json()['ok']
    assert c.get('/').status_code==200
    assert c.get('/assets/online.js').status_code==200
    assert c.get('/assets/online.css').status_code==200
    assert c.get('/api/me').status_code==401
    assert c.get('/places.json').status_code==404
    assert c.get('/api/monetization').json()=={'enabled':False}

def test_auth_cookie_isolation_and_logout(site):
    _,a,b=site
    register(a,'alice123')
    assert a.get('/api/me').status_code==200
    assert b.get('/api/me').status_code==401
    assert a.post('/api/register',json={'nickname':'alice123','password':'anotherpassword8'}).status_code==409
    assert b.post('/api/login',json={'nickname':'alice123','password':'wrongpassword99'}).status_code==401
    assert b.post('/api/login',json={'nickname':'alice123','password':'testpassword891'}).status_code==200
    assert b.get('/api/me').status_code==200
    assert a.post('/api/logout').status_code==200
    assert a.get('/api/me').status_code==401

def test_daily_score_cannot_be_submitted_directly(site):
    _,a,b=site
    register(a,'hanako22');register(b,'sakura22')
    g=a.post('/api/games',json={'mode':'daily'}).json()
    same=b.post('/api/games',json={'mode':'daily'}).json()
    assert g['question']['id']==same['question']['id']
    assert a.get('/api/leaderboard').json()['rows']==[]
    assert b.get('/api/games/'+g['id']).status_code==404
    assert a.post(f"/api/games/{g['id']}/answer",json={'lat':99,'lon':170}).status_code==422
    # Even a forged client parameter hint:false cannot bypass the server's hint penalty.
    h=a.post(f"/api/games/{g['id']}/hint")
    assert h.status_code==200
    assert h.json()['hint_used'] and h.json()['question']['hint']
    result=a.post(f"/api/games/{g['id']}/answer",json={'lat':35,'lon':139,'hint':False}).json()
    assert result['last_result']['hint'] is True
    assert a.post(f"/api/games/{g['id']}/answer",json={'lat':35,'lon':139}).status_code==409
    g=a.post(f"/api/games/{g['id']}/next").json()
    assert not g['hint_used'] and 'hint' not in g['question']
    for i in range(4):
        g=a.post(f"/api/games/{g['id']}/answer",json={'lat':35,'lon':139}).json()
        g=a.post(f"/api/games/{g['id']}/next").json()
    assert g['status']=='finished' and len(g['results'])==5
    lb=a.get('/api/leaderboard').json()
    assert lb['total_players']==1 and lb['rows'][0]['nickname']=='hanako22'
    assert a.get('/api/leaderboard?period=week').json()['rows'][0]['score']==g['score']
    assert a.get('/api/leaderboard?period=all').json()['total_players']==1
    repeat=a.post('/api/games',json={'mode':'daily'}).json()
    assert repeat['id']==g['id']
    assert a.post(f"/api/games/{g['id']}/next").status_code==409
    assert 'hint' not in b.get('/api/games/'+same['id']).json()['question']

def test_real_friend_challenge_two_accounts(site):
    _,a,b=site
    register(a,'mamoru7');register(b,'usagi7')
    c=a.post('/api/challenges').json()['code']
    assert c.startswith('AP-')
    ga=a.post('/api/games',json={'mode':'friend','code':c}).json()
    gb=b.post('/api/games',json={'mode':'friend','code':c}).json()
    assert ga['question']['id']==gb['question']['id']
    assert a.post('/api/games',json={'mode':'friend','code':c}).json()['id']==ga['id']
    ga=finish(a,ga)
    assert len(b.get(f'/api/challenges/{c}').json()['entries'])==1
    gb=finish(b,gb)
    rows=a.get(f'/api/challenges/{c}').json()['entries']
    assert {x['nickname'] for x in rows}=={'mamoru7','usagi7'}
    assert rows==sorted(rows,key=lambda x:(-x['score'],x['finished']))
    assert not a.get('/api/leaderboard').json()['rows'] # friend games never pollute daily ranking
    from fastapi.testclient import TestClient
    # A third account must not enter the same two-person room.
    with TestClient(_ .app) as extra:
        register(extra,'rei777')
        assert extra.post('/api/games',json={'mode':'friend','code':c}).status_code==409


def test_demo_modes_do_not_change_daily(site):
    _,a,_=site
    register(a,'pika777')
    s=a.post('/api/games',json={'mode':'sprint'}).json()
    assert s['mode']=='sprint'
    p=a.post('/api/games',json={'mode':'practice'}).json()
    assert p['mode']=='practice'
    assert a.get('/api/leaderboard').json()['total_players']==0

def test_account_deletion_and_origin_check(site):
    mod,a,b=site
    register(a,'delete000')
    register(b,'friend999')
    room=a.post('/api/challenges').json()['code']
    a.post('/api/games',json={'mode':'friend','code':room})
    b.post('/api/games',json={'mode':'friend','code':room})
    r=a.post('/api/delete-account',json={'password':'wrongpassword'})
    assert r.status_code==401
    assert a.post('/api/delete-account',json={'password':'testpassword891'}).status_code==200
    assert a.get('/api/me').status_code==401
    assert b.get('/api/me').status_code==200
    assert b.get('/api/challenges/'+room).status_code==404
    assert b.post('/api/games',json={'mode':'daily'},headers={'Origin':'https://evil.invalid'}).status_code==403


def test_health_checks_database(site):
    mod,a,b=site
    health=a.get('/api/health')
    assert health.status_code==200 and health.json()['ok']
    assert health.headers['cache-control']=='no-store'
    assert health.headers['x-content-type-options']=='nosniff'
