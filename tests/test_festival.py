from test_online import register,finish,site

def test_matsuri_public_pages_and_assets(site):
    _,c,_=site
    assert b'festival.js' in c.get('/').content
    assert c.get('/assets/festival.css').status_code==200
    assert c.get('/assets/festival.js').status_code==200
    assert c.get('/about').status_code==200
    assert c.get('/privacy').status_code==200
    assert c.get('/terms').status_code==200
    assert c.get('/api/season').status_code==401

def test_weekly_progress_and_achievements_from_real_games(site):
    _,a,b=site
    register(a,'matsuri_1')
    first=a.get('/api/season').json()
    assert first['score']==0 and first['days']==0
    assert first['prizes_enabled'] is False
    assert sum(item['unlocked'] for item in first['achievements'])==0
    g=a.post('/api/games',json={'mode':'daily'}).json()
    g=finish(a,g)
    s=a.get('/api/season').json()
    assert s['score']==g['score'] and s['days']==1 and s['total_completed']==1
    assert any(item['id']=='first' and item['unlocked'] for item in s['achievements'])
    assert a.post('/api/games',json={'mode':'daily'}).json()['id']==g['id']
    assert b.get('/api/season').status_code==401

def test_practice_does_not_affect_weekly_official_score(site):
    _,a,_=site
    register(a,'practice99')
    g=a.post('/api/games',json={'mode':'sprint'}).json()
    finish(a,g)
    s=a.get('/api/season').json()
    assert s['score']==0 and s['days']==0
    assert any(x['id']=='fast' and x['unlocked'] for x in s['achievements'])
