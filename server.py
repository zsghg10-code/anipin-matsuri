"""ANI PIN ARENA: Online beta. Authoritative timed scoring; no client-supplied scores."""
from __future__ import annotations
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from fastapi import FastAPI, Request, Response, Depends, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import text, create_engine, Column, Integer, String, Float, ForeignKey, UniqueConstraint, Boolean, select, func, or_
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

ROOT = Path(__file__).resolve().parent
DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///' + str(ROOT / 'anipin.db'))
if DATABASE_URL.startswith('postgres://'):
    DATABASE_URL = 'postgresql+psycopg://' + DATABASE_URL[len('postgres://'):]
elif DATABASE_URL.startswith('postgresql://'):
    DATABASE_URL = 'postgresql+psycopg://' + DATABASE_URL[len('postgresql://'):]
engine = create_engine(DATABASE_URL, connect_args={'check_same_thread': False, 'timeout': 20} if DATABASE_URL.startswith('sqlite') else {}, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
Base = declarative_base()
KST = ZoneInfo('Asia/Seoul')
PLACES = {p['id']:p for p in json.loads((ROOT/'places.json').read_text(encoding='utf8'))}
MAX_QUESTIONS=5

class User(Base):
    __tablename__='users'
    id=Column(Integer, primary_key=True)
    nickname=Column(String(24), nullable=False, unique=True, index=True)
    password_hash=Column(String(160), nullable=False)
    created=Column(Float, default=time.time, nullable=False)

class SessionToken(Base):
    __tablename__='sessions'
    token_hash=Column(String(64), primary_key=True)
    user_id=Column(Integer, ForeignKey('users.id'), nullable=False)
    expiry=Column(Float, nullable=False)

class Challenge(Base):
    __tablename__='challenges'
    code=Column(String(16), primary_key=True)
    creator_id=Column(Integer, ForeignKey('users.id'), nullable=False)
    opponent_id=Column(Integer, ForeignKey('users.id'), nullable=True)
    questions=Column(String(200), nullable=False)
    created=Column(Float, default=time.time, nullable=False)

class Game(Base):
    __tablename__='games'
    id=Column(String(40), primary_key=True)
    user_id=Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    mode=Column(String(20), nullable=False)
    date=Column(String(10), nullable=False, index=True)
    challenge_code=Column(String(16), ForeignKey('challenges.code'), nullable=True)
    questions=Column(String(200), nullable=False)
    idx=Column(Integer, default=0, nullable=False)
    score=Column(Integer, default=0, nullable=False)
    streak=Column(Integer, default=0, nullable=False)
    hint_used=Column(Boolean, default=False, nullable=False)
    round_started=Column(Float, nullable=False)
    result=Column(String, default='[]', nullable=False)
    last_result=Column(String, nullable=True)
    status=Column(String(16), default='active', nullable=False)
    created=Column(Float, nullable=False)
    finished=Column(Float, nullable=True)
    __table_args__=(UniqueConstraint('user_id','mode','date','challenge_code',name='uq_per_challenge'),)

Base.metadata.create_all(engine)
app=FastAPI(title='ANI PIN MATSURI',version='4.0.0',docs_url=None,redoc_url=None)
# Reverse proxy should pass expected public host. Avoid overly permissive CORS; same-origin only.
app.add_middleware(TrustedHostMiddleware, allowed_hosts=os.getenv('ALLOWED_HOSTS','*').split(','))

@app.middleware('http')
async def basic_security(request: Request, call_next):
    # Browser clients use same-origin fetch + SameSite cookie; reject cross-origin mutating requests.
    origin = request.headers.get('origin','')
    if origin and request.method.upper() not in ('GET','HEAD','OPTIONS'):
        from urllib.parse import urlsplit
        o = urlsplit(origin)
        if not (o.scheme in ('http','https') and o.netloc == request.headers.get('host','')):
            return Response(content='Origin not allowed', status_code=403)
    res = await call_next(request)
    res.headers['X-Content-Type-Options'] = 'nosniff'
    res.headers['X-Frame-Options'] = 'DENY'
    res.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    res.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    if request.url.path.startswith('/api/'):
        res.headers['Cache-Control'] = 'no-store'
    return res
app.mount('/assets', StaticFiles(directory=str(ROOT/'static'/'assets')), name='assets')

class Credentials(BaseModel):
    nickname:str=Field(min_length=2,max_length=18)
    password:str=Field(min_length=8,max_length=128)

class Guess(BaseModel):
    lat:float=Field(ge=20,le=50)
    lon:float=Field(ge=120,le=155)
    hint:bool=False

class GameStart(BaseModel):
    mode:str='daily'
    code:str|None=None


def get_db():
    with SessionLocal() as db:
        yield db

def day():return datetime.now(KST).strftime('%Y-%m-%d')

def password_digest(password:str):
    salt=secrets.token_bytes(16)
    return salt.hex()+':'+hashlib.pbkdf2_hmac('sha256',password.encode(),salt,450_000).hex()

def verify_password(password:str,digest:str):
    try:
        a,b=digest.split(':'); expected=bytes.fromhex(b)
        test=hashlib.pbkdf2_hmac('sha256',password.encode(),bytes.fromhex(a),450_000)
        return hmac.compare_digest(test,expected)
    except (ValueError,TypeError):return False

def cookie_secure(request:Request):return os.getenv('COOKIE_SECURE','').lower()=='true' or request.headers.get('x-forwarded-proto')=='https' or request.url.scheme=='https'

def login_cookie(response:Response,request:Request,user:User,db:Session):
    value=secrets.token_urlsafe(36)
    db.add(SessionToken(token_hash=hashlib.sha256(value.encode()).hexdigest(),user_id=user.id,expiry=time.time()+30*86400))
    db.commit()
    response.set_cookie('anipin_sid',value,max_age=30*86400,httponly=True,samesite='lax',secure=cookie_secure(request),path='/')

def current_user(request:Request,db:Session=Depends(get_db)):
    token=request.cookies.get('anipin_sid','')
    if not token: raise HTTPException(status_code=401, detail='로그인이 필요합니다.')
    session=db.get(SessionToken,hashlib.sha256(token.encode()).hexdigest())
    if not session or session.expiry<time.time(): raise HTTPException(status_code=401,detail='로그인이 만료됐습니다.')
    user=db.get(User,session.user_id)
    if not user:raise HTTPException(status_code=401,detail='이용자를 찾을 수 없습니다.')
    return user

def public_user(u):return {'id':u.id,'nickname':u.nickname}

@app.get('/api/health')
def health(db:Session=Depends(get_db)):
    try: db.execute(text('SELECT 1'))
    except Exception: raise HTTPException(503,'데이터베이스 연결을 확인할 수 없습니다.')
    return {'ok':True,'date':day()}

# A lightweight per-process throttle. For high traffic replace with shared datastore/WAF.
_login_attempts: dict[str,list[float]] = {}

def check_auth_rate(request:Request):
    now=time.time()
    key=request.client.host if request.client else 'unknown'
    history=[v for v in _login_attempts.get(key,[]) if v > now-600]
    if len(history)>=24:
        raise HTTPException(429,'로그인 시도가 많습니다. 잠시 후 다시 시도해주세요.')
    history.append(now)
    _login_attempts[key]=history

@app.post('/api/register')
def register(creds:Credentials,request:Request,response:Response,db:Session=Depends(get_db)):
    check_auth_rate(request)
    name=creds.nickname.strip()
    if not re.fullmatch(r'[\w가-힣\-]{2,18}',name,re.UNICODE):raise HTTPException(422,'닉네임은 한글·영문·숫자·_·-로 2~18자입니다.')
    if db.scalar(select(User).where(User.nickname==name)):raise HTTPException(409,'이미 사용 중인 닉네임입니다.')
    user=User(nickname=name,password_hash=password_digest(creds.password))
    db.add(user)
    try: db.commit();db.refresh(user)
    except Exception:db.rollback();raise HTTPException(409,'닉네임이 중복됩니다.')
    login_cookie(response,request,user,db)
    return {'user':public_user(user)}

@app.post('/api/login')
def login(creds:Credentials,request:Request,response:Response,db:Session=Depends(get_db)):
    check_auth_rate(request)
    user=db.scalar(select(User).where(User.nickname==creds.nickname.strip()))
    if not user or not verify_password(creds.password,user.password_hash):raise HTTPException(401,'닉네임 또는 비밀번호가 올바르지 않습니다.')
    login_cookie(response,request,user,db)
    return {'user':public_user(user)}

@app.post('/api/logout')
def logout(request:Request,response:Response,db:Session=Depends(get_db)):
    val=request.cookies.get('anipin_sid','')
    if val:
        item=db.get(SessionToken,hashlib.sha256(val.encode()).hexdigest())
        if item:db.delete(item);db.commit()
    response.delete_cookie('anipin_sid',path='/')
    return {'ok':True}

class DeleteAccount(BaseModel):
    password: str

@app.post('/api/delete-account')
def delete_account(body:DeleteAccount, request:Request, response:Response, user:User=Depends(current_user), db:Session=Depends(get_db)):
    if not verify_password(body.password,user.password_hash):raise HTTPException(401,'비밀번호가 일치하지 않습니다.')
    # Delete personal games first; friends' game records remain but lose the room reference.
    codes=db.scalars(select(Challenge.code).where(Challenge.creator_id==user.id)).all()
    for code in codes:
        for game in db.scalars(select(Game).where(Game.challenge_code==code)).all():
            if game.user_id==user.id:db.delete(game)
            else:game.challenge_code=None
        ch=db.get(Challenge,code)
        if ch:db.delete(ch)
    for ch in db.scalars(select(Challenge).where(Challenge.opponent_id==user.id)).all():ch.opponent_id=None
    for g in db.scalars(select(Game).where(Game.user_id==user.id)).all():db.delete(g)
    for t in db.scalars(select(SessionToken).where(SessionToken.user_id==user.id)).all():db.delete(t)
    db.delete(user)
    db.commit()
    response.delete_cookie('anipin_sid',path='/')
    return {'ok':True}

@app.get('/api/me')
def me(user:User=Depends(current_user),db:Session=Depends(get_db)):
    today=day()
    latest=db.scalar(select(Game).where(Game.user_id==user.id,Game.mode=='daily',Game.date==today).order_by(Game.created.desc()))
    total=db.scalar(select(func.count(Game.id)).where(Game.user_id==user.id,Game.status=='finished')) or 0
    top=db.scalar(select(func.max(Game.score)).where(Game.user_id==user.id,Game.status=='finished')) or 0
    return {'user':public_user(user),'date':today,'daily_game':latest.id if latest else None,'daily_done':latest.status=='finished' if latest else False,'total_games':total,'best':top}

def ids_for_day(theday:str):
    # Shuffle deterministically on server, do not send future correct coordinates to client.
    import random
    seed=int.from_bytes(hashlib.sha256(('anipin-daily-v2-'+theday).encode()).digest()[:8],'big')
    return random.Random(seed).sample(sorted(PLACES),MAX_QUESTIONS)

def question_public(p:dict):return {k:p[k] for k in ('id','work','clue','level','emoji')}

def game_public(g:Game):
    ids=json.loads(g.questions);arr=json.loads(g.result)
    body={'id':g.id,'mode':g.mode,'date':g.date,'challenge_code':g.challenge_code,'index':g.idx,'count':len(ids),'score':g.score,'status':g.status,'results':arr,'server_now':time.time()}
    if g.status=='active':
        if g.last_result is not None:
            body['last_result']=json.loads(g.last_result)
        else:
            body['question']=question_public(PLACES[ids[g.idx]])
            body['hint_used']=bool(g.hint_used)
            if g.hint_used:body['question']['hint']=PLACES[ids[g.idx]]['hint']
            body['deadline']=g.round_started+(12 if g.mode=='sprint' else 30)
    return body

def find_game(game_id,user,db,locked=False):
    stmt=select(Game).where(Game.id==game_id,Game.user_id==user.id)
    if locked:stmt=stmt.with_for_update()
    g=db.scalar(stmt)
    if not g:raise HTTPException(404,'게임을 찾을 수 없습니다.')
    return g

@app.post('/api/challenges')
def make_challenge(user:User=Depends(current_user),db:Session=Depends(get_db)):
    recent=db.scalar(select(func.count(Challenge.code)).where(Challenge.creator_id==user.id,Challenge.created>=time.time()-86400)) or 0
    if recent>=10:raise HTTPException(429,'도전 코드는 하루 최대 10개 만들 수 있습니다.')
    ids=secrets.SystemRandom().sample(sorted(PLACES),MAX_QUESTIONS)
    code='AP-'+secrets.token_hex(4).upper()
    db.add(Challenge(code=code,creator_id=user.id,questions=json.dumps(ids),created=time.time()))
    db.commit()
    return {'code':code,'share_url':f'/challenge/{code}'}

@app.get('/api/challenges/{code}')
def challenge_detail(code:str,db:Session=Depends(get_db)):
    ch=db.get(Challenge,code.upper())
    if not ch:raise HTTPException(404,'존재하지 않는 친구 도전입니다.')
    rows=db.execute(select(Game,User.nickname).join(User,Game.user_id==User.id).where(Game.challenge_code==ch.code,Game.status=='finished').order_by(Game.score.desc(),Game.finished.asc()).limit(30)).all()
    return {'code':ch.code,'entries':[{'nickname':name,'score':g.score,'finished':g.finished} for g,name in rows],'max_players':2}

@app.post('/api/games')
def start_game(body:GameStart,user:User=Depends(current_user),db:Session=Depends(get_db)):
    mode=body.mode
    if mode not in ('daily','friend','sprint','practice'):raise HTTPException(422,'알 수 없는 게임 모드입니다.')
    d=day();code=None
    if mode=='friend':
        code=(body.code or '').strip().upper()
        ch=db.scalar(select(Challenge).where(Challenge.code==code).with_for_update())
        if not ch:raise HTTPException(404,'친구 도전 코드가 유효하지 않습니다.')
        existing=db.scalar(select(Game).where(Game.mode=='friend',Game.user_id==user.id,Game.challenge_code==code))
        if existing:return game_public(existing)
        if user.id!=ch.creator_id:
            if ch.opponent_id is not None and ch.opponent_id!=user.id:
                raise HTTPException(409,'이미 두 명이 참가 중인 1:1 대결입니다.')
            ch.opponent_id=user.id
        ids=json.loads(ch.questions)
    elif mode=='daily':
        existing=db.scalar(select(Game).where(Game.mode=='daily',Game.user_id==user.id,Game.date==d))
        if existing:return game_public(existing)
        ids=ids_for_day(d)
    else:ids=secrets.SystemRandom().sample(sorted(PLACES),MAX_QUESTIONS)
    now=time.time()
    g=Game(id=str(uuid.uuid4()),user_id=user.id,mode=mode,date=d,challenge_code=code,questions=json.dumps(ids),idx=0,score=0,streak=0,round_started=now,result='[]',last_result=None,status='active',created=now)
    db.add(g)
    try:db.commit()
    except Exception:
        db.rollback()
        if mode=='daily':
            old=db.scalar(select(Game).where(Game.mode=='daily',Game.user_id==user.id,Game.date==d))
            if old:return game_public(old)
        if mode=='friend':
            old=db.scalar(select(Game).where(Game.mode=='friend',Game.user_id==user.id,Game.challenge_code==code))
            if old:return game_public(old)
        raise
    return game_public(g)

@app.get('/api/games/{game_id}')
def get_game(game_id:str,user:User=Depends(current_user),db:Session=Depends(get_db)):
    return game_public(find_game(game_id,user,db))

def haversine(a,b,c,d):
    R=6371;p=math.pi/180
    x=(c-a)*p;y=(d-b)*p
    return round(2*R*math.asin(min(1,math.sqrt(math.sin(x/2)**2+math.cos(a*p)*math.cos(c*p)*math.sin(y/2)**2))))

@app.post('/api/games/{game_id}/hint')
def request_hint(game_id:str,user:User=Depends(current_user),db:Session=Depends(get_db)):
    g=find_game(game_id,user,db,locked=True)
    if g.status!='active' or g.last_result:raise HTTPException(409,'지금 라운드에서는 힌트를 사용할 수 없습니다.')
    g.hint_used=True
    db.commit()
    return game_public(g)

@app.post('/api/games/{game_id}/answer')
def answer(game_id:str,guess:Guess,user:User=Depends(current_user),db:Session=Depends(get_db)):
    g=find_game(game_id,user,db,locked=True)
    if g.status!='active':raise HTTPException(409,'이미 종료된 경기입니다.')
    if g.last_result:raise HTTPException(409,'이미 제출한 라운드입니다. 다음 라운드를 눌러주세요.')
    target=PLACES[json.loads(g.questions)[g.idx]]
    elapsed=max(0,time.time()-g.round_started)
    limit=12 if g.mode=='sprint' else 30
    timed_out=elapsed>limit+1.5 # network tolerance
    km=haversine(guess.lat,guess.lon,target['lat'],target['lon'])
    if timed_out:
        pts=0;g.streak=0
    else:
        accuracy=max(0,round(900*math.exp(-km/210)))
        speed=round(100*max(0,1-elapsed/limit))
        if km<=80 and accuracy+speed>100:g.streak+=1
        else:g.streak=0
        combo=min(100,(g.streak-1)*25) if g.streak>=2 else 0
        pts=round((accuracy+speed+combo)*(0.85 if g.hint_used else 1))
    res={'id':target['id'],'km':km,'secs':min(limit,round(elapsed,1)),'score':pts,'hint':bool(g.hint_used),'timeout':timed_out,'place':target['place'],'city':target['city'],'lat':target['lat'],'lon':target['lon'],'guess_lat':guess.lat,'guess_lon':guess.lon}
    results=json.loads(g.result);results.append(res);g.result=json.dumps(results,ensure_ascii=False)
    g.last_result=json.dumps(res,ensure_ascii=False);g.score+=pts
    db.commit()
    return game_public(g)

@app.post('/api/games/{game_id}/next')
def next_round(game_id:str,user:User=Depends(current_user),db:Session=Depends(get_db)):
    g=find_game(game_id,user,db,locked=True)
    if g.status!='active':raise HTTPException(409,'이미 종료된 게임입니다.')
    if not g.last_result:raise HTTPException(409,'답안을 먼저 제출하세요.')
    if g.idx==MAX_QUESTIONS-1:
        g.status='finished';g.finished=time.time()
    else:
        g.idx+=1;g.round_started=time.time();g.last_result=None;g.hint_used=False
    db.commit()
    return game_public(g)

@app.get('/api/leaderboard')
def leaderboard(period:str='today',db:Session=Depends(get_db)):
    if period not in ('today','week','all'):raise HTTPException(422,'잘못된 기간입니다.')
    stmt=select(Game,User.nickname).join(User,Game.user_id==User.id).where(Game.status=='finished',Game.mode=='daily')
    if period=='today':stmt=stmt.where(Game.date==day())
    if period=='week':stmt=stmt.where(Game.date>=((datetime.now(KST)-timedelta(days=datetime.now(KST).weekday())).strftime('%Y-%m-%d')))
    games=db.execute(stmt).all()
    best={}
    if period=='week':
        for g,n in games:
            old=best.get(g.user_id,(0,0,n))
            best[g.user_id]=(old[0]+g.score,max(old[1],g.finished or 0),n)
    else:
        for g,n in games:
            old=best.get(g.user_id)
            if old is None or (g.score,-(g.finished or 0))>(old[0],-old[1]):best[g.user_id]=(g.score,g.finished or 0,n)
    ordered=sorted(best.values(),key=lambda x:(-x[0],x[1]))[:100]
    return {'period':period,'date':day(),'total_players':len(best),'rows':[{'rank':i+1,'nickname':name,'score':score} for i,(score,_,name) in enumerate(ordered)]}

@app.get('/api/season')
def season(user:User=Depends(current_user),db:Session=Depends(get_db)):
    # Public ranking and progress are computed from authoritative completed games.
    t=datetime.now(KST)
    monday=(t-timedelta(days=t.weekday())).strftime('%Y-%m-%d')
    sunday=(t+timedelta(days=6-t.weekday())).strftime('%Y-%m-%d')
    daily_games=db.scalars(select(Game).where(Game.user_id==user.id,Game.mode=='daily',Game.status=='finished',Game.date>=monday)).all()
    all_games=db.scalars(select(Game).where(Game.user_id==user.id,Game.status=='finished')).all()
    best=max((g.score for g in all_games),default=0)
    week_score=sum(g.score for g in daily_games)
    accurate=0
    for g in all_games:
        for r in json.loads(g.result):
            if r.get('km',1e9)<=50:accurate+=1
    achievements=[
      {'id':'first', 'name':'첫 출정', 'icon':'⛩️','detail':'게임 1회 완료','unlocked':len(all_games)>=1},
      {'id':'fast', 'name':'번개 검객', 'icon':'⚡','detail':'스피드 러시 완료','unlocked':any(g.mode=='sprint' for g in all_games)},
      {'id':'steady', 'name':'꾸준한 순례자','icon':'🌸','detail':'이번 주 데일리 3일 완료','unlocked':len({g.date for g in daily_games})>=3},
      {'id':'precision','name':'정밀 탐험가','icon':'🎯','detail':'50km 이내 정답 5회','unlocked':accurate>=5},
      {'id':'ace','name':'전설의 도전자','icon':'🏆','detail':'한 게임 4,000점 달성','unlocked':best>=4000},
      {'id':'duel','name':'결투의 서약','icon':'⚔️','detail':'친구 대결 1회 완료','unlocked':any(g.mode=='friend' for g in all_games)},
    ]
    return {'week_start':monday,'week_end':sunday,'score':week_score,'days':len({g.date for g in daily_games}), 'total_completed':len(all_games),'best':best,'accurate':accurate,'achievements':achievements,'prizes_enabled':False,'prize_notice':'현금 상금은 운영하지 않습니다. 법률 검토 후 별도 공지.'}

@app.get('/api/monetization')
def monetization():
    # Client ID is intentionally public, but never enable ad serving without real AdSense approval.
    cid=os.getenv('ADSENSE_CLIENT_ID','').strip()
    slot=os.getenv('ADSENSE_SLOT_ID','').strip()
    if not re.fullmatch(r'ca-pub-\d{16}',cid) or not re.fullmatch(r'\d+',slot):return {'enabled':False}
    return {'enabled':True,'client':cid,'slot':slot}

@app.get('/challenge/{code}')
def challenge_url(code:str):return FileResponse(ROOT/'static'/'index.html')

@app.get('/')
def home():return FileResponse(ROOT/'static'/'index.html')

@app.get('/robots.txt')
def robots():return Response('User-agent: *\nAllow: /\n',media_type='text/plain')

@app.get('/about')
def about_page():return FileResponse(ROOT/'static'/'about.html')

@app.get('/privacy')
def privacy_page():return FileResponse(ROOT/'static'/'privacy.html')

@app.get('/terms')
def terms_page():return FileResponse(ROOT/'static'/'terms.html')
