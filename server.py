"""WJMAX PvP experimental WebSocket server for Render.
GitHub private repository profile storage is opt-in and fail-closed.
No plaintext passwords, no API credentials sent to clients.
"""
import asyncio, base64, hashlib, hmac, json, os, re, secrets, time
from aiohttp import web, ClientSession

ROOMS = {}
MAX_CLIENTS = 8
BOT_DURATION = 18  # seconds; synthetic data, never presented as a real score
GITHUB_REPO = os.getenv('PVP_ACCOUNTS_REPO', '').strip()  # owner/private-repo
GITHUB_TOKEN = os.getenv('PVP_GITHUB_TOKEN', '').strip()
GITHUB_PATH = os.getenv('PVP_ACCOUNTS_PATH', 'accounts.json').strip()
AUTH_ON = bool(GITHUB_REPO and GITHUB_TOKEN)
account_lock = asyncio.Lock()
active_names = {}

async def send(ws, obj):
    if not ws.closed:
        await ws.send_json(obj)

async def broadcast(room, obj):
    await asyncio.gather(*(send(w, obj) for w in list(room['members']) if not w.closed), return_exceptions=True)

def safe_name(name):
    return isinstance(name, str) and 3 <= len(name) <= 20 and bool(re.fullmatch(r'[\w가-힣]+', name, re.UNICODE))

def hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 260000)
    return {'salt': base64.b64encode(salt).decode(), 'hash': base64.b64encode(digest).decode(), 'iterations': 260000}

def verify_password(password, record):
    try:
        expected = base64.b64decode(record['hash'])
        got = hashlib.pbkdf2_hmac('sha256', password.encode(), base64.b64decode(record['salt']), int(record['iterations']))
        return hmac.compare_digest(expected, got)
    except (ValueError, KeyError, TypeError):
        return False

async def github_document():
    url = f'https://api.github.com/repos/{GITHUB_REPO}/contents/{GITHUB_PATH}'
    headers = {'Authorization': f'Bearer {GITHUB_TOKEN}', 'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28'}
    async with ClientSession(headers=headers, timeout=__import__('aiohttp').ClientTimeout(total=12)) as session:
        async with session.get(url) as resp:
            if resp.status == 404:
                # Don't treat access-denied or wrong repositories as an empty database.
                async with session.get(f'https://api.github.com/repos/{GITHUB_REPO}') as probe:
                    if probe.status != 200 or not (await probe.json()).get('private'):
                        raise RuntimeError('Private profile repository unavailable')
                return {}, None
            if resp.status != 200: raise RuntimeError(f'GitHub read failed: HTTP {resp.status}')
            data = await resp.json()
            decoded = base64.b64decode(data['content']).decode('utf-8')
            accounts = json.loads(decoded)
            if not isinstance(accounts, dict): raise RuntimeError('Malformed accounts document')
            return accounts, data['sha']

async def github_save(accounts, sha):
    url = f'https://api.github.com/repos/{GITHUB_REPO}/contents/{GITHUB_PATH}'
    headers = {'Authorization': f'Bearer {GITHUB_TOKEN}', 'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28'}
    payload = {'message': 'Add WJMAX PvP profile', 'content': base64.b64encode(json.dumps(accounts, ensure_ascii=False).encode()).decode()}
    if sha: payload['sha'] = sha
    async with ClientSession(headers=headers, timeout=__import__('aiohttp').ClientTimeout(total=12)) as session:
        async with session.put(url, json=payload) as resp:
            if resp.status not in (200, 201): raise RuntimeError(f'GitHub write failed: HTTP {resp.status}')

async def authenticate(name, password, create):
    if not AUTH_ON: return False, 'Account storage not configured on Render'
    if not safe_name(name): return False, 'Nickname must be 3-20 letters/digits/underscore'
    if not isinstance(password, str) or len(password) < 8 or len(password) > 128:
        return False, 'Password must be 8-128 characters'
    key = name.casefold()
    async with account_lock:
        accounts, sha = await github_document()
        if create:
            if key in accounts: return False, 'Nickname already exists'
            accounts[key] = dict(nickname=name, **hash_password(password), created=int(time.time()))
            await github_save(accounts, sha)
            return True, 'Account created'
        if key not in accounts or not verify_password(password, accounts[key]): return False, 'Invalid nickname or password'
        return True, 'Logged in'

def room_state(r):
    players = []
    for idx, p in enumerate(r['players']):
        players.append({'slot': idx, 'nickname': p['nickname'], 'score': p['score'], 'accuracy': p['accuracy'],
                        'miss': p['miss'], 'max_combo': p['max_combo'], 'ready': p['ready'], 'prepared': p['prepared'],
                        'finished': p['finished'], 'team': p['team'], 'bot': p.get('bot', False)})
    ranking = sorted(players, key=lambda p: (-p['score'], -p['accuracy'], p['miss']))
    # Winner is resolved only after every remaining participant has finished.
    # A tied top score does not arbitrarily award one winner.
    winner = ''
    winner_score = 0
    if r['phase'] == 'finished' and ranking:
        best = ranking[0]
        winner_score = best['score']
        tied = [p for p in ranking if (p['score'], p['accuracy'], p['miss']) == (best['score'], best['accuracy'], best['miss'])]
        winner = best['nickname'] if len(tied) == 1 else 'TIE'
    state = dict(op='state', code=r['code'], phase=r['phase'], song=r['song'], revision=r['revision'],
                 winner=winner, winner_score=winner_score,
                 players=len(players), max_players=r['max_players'], spectators=len(r['spectators']),
                 entries=players, ranking=ranking, mode=r['mode'], public=r['public'], simulation=r['phase']=='bot_testing', bot_count=sum(p.get('bot',False) for p in r['players']),
                 score1=players[0]['score'] if players else 0,score2=players[1]['score'] if len(players)>1 else 0,
                 ready1=int(players[0]['ready']) if players else 0,ready2=int(players[1]['ready']) if len(players)>1 else 0,
                 prepared1=int(players[0]['prepared']) if players else 0,prepared2=int(players[1]['prepared']) if len(players)>1 else 0)
    return state

async def update_state(r): await broadcast(r, room_state(r))

async def maybe_start(r):
    if r['phase'] != 'lobby' or len(r['players']) < 2 or not r['song']: return
    if not all(p['ready'] and p['prepared'] for p in r['players']): return
    await start_match(r)

async def bot_score_loop(r, test_only=False):
    """Synthetic opponents for local verification; no fake score assigned to humans."""
    start=time.monotonic()
    try:
        while ROOMS.get(r['code']) is r and r['phase'] in ('playing','bot_testing'):
            elapsed=time.monotonic()-start
            if test_only and elapsed >= BOT_DURATION:
                for p in r['players']:
                    if p.get('bot'): p['finished']=True
                r['phase']='finished'
                await update_state(r)
                break
            changed=False
            for idx,p in enumerate(r['players']):
                if p.get('bot') and not p['finished']:
                    # Repeatable synthetic rate; independent of the user's real score.
                    value=min(1000000, int(elapsed*(2800+idx*735)))
                    if value>p['score']:
                        p['score']=value; p['accuracy']=round(92+idx*.65,2)
                        p['max_combo']=int(elapsed*2.1); changed=True
            if changed: await update_state(r)
            await asyncio.sleep(.45)
    except asyncio.CancelledError:
        return

async def start_match(r):
    r['phase'] = 'playing'
    for p in r['players']:
        p.update(score=0,accuracy=0.0,miss=0,max_combo=0,finished=False)
    await update_state(r)
    await broadcast(r, dict(op='start_signal',song=r['song'],revision=r['revision'],delay_ms=3000))
    if any(p.get('bot') for p in r['players']):
        r['bot_task']=asyncio.create_task(bot_score_loop(r))

async def detach_room(ws, room, player):
    """Remove one socket from a match without closing its WebSocket or login."""
    room['members'].discard(ws)
    room['spectators'].discard(ws)
    if player is not None and player in room['players']:
        room['players'].remove(player)
    if ws is room['host']:
        room['host'] = next((p['ws'] for p in room['players'] if not p.get('bot')), None)
        if room['host'] is not None:
            await send(room['host'], dict(op='role',role='host'))
    if not room['players'] or all(p.get('bot') for p in room['players']):
        if room.get('bot_task'): room['bot_task'].cancel()
        ROOMS.pop(room['code'],None)
        # Spectators may still have the room on their screens.
        await broadcast(room,dict(op='room_closed',message='All players left'))
        room['spectators'].clear()
        room['members'].clear()
    else:
        if room['phase']=='playing' and all(p['finished'] for p in room['players']):
            room['phase']='finished'
        await update_state(room)

async def websocket(request):
    ws = web.WebSocketResponse(heartbeat=25, max_msg_size=16384)
    await ws.prepare(request)
    room = None; player = None; name = None
    try:
        async for msg in ws:
            if msg.type != web.WSMsgType.TEXT: break
            try: d = json.loads(msg.data)
            except (ValueError, TypeError): await send(ws,dict(op='error',message='Invalid JSON'));continue
            if not isinstance(d, dict): continue
            op = d.get('op')
            if op in ('register','login') and room is None:
                try: ok, message = await authenticate(d.get('nickname'),d.get('password'),op=='register')
                except Exception as exc: ok, message = False, 'Account backend unavailable'; print('Account error:',repr(exc),flush=True)
                if ok:
                    name = d['nickname']
                    await send(ws,dict(op='auth',ok=True,nickname=name,message=message))
                else: await send(ws,dict(op='auth',ok=False,message=message))
            elif op == 'list_rooms':
                await send(ws,dict(op='rooms',rooms=[dict(code=r['code'],name=r['name'],players=len(r['players']),max_players=r['max_players'],mode=r['mode']) for r in ROOMS.values() if r['public'] and r['phase']=='lobby']))
            elif op in ('create','join','spectate') and room is None:
                if not name:
                    await send(ws,dict(op='error',message='Login first (configure private GitHub profile repository)'));continue
                if op=='create':
                    mode = d.get('mode','ffa')
                    if mode not in ('ffa','teams'): mode='ffa'
                    max_players = d.get('max_players',4)
                    if type(max_players)!=int or not 2<=max_players<=MAX_CLIENTS: max_players=4
                    code = secrets.token_hex(3).upper()
                    room = dict(code=code,name=str(d.get('name','WJMAX PvP'))[:30],host=ws,players=[],spectators=set(),members={ws},
                                max_players=max_players,mode=mode,public=d.get('public',True) is True,phase='lobby',song='',revision=0,bot_task=None)
                    ROOMS[code]=room
                else:
                    code = str(d.get('code','')).upper().strip()
                    room = ROOMS.get(code)
                    if not room:
                        await send(ws,dict(op='error',message='Room not found'));continue
                    if op=='join' and (room['phase']!='lobby' or len(room['players'])>=room['max_players']):
                        await send(ws,dict(op='error',message='Room is full or already playing'));room=None;continue
                    room['members'].add(ws)
                if op!='spectate':
                    player = dict(ws=ws,nickname=name or str(d.get('nickname','Guest'))[:20],score=0,accuracy=0.0,
                                  miss=0,max_combo=0,ready=False,prepared=False,finished=False,team=len(room['players'])%2)
                    room['players'].append(player)
                else: room['spectators'].add(ws)
                await send(ws,dict(op='joined',role='host' if room['host'] is ws else ('spectator' if op=='spectate' else 'guest'),code=room['code'],slot=len(room['players'])-1 if player else -1))
                await update_state(room)
                if player and room['song']:
                    await send(ws,dict(op='prepare_song',song=room['song'],revision=room['revision']))
            elif room is not None:
                if op=='bot_add' and room['host'] is ws and room['phase']=='lobby':
                    if len(room['players']) >= room['max_players']:
                        await send(ws,dict(op='error',message='Room full: increase maximum players'))
                    else:
                        idx=1
                        used={p['nickname'] for p in room['players']}
                        while 'TEST BOT '+str(idx) in used: idx+=1
                        bot=dict(ws=None,nickname='TEST BOT '+str(idx),bot=True,score=0,accuracy=0.0,
                                 miss=0,max_combo=0,ready=True,prepared=True,finished=False,team=len(room['players'])%2)
                        room['players'].append(bot)
                        await update_state(room)
                        await send(ws,dict(op='bot_added',message=bot['nickname']+' added (synthetic)'))
                elif op=='bot_remove' and room['host'] is ws and room['phase']=='lobby':
                    bots=[p for p in room['players'] if p.get('bot')]
                    if bots:
                        room['players'].remove(bots[-1]); await update_state(room)
                    else: await send(ws,dict(op='error',message='No test bots in room'))
                elif op=='bot_test_start' and room['host'] is ws and room['phase']=='lobby':
                    if not any(p.get('bot') for p in room['players']):
                        await send(ws,dict(op='error',message='Add a test bot first (F10)'))
                    else:
                        room['phase']='bot_testing'
                        for p in room['players']:p.update(score=0,accuracy=0.,miss=0,max_combo=0,finished=not p.get('bot',False))
                        await update_state(room)
                        await broadcast(room,dict(op='bot_test_started',message='Synthetic bot test running for 18 seconds'))
                        room['bot_task']=asyncio.create_task(bot_score_loop(room,test_only=True))
                elif op=='song' and room['host'] is ws and room['phase']=='lobby':
                    song=d.get('song','')
                    if isinstance(song,str) and song and len(song)<=200:
                        room['song']=song;room['revision']+=1
                        for p in room['players']:p.update(ready=p.get('bot',False),prepared=p.get('bot',False))
                        await update_state(room)
                        for p in room['players']:
                            if p['ws'] is not None: await send(p['ws'],dict(op='prepare_song',song=song,revision=room['revision']))
                elif op=='prepared' and player and room['phase']=='lobby' and d.get('revision')==room['revision']:
                    player['prepared']=d.get('ok') is True
                    if not player['prepared']:player['ready']=False
                    await update_state(room);await maybe_start(room)
                elif op=='ready' and player and room['phase']=='lobby':
                    player['ready']=d.get('ready') is True and player['prepared']
                    await update_state(room);await maybe_start(room)
                elif op=='start' and room['host'] is ws and room['phase']=='lobby':
                    if len(room['players'])>=2 and room['song'] and all(p['ready'] and p['prepared'] for p in room['players']):
                        await start_match(room)
                    else: await send(ws,dict(op='error',message='All players must prepare and ready'))
                elif op=='score' and player and room['phase']=='playing' and not player['finished']:
                    score=d.get('score')
                    if type(score)==int and player['score']<=score<=1000000000:
                        player['score']=score
                        accuracy=d.get('accuracy',player['accuracy']);miss=d.get('miss',player['miss']);combo=d.get('max_combo',player['max_combo'])
                        if type(accuracy) in (float,int) and 0<=accuracy<=100:player['accuracy']=float(accuracy)
                        if type(miss)==int and 0<=miss<=1000000:player['miss']=miss
                        if type(combo)==int and 0<=combo<=1000000:player['max_combo']=combo
                        await update_state(room)
                elif op=='finish' and player and room['phase']=='playing':
                    player['finished']=True
                    # Each client can show its own final screen without pausing opponents.
                    if all(p['finished'] for p in room['players']):room['phase']='finished'
                    await update_state(room)
                elif op=='reset' and room['host'] is ws and room['phase']=='finished':
                    room['phase']='lobby'
                    if room.get('bot_task'):room['bot_task'].cancel();room['bot_task']=None
                    for p in room['players']:p.update(ready=p.get('bot',False),prepared=p.get('bot',False),finished=False)
                    await update_state(room)
                elif op=='leave':
                    await detach_room(ws, room, player)
                    room = None
                    player = None
                    await send(ws,dict(op='left',message='Returned to lobby'))
    finally:
        if room:
            await detach_room(ws, room, player)
    return ws

async def health(request): return web.json_response(dict(service='WJMAX PvP',status='ok',transport='websocket',rooms=len(ROOMS),account_backend='configured' if AUTH_ON else 'not_configured'))
app=web.Application()
app.router.add_get('/',health)
app.router.add_get('/health',health)
app.router.add_get('/ws',websocket)
if __name__=='__main__':
    web.run_app(app,host='0.0.0.0',port=int(os.environ.get('PORT','10000')))
