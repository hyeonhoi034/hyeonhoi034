"""WJMAX PvP experimental WebSocket server for Render.
GitHub private repository profile storage is opt-in and fail-closed.
No plaintext passwords, no API credentials sent to clients.
"""
import asyncio, base64, hashlib, hmac, json, os, re, secrets, time
from aiohttp import web, ClientSession

ROOMS = {}
MAX_CLIENTS = 8
VERSION = '0.22.7'
BOT_MIN_SCORE = 950_000
BOT_MAX_SCORE = 1_000_000
START_DELAY_MS = 3000
MAX_CHART_NOTES = 50_000
GITHUB_REPO = os.getenv('PVP_ACCOUNTS_REPO', '').strip()  # owner/private-repo
GITHUB_TOKEN = os.getenv('PVP_GITHUB_TOKEN', '').strip()
GITHUB_PATH = os.getenv('PVP_ACCOUNTS_PATH', 'accounts.json').strip()
AUTH_ON = bool(GITHUB_REPO and GITHUB_TOKEN)
account_lock = asyncio.Lock()
active_names = {}

async def send(ws, obj):
    if not ws.closed:
        await ws.send_json(obj)

async def broadcast(room, *packets):
    # Keep snapshots and their follow-up signals in order across player connections.
    async with room['broadcast_lock']:
        for packet in packets:
            await asyncio.gather(*(send(w, packet) for w in room['members']), return_exceptions=True)

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

# Persistent, revocable per-device sessions. Only SHA-256 token hashes are stored in GitHub.
# A random bearer secret is returned ONCE to the requesting client and must be DPAPI protected locally.
def session_hash(token):
    return hashlib.sha256(token.encode('utf-8')).hexdigest()

async def issue_session(name):
    token = secrets.token_urlsafe(48)
    key = name.casefold()
    async with account_lock:
        accounts, sha = await github_document()
        if key not in accounts: raise RuntimeError('Account missing')
        entry = accounts[key]
        sessions = entry.get('sessions', [])
        if not isinstance(sessions, list): sessions = []
        # Limit each account to ten active devices without storing any bearer token.
        entry['sessions'] = (sessions[-9:] + [session_hash(token)])
        await github_save(accounts, sha)
    return token

async def resume_session(token):
    if not AUTH_ON or not isinstance(token, str) or len(token) < 40 or len(token) > 256:
        return None
    digest = session_hash(token)
    async with account_lock:
        accounts, _ = await github_document()
        for entry in accounts.values():
            if any(isinstance(item,str) and hmac.compare_digest(digest,item) for item in entry.get('sessions', [])):
                return entry['nickname']
    return None

async def revoke_session(name, token):
    if not name or not token: return
    async with account_lock:
        accounts, sha = await github_document()
        entry = accounts.get(name.casefold())
        if not entry: return
        digest=session_hash(token)
        before = entry.get('sessions', [])
        entry['sessions']=[x for x in before if not hmac.compare_digest(x,digest)]
        if len(entry['sessions'])!=len(before): await github_save(accounts, sha)

def ranking_key(player):
    return -player['score'], -player['accuracy'], player['miss']

def chart_clock(players):
    clocks = [(p['notes_passed'], p['notes_total']) for p in players if p['notes_total']]
    return max(clocks, key=lambda pair: pair[0] / pair[1], default=(0, 0))

def room_state(r):
    fields = ('slot', 'nickname', 'score', 'accuracy', 'accuracy_known', 'accuracy_estimated',
              'miss', 'max_combo', 'ready', 'prepared', 'finished', 'team', 'bot')
    players = [{key: p[key] for key in fields} for p in r['players']]
    ranking = sorted(players, key=ranking_key)
    previous_key = None
    rank = 0
    for index, player in enumerate(ranking, 1):
        key = ranking_key(player)
        if key != previous_key:
            rank = index
            previous_key = key
        player['rank'] = rank
    # Winner is resolved only after every remaining participant has finished.
    # A tied top score does not arbitrarily award one winner.
    winner = ''
    winner_score = 0
    if r['phase'] == 'finished' and ranking:
        best = ranking[0]
        winner_score = best['score']
        winner = 'TIE' if len(ranking) > 1 and ranking[1]['rank'] == 1 else best['nickname']
    passed, total = chart_clock(r['players'])
    state = dict(op='state', version=VERSION, code=r['code'], phase=r['phase'], song=r['song'], revision=r['revision'],
                 notes_passed=passed, notes_total=total,
                 winner=winner, winner_score=winner_score,
                 players=len(players), max_players=r['max_players'], spectators=len(r['spectators']),
                 entries=players, ranking=ranking, mode=r['mode'], public=r['public'], bot_count=sum(p['bot'] for p in players),
                 score1=players[0]['score'] if players else 0,score2=players[1]['score'] if len(players)>1 else 0,
                 ready1=int(players[0]['ready']) if players else 0,ready2=int(players[1]['ready']) if len(players)>1 else 0,
                 prepared1=int(players[0]['prepared']) if players else 0,prepared2=int(players[1]['prepared']) if len(players)>1 else 0)
    return state

async def update_state(r): await broadcast(r, room_state(r))

async def maybe_start(r):
    if ROOMS.get(r['code']) is not r or r['phase'] != 'lobby' or len(r['players']) < 2 or not r['song']:
        return False
    if not all(p['ready'] and p['prepared'] for p in r['players']):
        return False
    await start_match(r)
    return True

def clear_score(player):
    player.update(score=0, accuracy=0.0, accuracy_known=player['bot'], accuracy_estimated=False,
                  miss=0, max_combo=0, finished=False, progress=-1.0, notes_passed=0, notes_total=0)
    player.pop('target_score', None)

def new_player(room, ws, nickname, bot=False):
    used_slots = {p['slot'] for p in room['players']}
    slot = next(i for i in range(room['max_players']) if i not in used_slots)
    player = dict(ws=ws, slot=slot, nickname=nickname, bot=bot, ready=bot, prepared=bot, team=slot % 2)
    clear_score(player)
    room['players'].append(player)
    return player

def bot_accuracy(score):
    """Round the score-derived percentage half up, using integer arithmetic."""
    return ((score + 50) // 100) / 100

def initialize_bot_targets(room):
    """One independent uniform, integer-precision target per bot per match."""
    for player in room['players']:
        if player['bot']:
            player['target_score'] = BOT_MIN_SCORE + secrets.randbelow(BOT_MAX_SCORE - BOT_MIN_SCORE + 1)

def receive_score(player, packet):
    """Save the human sample before publishing the combined room standings."""
    progress = packet.get('progress')
    valid_progress = type(progress) in (int, float) and max(0, player['progress']) <= progress <= 1
    if valid_progress:
        player['progress'] = float(progress)
    passed, total = packet.get('notes_passed'), packet.get('notes_total')
    valid_notes = (type(passed) is int and type(total) is int and 1 <= total <= MAX_CHART_NOTES
                   and player['notes_total'] in (0, total) and player['notes_passed'] <= passed <= total)
    if valid_notes:
        player.update(notes_passed=passed, notes_total=total)
    score = packet.get('score')
    if 'score' in packet and (type(score) is not int or not player['score'] <= score <= 1_000_000_000):
        return valid_notes or valid_progress
    if score is not None:
        player['score'] = score
    accuracy = packet.get('accuracy')
    valid_accuracy = type(accuracy) in (float, int) and 0 <= accuracy <= 100
    if valid_accuracy:
        player['accuracy'] = float(accuracy)
        player['accuracy_known'] = True
        player['accuracy_estimated'] = packet.get('accuracy_estimated') is True
    for field in ('miss', 'max_combo'):
        value = packet.get(field)
        if type(value) is int and 0 <= value <= 1_000_000:
            player[field] = value
    return score is not None or valid_accuracy or valid_notes or valid_progress

def advance_match(room):
    humans = [p for p in room['players'] if not p['bot']]
    finished = all(p['finished'] for p in humans)
    passed, total = chart_clock(humans)
    playback_progress = max(0.0, max(p['progress'] for p in humans))
    for player in room['players']:
        if player['bot']:
            target = player['target_score']
            chart_score = target * passed // total if total else int(target * playback_progress)
            score = target if finished else max(player['score'], min(target - 1, chart_score))
            player.update(score=score, accuracy=bot_accuracy(score), finished=finished)
    if finished:
        room['phase'] = 'finished'

async def start_match(r):
    r['phase'] = 'playing'
    for p in r['players']:
        clear_score(p)
    initialize_bot_targets(r)
    await broadcast(r, room_state(r), dict(op='start_signal', song=r['song'], revision=r['revision'], delay_ms=START_DELAY_MS))

async def reset_round(room, message=None, song=''):
    room.update(phase='lobby', song=song, revision=room['revision'] + 1)
    for player in room['players']:
        clear_score(player)
        player.update(ready=player['bot'], prepared=player['bot'])
    packets = [room_state(room)]
    if song:
        packets.append(dict(op='prepare_song', song=song, revision=room['revision']))
    if message:
        packets.append(dict(op='round_cancelled', message=message))
    await broadcast(room, *packets)

async def detach_room(ws, room, player):
    """Remove one socket from a match without closing its WebSocket or login."""
    room['members'].discard(ws)
    room['spectators'].discard(ws)
    if player is not None and player in room['players']:
        room['players'].remove(player)
    host_left = ws is room['host']
    if host_left:
        room['host'] = next((p['ws'] for p in room['players'] if not p['bot']), None)
    if room['host'] is None:
        ROOMS.pop(room['code'], None)
        # Spectators may still have the room on their screens.
        await broadcast(room,dict(op='room_closed',message='All players left'))
        room['spectators'].clear()
        room['members'].clear()
    else:
        if room['phase'] == 'playing':
            advance_match(room)
        if host_left:
            await send(room['host'], dict(op='role', role='host'))
        await update_state(room)
        if room['phase'] == 'lobby':
            await maybe_start(room)

async def websocket(request):
    ws = web.WebSocketResponse(heartbeat=25, max_msg_size=16384)
    await ws.prepare(request)
    room = None; player = None; name = None; current_token = None
    try:
        async for msg in ws:
            if msg.type != web.WSMsgType.TEXT: break
            try: d = json.loads(msg.data)
            except (ValueError, TypeError): await send(ws,dict(op='error',message='Invalid JSON'));continue
            if not isinstance(d, dict): continue
            op = d.get('op')
            if room is not None and ROOMS.get(room['code']) is not room:
                room = None; player = None
            if op in ('register','login') and room is None:
                try: ok, message = await authenticate(d.get('nickname'),d.get('password'),op=='register')
                except Exception as exc: ok, message = False, 'Account backend unavailable'; print('Account error:',repr(exc),flush=True)
                if ok:
                    name = d['nickname']
                    try:
                        current_token = await issue_session(name)
                        await send(ws,dict(op='auth',ok=True,nickname=name,session=current_token,message=message))
                    except Exception as exc:
                        print('Session issuance failed:',repr(exc),flush=True)
                        name=None; current_token=None
                        await send(ws,dict(op='auth',ok=False,message='Session persistence unavailable'))
                else: await send(ws,dict(op='auth',ok=False,message=message))
            elif op == 'resume':
                try:
                    resumed = await resume_session(d.get('session'))
                    if resumed:
                        name = resumed; current_token = d['session']
                        await send(ws,dict(op='auth',ok=True,nickname=name,message='Session restored'))
                    else: await send(ws,dict(op='auth',ok=False,expired=True,message='Session invalid; log in again'))
                except Exception as exc:
                    print('Session resume failed:',repr(exc),flush=True)
                    await send(ws,dict(op='auth',ok=False,message='Session backend temporarily unavailable'))
            elif op == 'logout':
                if room:
                    await detach_room(ws,room,player)
                    room=None; player=None
                try:
                    await revoke_session(name,current_token)
                except Exception as exc:
                    print('Session revoke failed:',repr(exc),flush=True)
                    await send(ws,dict(op='error',message='Logout could not revoke session; try again'))
                    continue
                name=None; current_token=None
                await send(ws,dict(op='logged_out',message='Logged out'))
            elif op == 'list_rooms':
                await send(ws,dict(op='rooms',version=VERSION,rooms=[dict(code=r['code'],name=r['name'],players=len(r['players']),max_players=r['max_players'],mode=r['mode']) for r in ROOMS.values() if r['public'] and r['phase']=='lobby']))
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
                                max_players=max_players,mode=mode,public=d.get('public',True) is True,phase='lobby',song='',revision=0,
                                broadcast_lock=asyncio.Lock())
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
                    player = new_player(room, ws, name)
                else: room['spectators'].add(ws)
                await send(ws,dict(op='joined',role='host' if room['host'] is ws else ('spectator' if op=='spectate' else 'guest'),code=room['code'],slot=player['slot'] if player else -1))
                await update_state(room)
                if player and room['phase'] == 'lobby' and room['song']:
                    await send(ws,dict(op='prepare_song',song=room['song'],revision=room['revision']))
            elif room is not None:
                is_host = room['host'] is ws
                phase = room['phase']
                # Older clients may omit the revision on actions other than prepared.
                revision = d.get('revision', room['revision'])
                current_round = type(revision) is int and revision == room['revision']
                if op=='bot_add' and is_host and phase=='lobby':
                    if len(room['players']) >= room['max_players']:
                        await send(ws,dict(op='error',message='Room is full'))
                    else:
                        used = {p['nickname'] for p in room['players']}
                        bot_name = next(f'Bot {i}' for i in range(1, MAX_CLIENTS + 1) if f'Bot {i}' not in used)
                        bot = new_player(room, None, bot_name, bot=True)
                        await update_state(room)
                        await send(ws,dict(op='bot_added',message=bot['nickname']+' added'))
                        await maybe_start(room)
                elif op=='bot_remove' and is_host and phase=='lobby':
                    bots=[p for p in room['players'] if p['bot']]
                    if bots:
                        room['players'].remove(bots[-1]); await update_state(room)
                        await maybe_start(room)
                    else: await send(ws,dict(op='error',message='No bots in room'))
                elif op=='bot_test_start':
                    await send(ws,dict(op='error',message='Select a song and ready up to play with bots'))
                elif op=='song':
                    song=d.get('song','')
                    if not is_host or phase not in ('lobby', 'finished'):
                        await send(ws, dict(op='error', message='The host can choose a chart before or after a match'))
                    elif not current_round:
                        await send(ws, dict(op='error', message='The chart already changed. Select it again if needed'))
                    elif isinstance(song, str) and song.strip() and len(song) <= 200:
                        await reset_round(room, song=song)
                    else:
                        await send(ws, dict(op='error', message='Invalid chart name'))
                elif op=='prepared' and player and phase=='lobby' and room['song'] and 'revision' in d and current_round:
                    player['prepared']=d.get('ok') is True
                    if not player['prepared']:player['ready']=False
                    await update_state(room);await maybe_start(room)
                elif op=='ready' and player and phase=='lobby' and current_round:
                    player['ready']=d.get('ready') is True and player['prepared']
                    await update_state(room);await maybe_start(room)
                elif op=='start' and is_host and phase=='lobby' and current_round:
                    if not await maybe_start(room):
                        await send(ws,dict(op='error',message='Select a chart and ready all players (minimum two participants)'))
                elif op in ('score', 'finish') and player and phase=='playing' and current_round and not player['finished']:
                    saved = receive_score(player, d)
                    if op == 'finish':
                        player['finished'] = True
                    if saved or op == 'finish':
                        advance_match(room)
                        await update_state(room)
                elif op=='launch_failed' and player and phase=='playing' and current_round and not player['finished']:
                    await reset_round(room, f"{player['nickname']} could not start or complete the native chart. Select it again.")
                elif op in ('next_round', 'reset') and current_round:
                    if is_host and phase == 'finished':
                        await reset_round(room)
                    else:
                        await send(ws, dict(op='error', message='The host can prepare the next round after the match finishes'))
                elif op=='leave':
                    await detach_room(ws, room, player)
                    room = None
                    player = None
                    await send(ws,dict(op='left',message='Returned to lobby'))
    finally:
        if room and ROOMS.get(room['code']) is room:
            await detach_room(ws, room, player)
    return ws

async def health(request): return web.json_response(dict(service='WJMAX PvP',version=VERSION,status='ok',transport='websocket',rooms=len(ROOMS),account_backend='configured' if AUTH_ON else 'not_configured'))
app=web.Application()
app.router.add_get('/',health)
app.router.add_get('/health',health)
app.router.add_get('/ws',websocket)
if __name__=='__main__':
    web.run_app(app,host='0.0.0.0',port=int(os.environ.get('PORT','10000')))
