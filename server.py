"""WJMAX PvP experimental WebSocket server for Render.
GitHub private repository profile storage is opt-in and fail-closed.
No plaintext passwords, no API credentials sent to clients.
"""
import asyncio, base64, hashlib, hmac, json, os, re, secrets, time
from aiohttp import web, ClientSession

ROOMS = {}
MAX_CLIENTS = 8
VERSION = '0.22.7'  # Retained wire version for existing deployed clients; song sync adds optional fields
BUILD_VERSION = '0.16.0'
BOT_MIN_SCORE = 950_000
BOT_MAX_SCORE = 1_000_000
START_DELAY_MS = 3000
MAX_CHART_NOTES = 50_000
# Each WebSocket message carries at most 100 chart-level signatures, allowing the
# entire matching native catalogue to be uploaded without a 240-chart truncation.
VERSUS_POOL_LIMIT = 100
VERSUS_MAX_UPLOAD = 12000
VERSUS_MAX_PARTS = (VERSUS_MAX_UPLOAD + VERSUS_POOL_LIMIT - 1) // VERSUS_POOL_LIMIT
VERSUS_MIN_LEVEL, VERSUS_MAX_LEVEL = 1, 50
VERSUS_JUDGE_NAMES = ('NORMAL', 'PLUS', 'EXPERT', 'MASTER', 'NIGHTMARE')
VERSUS_CANDIDATES = 5
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
    if r['mode'] == 'versus':
        state.update(versus_stage=r['versus_stage'], versus_candidates=list(r['versus_candidates']),
                     versus_tracks=list(r['versus_tracks']), versus_ban1=r['versus_bans'].get(0, -1),
                     versus_ban2=r['versus_bans'].get(1, -1), versus_ban_turn=r['versus_ban_turn'],
                     versus_index=r['versus_index'], versus_wins1=r['versus_wins'].get(0, 0),
                     versus_wins2=r['versus_wins'].get(1, 0), versus_winner=r['versus_winner'],
                     versus_pool_received=sum(bool(v) for v in r['versus_pools'].values()),
                     versus_history=list(r['versus_history']),
                     versus_level_min=r['versus_level_min'], versus_level_max=r['versus_level_max'],
                     versus_judges=list(r['versus_judges']))
    return state

async def update_state(r): await broadcast(r, room_state(r))

async def maybe_start(r):
    if ROOMS.get(r['code']) is not r or r['phase'] != 'lobby' or len(r['players']) < 2 or not r['song']:
        return False
    if r['mode'] == 'versus' and (r['versus_stage'] != 'round' or len(r['players']) != 2):
        return False
    if not all(p['ready'] and p['prepared'] for p in r['players']):
        return False
    print(f"[PVP READY] all participants confirmed room={r['code']} revision={r['revision']}", flush=True)
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
        versus_record_round(room)

def versus_valid_chart(value):
    """A chart candidate is a playable (song, MODE, KEY, displayed star) tuple."""
    if not isinstance(value, str) or len(value) > 220 or any(ord(c) < 32 for c in value):
        return False
    parts = value.split('|')
    return (len(parts) == 4 and all(x and x.strip() == x for x in parts)
            and parts[2] in ('Key4', 'Key5', 'Key6')
            and bool(re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{0,24}', parts[1]))
            and bool(re.fullmatch(r'[0-9]{1,2}', parts[3]))
            and VERSUS_MIN_LEVEL <= int(parts[3]) <= VERSUS_MAX_LEVEL)


def versus_play_signature(candidate):
    # Do not pass the matchmaking-only ★ level into the existing song protocol.
    # The native game resolves exactly the original rootFileName|MODE|KEY pattern.
    if not versus_valid_chart(candidate):
        raise ValueError('Invalid random-versus candidate')
    return candidate.rsplit('|', 1)[0]


def versus_initialize(room):
    # Keep the host's selected ranges/judges on rematch, reset all sampled state.
    room.update(versus_stage='setup', versus_candidates=[], versus_tracks=[],
                versus_bans={}, versus_ban_turn=0, versus_pools={}, versus_uploads={},
                versus_wins={0: 0, 1: 0}, versus_index=0,
                versus_level_min=room.get('versus_level_min', 1),
                versus_level_max=room.get('versus_level_max', 30),
                versus_judges=list(room.get('versus_judges', [1, 1, 1])),
                versus_winner='', versus_history=[], versus_round_recorded=False)


async def versus_set_range(room, ws, minimum, maximum):
    if room['phase'] != 'lobby' or room['versus_stage'] not in ('setup', 'pool'):
        await send(ws, dict(op='versus_error', message='Star range can only change before BAN')); return
    if type(minimum) is not int or type(maximum) is not int or not VERSUS_MIN_LEVEL <= minimum <= maximum <= VERSUS_MAX_LEVEL:
        await send(ws, dict(op='versus_error', message='Invalid star range (1-50; min <= max)')); return
    if (minimum, maximum) == (room['versus_level_min'], room['versus_level_max']): return
    room['versus_level_min'], room['versus_level_max'] = minimum, maximum
    room['versus_stage'] = 'setup'   # explicit new draw required
    room['versus_pools'].clear()
    room['versus_uploads'].clear()
    print(f"[PVP VERSUS] range room={room['code']} ★{minimum}-★{maximum} invalidated uploads", flush=True)
    await reset_round(room, message=f'Star range changed to {minimum}-{maximum}; both players must re-upload charts')


async def versus_draw(room, ws):
    if room['versus_stage'] != 'setup' or room['phase'] != 'lobby':
        await send(ws, dict(op='versus_error', message='Draw is available only during host setup')); return
    if len(room['players']) != 2:
        await send(ws, dict(op='versus_error', message='Two players must join before the five-chart draw')); return
    room['versus_stage'] = 'pool'
    room['versus_pools'].clear()
    room['versus_uploads'].clear()
    print(f"[PVP VERSUS] draw requested room={room['code']} ★{room['versus_level_min']}-★{room['versus_level_max']}", flush=True)
    await reset_round(room, message='Host confirmed star range: both players upload native charts now')


async def versus_set_judge(room, ws, index, judge):
    if room['versus_stage'] == 'complete' or room['phase'] == 'playing':
        await send(ws, dict(op='versus_error', message='Judge mode cannot change during/after play')); return
    if type(index) is not int or type(judge) is not int or not 0 <= index < 3 or not 0 <= judge < len(VERSUS_JUDGE_NAMES):
        await send(ws, dict(op='versus_error', message='Invalid round/judge mode')); return
    if room['versus_stage'] == 'round' and index < room['versus_index']:
        await send(ws, dict(op='versus_error', message='Completed round cannot be modified')); return
    if room['versus_stage'] == 'round' and room['phase'] == 'finished' and index <= room['versus_index']:
        await send(ws, dict(op='versus_error', message='Round is already finished')); return
    if room['versus_judges'][index] == judge: return
    room['versus_judges'][index] = judge
    print(f"[PVP VERSUS JUDGE] room={room['code']} round={index+1} mode={VERSUS_JUDGE_NAMES[judge]}", flush=True)
    if room['versus_stage'] == 'round' and index == room['versus_index']:
        # Increment revision and invalidate each player's ready/prepared receipt.
        await reset_round(room, song=versus_play_signature(room['versus_tracks'][index]),
                          message='Host changed round judgement; both players must F9 again')
    else:
        await update_state(room)


async def versus_offer_pool(room, player, raw, part, total):
    if room['versus_stage'] != 'pool' or room['phase'] != 'lobby':
        await send(player['ws'], dict(op='versus_error', message='Song pool is not open')); return
    if (type(part) is not int or type(total) is not int or not 0 <= part < total <= VERSUS_MAX_PARTS or
        not isinstance(raw, list) or not 1 <= len(raw) <= VERSUS_POOL_LIMIT or
        any(not versus_valid_chart(x) for x in raw)):
        await send(player['ws'], dict(op='versus_error', message='Invalid native chart chunk/level (100 per part, ★1-50)')); return
    if any(not room['versus_level_min'] <= int(x.rsplit('|', 1)[-1]) <= room['versus_level_max'] for x in raw):
        await send(player['ws'], dict(op='versus_error', message='A chart is outside the host-selected star range')); return
    slot = player['slot']
    upload = room['versus_uploads'].get(slot)
    if upload is None or (part == 0 and 0 in upload['parts'] and upload['parts'][0] != raw):
        upload = {'total': total, 'parts': {}}
        room['versus_uploads'][slot] = upload
        room['versus_pools'].pop(slot, None)
    if upload['total'] != total or (part in upload['parts'] and upload['parts'][part] != raw):
        await send(player['ws'], dict(op='versus_error', message='Inconsistent chart upload; restart from chunk 0')); return
    upload['parts'][part] = raw
    if len(upload['parts']) != total: return
    all_charts = [item for k in range(total) for item in upload['parts'][k]]
    if len(all_charts) > VERSUS_MAX_UPLOAD or len(set(all_charts)) < 5:
        await send(player['ws'], dict(op='versus_error', message='Invalid complete chart upload (5-12000 unique charts)')); return
    room['versus_pools'][slot] = set(all_charts)
    print(f"[PVP VERSUS] pool complete room={room['code']} slot={slot} size={len(room['versus_pools'][slot])} chunks={total} ★{room['versus_level_min']}-★{room['versus_level_max']}", flush=True)
    if len(room['players']) != 2 or len(room['versus_pools']) != 2:
        await update_state(room); return
    common = sorted(set.intersection(*room['versus_pools'].values()))
    if len(common) < VERSUS_CANDIDATES:
        await broadcast(room, dict(op='versus_error', message='Both players have fewer than five common charts in the star range; change range or key availability'))
        await update_state(room); return
    # Server picks ONCE from the complete filtered intersection. BAN removes only
    # from this immutable five; never draw a fresh three from the complete pool.
    room['versus_candidates'] = secrets.SystemRandom().sample(common, VERSUS_CANDIDATES)
    room['versus_stage'] = 'ban'
    room['versus_ban_turn'] = min(p['slot'] for p in room['players'])
    print(f"[PVP VERSUS] BAN room={room['code']} 5 locked={room['versus_candidates']}", flush=True)
    await update_state(room)


async def versus_apply_ban(room, player, index):
    if room['phase'] != 'lobby' or room['versus_stage'] != 'ban':
        await send(player['ws'], dict(op='versus_error', message='BAN phase is no longer active')); return
    if type(index) is not int or not 0 <= index < VERSUS_CANDIDATES:
        await send(player['ws'], dict(op='versus_error', message='Invalid BAN index')); return
    if player['slot'] != room['versus_ban_turn'] or player['slot'] in room['versus_bans']:
        await send(player['ws'], dict(op='versus_error', message='Not your BAN turn')); return
    if index in room['versus_bans'].values():
        await send(player['ws'], dict(op='versus_error', message='This chart was already banned')); return
    room['versus_bans'][player['slot']] = index
    print(f"[PVP VERSUS] BAN room={room['code']} slot={player['slot']} index={index}", flush=True)
    if len(room['versus_bans']) == 1:
        room['versus_ban_turn'] = next(p['slot'] for p in room['players'] if p['slot'] not in room['versus_bans'])
        await update_state(room); return
    room['versus_tracks'] = [s for i, s in enumerate(room['versus_candidates']) if i not in room['versus_bans'].values()]
    room['versus_stage'] = 'round'
    room['versus_index'] = 0
    room['versus_round_recorded'] = False
    await reset_round(room, song=versus_play_signature(room['versus_tracks'][0]))


def versus_record_round(room):
    if room.get('mode') != 'versus' or room['phase'] != 'finished' or room.get('versus_round_recorded'):
        return
    room['versus_round_recorded'] = True
    ranked = sorted(room['players'], key=ranking_key)
    winner_slot = -1 if len(ranked) != 2 or ranking_key(ranked[0]) == ranking_key(ranked[1]) else ranked[0]['slot']
    if winner_slot >= 0:
        room['versus_wins'][winner_slot] = room['versus_wins'].get(winner_slot, 0) + 1
    room['versus_history'].append(dict(song=room['song'], winner_slot=winner_slot,
                                       scores={str(p['slot']): p['score'] for p in room['players']}))
    print(f"[PVP VERSUS] round result room={room['code']} chart={room['versus_index'] + 1} winner_slot={winner_slot} wins={room['versus_wins']}", flush=True)
    if max(room['versus_wins'].values()) >= 2 or (room['versus_index'] >= 2 and winner_slot >= 0):
        room['versus_stage'] = 'complete'
        if room['versus_wins'][0] == room['versus_wins'][1]:
            room['versus_winner'] = 'TIE'
        else:
            winning_slot = max(room['versus_wins'], key=lambda n: room['versus_wins'][n])
            room['versus_winner'] = next((p['nickname'] for p in room['players'] if p['slot'] == winning_slot), 'TIE')
        print(f"[PVP VERSUS] series complete room={room['code']} winner={room['versus_winner']}", flush=True)


async def versus_next(room):
    if room['versus_stage'] != 'round' or room['phase'] != 'finished': return False
    last = room['versus_history'][-1] if room['versus_history'] else {}
    if last.get('winner_slot', -1) >= 0:
        room['versus_index'] += 1
    # A tied chart is replayed (does not consume one of the three charts).
    if room['versus_index'] >= len(room['versus_tracks']):
        room['versus_stage'] = 'complete'
        await update_state(room)
        return True
    room['versus_round_recorded'] = False
    await reset_round(room, song=versus_play_signature(room['versus_tracks'][room['versus_index']]))
    return True


async def start_match(r):
    # The phase transition is performed synchronously BEFORE any await: idempotent gate.
    if r['phase'] != 'lobby' or (r['mode'] == 'versus' and r['versus_stage'] != 'round'): return
    r['phase'] = 'playing'
    print(f"[PVP START] room={r['code']} revision={r['revision']} song={r['song']}", flush=True)
    for p in r['players']:
        clear_score(p)
    initialize_bot_targets(r)
    await broadcast(r, room_state(r), dict(op='start_signal', song=r['song'], revision=r['revision'], delay_ms=START_DELAY_MS))

async def reset_round(room, message=None, song=''):
    print(f"[PVP SONG] room={room['code']} revision={room['revision'] + 1} song={song or '(none)'}; invalidate ready/prepared", flush=True)
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
        if room['mode'] == 'versus':
            versus_initialize(room)
            await reset_round(room, message='Opponent left; versus restarted, waiting for a second player')
        elif room['phase'] == 'playing':
            advance_match(room)
        if host_left:
            await send(room['host'], dict(op='role', role='host'))
        await update_state(room)
        if room['phase'] == 'lobby':
            await maybe_start(room)

async def websocket(request):
    ws = web.WebSocketResponse(heartbeat=25, max_msg_size=65536)
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
                    if mode not in ('ffa','teams','versus'): mode='ffa'
                    max_players = d.get('max_players',4)
                    if type(max_players)!=int or not 2<=max_players<=MAX_CLIENTS: max_players=4
                    if mode == 'versus':
                        if d.get('versus_version') != 2:
                            await send(ws, dict(op='error', message='Versus requires v0.16.0 client')); continue
                        max_players = 2
                    code = secrets.token_hex(3).upper()
                    room = dict(code=code,name=str(d.get('name','WJMAX PvP'))[:30],host=ws,players=[],spectators=set(),members={ws},
                                max_players=max_players,mode=mode,public=d.get('public',True) is True,phase='lobby',song='',revision=0,
                                broadcast_lock=asyncio.Lock())
                    if mode == 'versus': versus_initialize(room)
                    ROOMS[code]=room
                else:
                    code = str(d.get('code','')).upper().strip()
                    room = ROOMS.get(code)
                    if not room:
                        await send(ws,dict(op='error',message='Room not found'));continue
                    if op=='join' and room['mode'] == 'versus' and d.get('versus_version') != 2:
                        await send(ws,dict(op='error',message='Versus mode requires v0.16.0 client (level/judge protocol v2)'));room=None;continue
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
                if op == 'chart_pool' and player and room['mode'] == 'versus' and current_round:
                    await versus_offer_pool(room, player, d.get('charts'), d.get('part'), d.get('total'))
                elif op == 'versus_range' and room['mode'] == 'versus' and is_host and current_round:
                    await versus_set_range(room, ws, d.get('min_level'), d.get('max_level'))
                elif op == 'versus_draw' and room['mode'] == 'versus' and is_host and current_round:
                    await versus_draw(room, ws)
                elif op == 'versus_judge' and room['mode'] == 'versus' and is_host and current_round:
                    await versus_set_judge(room, ws, d.get('index'), d.get('judge'))
                elif op == 'versus_ban' and player and room['mode'] == 'versus' and current_round:
                    await versus_apply_ban(room, player, d.get('index'))
                elif op == 'versus_next' and is_host and room['mode'] == 'versus' and current_round:
                    if not await versus_next(room):
                        await send(ws,dict(op='versus_error',message='Cannot advance before both players finish'))
                elif op == 'versus_restart' and is_host and room['mode'] == 'versus' and phase == 'finished' and room['versus_stage'] == 'complete' and current_round:
                    versus_initialize(room)
                    await reset_round(room, message='New versus: both players must send chart lists')
                elif op == 'bot_add' and room['mode'] == 'versus':
                    await send(ws,dict(op='versus_error',message='Bots are disabled in 1v1 Versus'))
                elif op == 'bot_remove' and room['mode'] == 'versus':
                    await send(ws,dict(op='versus_error',message='Bots are disabled in 1v1 Versus'))
                elif op=='bot_add' and is_host and phase=='lobby':
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
                elif op=='song' and room['mode'] == 'versus':
                    await send(ws,dict(op='versus_error',message='Versus charts are selected by the server after BAN'))
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
                elif op=='prepared':
                    # Explicit, individual receipt so local candidate-read success cannot be confused
                    # with server acceptance. Legacy clients without 'song' still work.
                    reason = ''
                    if player is None: reason = 'Not a player'
                    elif phase != 'lobby': reason = 'Round is not in lobby'
                    elif not room['song']: reason = 'Host has not selected a chart'
                    elif 'revision' not in d or not current_round: reason = 'Stale song revision'
                    elif d.get('ok') is not True and d.get('ok') is not False: reason = 'Invalid prepared flag'
                    elif d.get('ok') is True and 'song' in d and d['song'] != room['song']: reason = 'Chart mismatch: expected ' + room['song']
                    accepted = not reason
                    if accepted:
                        # Clearing readiness must work even after the candidate changes.
                        # Only prepared=true requires the exact server song signature.
                        player['prepared'] = d['ok'] is True
                        if not player['prepared']: player['ready'] = False
                    packet = dict(op='prepared_result', ok=accepted, prepared=player['prepared'] if player else False,
                                  revision=room['revision'], song=room['song'], message=reason or 'Prepared state accepted')
                    print(f"[PVP PREPARED] room={room['code']} player={name} accepted={accepted} requested={d.get('ok')} revision={revision} reason={reason or 'OK'}", flush=True)
                    await send(ws, packet)
                    if accepted:
                        await update_state(room)
                        await maybe_start(room)
                elif op=='ready':
                    reason = ''
                    if player is None: reason = 'Not a player'
                    elif phase != 'lobby': reason = 'Round is not in lobby'
                    elif not room['song']: reason = 'Host has not selected a chart'
                    elif not current_round: reason = 'Stale song revision'
                    elif d.get('ready') is True and not player['prepared']: reason = 'Chart not prepared/confirmed'
                    elif d.get('ready') is not True and d.get('ready') is not False: reason = 'Invalid ready flag'
                    accepted = not reason
                    if accepted: player['ready'] = d['ready'] is True
                    print(f"[PVP READY] room={room['code']} player={name} accepted={accepted} ready={player['ready'] if player else False} revision={revision} reason={reason or 'OK'}", flush=True)
                    await send(ws,dict(op='ready_result',ok=accepted,ready=player['ready'] if player else False,
                                       revision=room['revision'],message=reason or 'Ready state accepted'))
                    if accepted:
                        await update_state(room)
                        await maybe_start(room)
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
                    if room['mode'] == 'versus':
                        # Retry the SAME randomly chosen chart. Never leave the series in a
                        # lobby with an empty song (manual song choice is forbidden here).
                        room['versus_round_recorded'] = False
                        await reset_round(room, f"{player['nickname']} failed to launch. Retry this chart with F9.", song=versus_play_signature(room['versus_tracks'][room['versus_index']]))
                    else:
                        await reset_round(room, f"{player['nickname']} could not start or complete the native chart. Select it again.")
                elif op in ('next_round', 'reset') and current_round:
                    if room['mode'] == 'versus':
                        await send(ws,dict(op='versus_error',message='Use versus_next / versus_restart'))
                    elif is_host and phase == 'finished':
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

async def health(request): return web.json_response(dict(service='WJMAX PvP',version=VERSION,build_version=BUILD_VERSION,status='ok',transport='websocket',rooms=len(ROOMS),account_backend='configured' if AUTH_ON else 'not_configured'))
app=web.Application()
app.router.add_get('/',health)
app.router.add_get('/health',health)
app.router.add_get('/ws',websocket)
if __name__=='__main__':
    web.run_app(app,host='0.0.0.0',port=int(os.environ.get('PORT','10000')))
