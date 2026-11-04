"""WJMAX PvP v0.13 protocol over WebSocket for Render Free Web Service.
Original JSON messages and room logic preserved. This server does NOT change the
v0.13 Unity client's raw TCP transport; the client needs a WebSocket update.
"""
import asyncio, json, os, secrets, random
from aiohttp import web, WSMsgType

rooms = {}
MAX_LINE = 4096

class WSWriter:
    def __init__(self, ws):
        self.ws = ws
        self.pending = []
    def is_closing(self):
        return self.ws.closed
    def write(self, data):
        self.pending.append(data)
    async def drain(self):
        for data in self.pending:
            await self.ws.send_str(data.decode('utf-8').rstrip('\n'))
        self.pending.clear()
    def close(self):
        if not self.ws.closed:
            asyncio.create_task(self.ws.close())
    async def wait_closed(self):
        if not self.ws.closed:
            await self.ws.close()

class WSReader:
    def __init__(self, ws):
        self.ws = ws
    async def readline(self):
        msg = await self.ws.receive()
        if msg.type == WSMsgType.TEXT:
            data = msg.data.encode('utf-8')
            return data + b'\n' if len(data) <= MAX_LINE else b'x'*(MAX_LINE+1)
        if msg.type == WSMsgType.BINARY:
            return msg.data + b'\n' if len(msg.data) <= MAX_LINE else b'x'*(MAX_LINE+1)
        return b''

async def send(w, data):
    if w.is_closing(): return
    try:
        w.write((json.dumps(data, ensure_ascii=False, separators=(',', ':'))+'\n').encode())
        await w.drain()
    except (OSError, ConnectionError, RuntimeError): pass

async def broadcast(room, data):
    await asyncio.gather(*(send(w, data) for w in list(room['members'])), return_exceptions=True)

def snapshot(r):
    scores = [r['scores'].get(w,0) if w else 0 for w in r['players']]
    if r['bot']: scores[1] = r['bot_score']
    leader = 0 if scores[0]>scores[1] else 1 if scores[1]>scores[0] else -1
    return dict(op='state',code=r['code'],players=sum(w is not None for w in r['players']),
                spectators=len(r['spectators']),bot=int(r['bot']),song=r['song'],revision=r['revision'],
                ready1=int(r['ready'][0]),ready2=int(r['ready'][1]),
                prepared1=int(r['prepared'][0]),prepared2=int(r['prepared'][1]),
                score1=scores[0],score2=scores[1],leader=leader,phase=r['phase'])

async def maybe_auto_start(room):
    # Only real human-vs-human matches auto-launch. Bots are simulation-only.
    if (room['phase']!='lobby' or room['bot'] or room['players'][0] is None or room['players'][1] is None): return
    if not room['song'] or not all(room['ready']) or not all(room['prepared']): return
    room['phase']='playing';room['finished']=[False,False]
    room['scores']={w:0 for w in room['players'] if w}
    await broadcast(room,snapshot(room))
    await broadcast(room,dict(op='start_signal',song=room['song'],revision=room['revision'],delay_ms=3000))

async def bot_play(room, revision):
    # Deterministic-ish simulated opponent. No Unity instance is launched.
    try:
        for tick in range(1, 31):
            await asyncio.sleep(0.35)
            if rooms.get(room['code']) is not room or room['phase'] != 'playing' or room['revision'] != revision or not room['bot']:
                return
            room['bot_score'] += random.randint(1200, 4000)
            await broadcast(room, snapshot(room))
        room['finished'][1] = True
        if all(room['finished']): room['phase'] = 'finished'
        await broadcast(room, snapshot(room))
    except asyncio.CancelledError:
        pass

def cancel_bot(room):
    task = room.get('bot_task')
    if task and not task.done(): task.cancel()
    room['bot_task'] = None

async def handler(reader, writer):
    room = None; role = None
    try:
        while True:
            line = await reader.readline()
            if not line or len(line)>MAX_LINE: break
            try:
                msg = json.loads(line)
                if not isinstance(msg,dict): continue
            except (ValueError, UnicodeError): continue
            op = msg.get('op')
            if op=='create' and room is None:
                code=secrets.token_hex(3).upper()
                room=dict(code=code,players=[writer,None],spectators=set(),members={writer},
                          scores={writer:0},ready=[False,False],prepared=[False,False],
                          song='',revision=0,phase='lobby',finished=[False,False],
                          bot=False,bot_score=0,bot_task=None)
                rooms[code]=room; role='host'
                await send(writer,dict(op='joined',role=role,code=code))
                await broadcast(room,snapshot(room))
            elif op in ('join','spectate') and room is None:
                code=str(msg.get('code','')).upper().strip(); found=rooms.get(code)
                if not found:
                    await send(writer,dict(op='error',message='Room not found')); continue
                if op=='join':
                    if found['players'][1] is not None or found['bot'] or found['phase']!='lobby':
                        await send(writer,dict(op='error',message='Room full or match in progress')); continue
                    found['players'][1]=writer;found['scores'][writer]=0;role='guest'
                else:
                    if len(found['spectators'])>=20:
                        await send(writer,dict(op='error',message='Spectator limit'));continue
                    found['spectators'].add(writer);role='spectator'
                room=found;room['members'].add(writer)
                await send(writer,dict(op='joined',role=role,code=code))
                await broadcast(room,snapshot(room))
                if role=='guest' and room['song']:
                    await send(writer,dict(op='prepare_song',song=room['song'],revision=room['revision']))
            elif room is not None:
                idx=0 if role=='host' else 1
                if op=='bot_add' and role=='host' and room['phase']=='lobby':
                    if room['players'][1] is not None:
                        await send(writer,dict(op='error',message='Guest already joined'))
                    else:
                        room['bot']=True;room['bot_score']=0
                        room['ready'][1]=bool(room['song']);room['prepared'][1]=bool(room['song'])
                        await broadcast(room,snapshot(room))
                elif op=='bot_remove' and role=='host' and room['phase']=='lobby':
                    room['bot']=False;room['bot_score']=0
                    room['ready'][1]=False;room['prepared'][1]=False
                    await broadcast(room,snapshot(room))
                elif op=='song' and role=='host' and room['phase']=='lobby':
                    song=msg.get('song')
                    if isinstance(song,str) and 0<len(song.strip())<=120:
                        room['song']=song.strip();room['revision']+=1
                        room['ready']=[False,bool(room['bot'])];room['prepared']=[False,bool(room['bot'])]
                        await broadcast(room,snapshot(room))
                        for w in room['players']:
                            if w: await send(w,dict(op='prepare_song',song=room['song'],revision=room['revision']))
                elif op=='prepared' and role in ('host','guest') and room['phase']=='lobby':
                    if msg.get('revision')==room['revision'] and room['song']:
                        room['prepared'][idx]=msg.get('ok') is True
                        if not room['prepared'][idx]:room['ready'][idx]=False
                        await broadcast(room,snapshot(room))
                        await maybe_auto_start(room)
                elif op=='ready' and role in ('host','guest') and room['phase']=='lobby':
                    room['ready'][idx]=(msg.get('ready') is True and room['prepared'][idx])
                    await broadcast(room,snapshot(room))
                    await maybe_auto_start(room)
                elif op=='bot_test_start' and role=='host' and room['bot'] and room['phase']=='lobby':
                    # Simulation-only: no real chart preparation or launch is claimed.
                    if not room['song']:
                        await send(writer,dict(op='error',message='Set a test song first'))
                    else:
                        room['phase']='playing';room['finished']=[False,False]
                        room['scores']={w:0 for w in room['players'] if w};room['bot_score']=0
                        await broadcast(room,snapshot(room))
                        await send(writer,dict(op='bot_test_started',message='Simulation only; game chart NOT launched'))
                        room['bot_task']=asyncio.create_task(bot_play(room,room['revision']))
                elif op=='start' and role=='host':
                    if (room['phase']=='lobby' and (room['players'][1] is not None or room['bot']) and room['song']
                            and all(room['ready']) and all(room['prepared'])):
                        room['phase']='playing';room['finished']=[False,False]
                        room['scores']={w:0 for w in room['players'] if w};room['bot_score']=0
                        await broadcast(room,snapshot(room))
                        await broadcast(room,dict(op='start_signal',song=room['song'],revision=room['revision'],delay_ms=3000))
                        if room['bot']: room['bot_task']=asyncio.create_task(bot_play(room,room['revision']))
                    else:
                        await send(writer,dict(op='error',message='Both players must prepare and ready'))
                elif op=='score' and role in ('host','guest') and room['phase']=='playing':
                    score=msg.get('score')
                    if type(score) is int and 0<=score<=1000000000:
                        room['scores'][writer]=max(room['scores'].get(writer,0),score)
                        await broadcast(room,snapshot(room))
                elif op=='finish' and role in ('host','guest') and room['phase']=='playing':
                    room['finished'][idx]=True
                    if all(room['finished']):room['phase']='finished'
                    await broadcast(room,snapshot(room))
                elif op=='reset' and role=='host':
                    cancel_bot(room)
                    room['phase']='lobby';room['ready']=[False,bool(room['bot'])];room['prepared']=[False,bool(room['bot'])]
                    room['finished']=[False,False];room['bot_score']=0;room['scores']={w:0 for w in room['players'] if w}
                    await broadcast(room,snapshot(room))
                    if room['song']:
                        for w in room['players']:
                            if w: await send(w,dict(op='prepare_song',song=room['song'],revision=room['revision']))
    except (OSError,ConnectionError,RuntimeError,asyncio.IncompleteReadError):pass
    finally:
        if room is not None:
            room['members'].discard(writer);room['spectators'].discard(writer)
            if role=='host':
                cancel_bot(room)
                rooms.pop(room['code'],None)
                await broadcast(room,dict(op='error',message='Host disconnected; room closed'))
                for w in list(room['members']):w.close()
            else:
                if role=='guest':
                    room['players'][1]=None;room['ready'][1]=False;room['prepared'][1]=False
                    room['scores'].pop(writer,None);room['phase']='lobby';room['ready'][0]=False
                await broadcast(room,snapshot(room))
        writer.close()
        try:await writer.wait_closed()
        except (OSError,ConnectionError,RuntimeError):pass

async def health(request):
    return web.json_response({'service':'WJMAX PvP','status':'ok','transport':'websocket','rooms':len(rooms)})

async def websocket_handler(request):
    ws = web.WebSocketResponse(heartbeat=25, max_msg_size=MAX_LINE)
    await ws.prepare(request)
    await handler(WSReader(ws), WSWriter(ws))
    return ws

app = web.Application()
app.router.add_get('/', health)
app.router.add_get('/health', health)
app.router.add_get('/ws', websocket_handler)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', '10000'))
    print(f'WJMAX PvP WebSocket server listening on 0.0.0.0:{port}', flush=True)
    web.run_app(app, host='0.0.0.0', port=port)
