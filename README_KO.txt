WJMAX PvP v0.13 - Render WebSocket 서버

[중요]
이 ZIP은 Render 서버 파일만 포함합니다. 현재 v0.13 WJMAXPvP.cs 클라이언트는
TCP Socket을 사용하므로 이 서버에 직접 연결할 수 없습니다.
WJMAX 플러그인의 통신을 WebSocket(wss://.../ws)으로 변경해야 합니다.

GitHub 업로드 파일: server.py, requirements.txt, render.yaml
Render Web Service 설정:
  Runtime: Python 3
  Build Command: pip install -r requirements.txt
  Start Command: python server.py
  Instance Type: Free

배포 성공 후 테스트:
  https://hyeonhoi034.onrender.com/health
  -> JSON status ok 확인
WebSocket endpoint:
  wss://hyeonhoi034.onrender.com/ws

프로토콜: JSON 메시지 한 개당 WebSocket TEXT 프레임 하나.
기존 create, join, spectate, song, prepared, ready, start, score,
finish, reset, bot_* 및 state/prepare_song/start_signal 이벤트 유지.
서버는 메모리 기반이며 Render 재시작 시 방이 초기화됩니다.
무료 서버가 유휴 중지되면 첫 연결이 느릴 수 있습니다.
게임 내 실제 동시 시작/점수 연동은 별도 테스트가 필요합니다.

보안: 이 서버는 별도의 사용자 인증 없이 방 코드를 사용합니다.
비밀 정보/개인 정보를 GitHub 저장소에 올리지 마세요.
