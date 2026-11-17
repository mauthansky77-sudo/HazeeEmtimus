"""Hazee key management trial. Python standard library only."""
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit, parse_qs

ADMIN_TOKEN = os.environ.get('ADMIN_TOKEN', '')
DB_PATH = os.environ.get('DB_PATH', 'data/hazee.sqlite3')
SESSIONS = {}
ATTEMPTS = {}
HE = None


@contextmanager
def connect():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB_PATH, timeout=15)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    try:
        with db:
            yield db
    finally:
        db.close()


def initialize():
    global HE
    with connect() as db:
        db.executescript('''
        CREATE TABLE IF NOT EXISTS licenses(
          id TEXT PRIMARY KEY, digest TEXT NOT NULL UNIQUE, label TEXT NOT NULL,
          expires INTEGER NOT NULL, max_devices INTEGER NOT NULL,
          revoked INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS devices(
          license_id TEXT REFERENCES licenses(id), device_hash TEXT,
          PRIMARY KEY(license_id, device_hash));
        ''')
    if os.environ.get('HE_SIGNING_SEED'):
        from he_compat import HECompat
        HE = HECompat(connect, verify_license)


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def verify_license(key, device):
    if not isinstance(key, str) or not isinstance(device, str) or not key or not device or len(key) > 200 or len(device) > 256:
        return 400, {'valid': False, 'error': 'key_and_device_id_required'}
    with connect() as db:
        db.execute('BEGIN IMMEDIATE')
        row = db.execute('SELECT * FROM licenses WHERE digest=?', (digest(key),)).fetchone()
        if row is None or row['revoked'] or row['expires'] <= time.time():
            return 403, {'valid': False, 'error': 'invalid_expired_or_revoked'}
        device_hash = digest(device)
        bound = db.execute('SELECT 1 FROM devices WHERE license_id=? AND device_hash=?', (row['id'], device_hash)).fetchone()
        count = db.execute('SELECT COUNT(*) FROM devices WHERE license_id=?', (row['id'],)).fetchone()[0]
        if not bound and count >= row['max_devices']:
            return 403, {'valid': False, 'error': 'device_limit'}
        db.execute('INSERT OR IGNORE INTO devices VALUES (?,?)', (row['id'], device_hash))
        return 200, {'valid': True, 'license_id': row['id'], 'expires_at': row['expires']}


PAGE = '''<!doctype html><html lang="vi"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Hazee · Quản lý key</title>
<style>body{font:16px system-ui;background:#101725;color:#e9edf5;margin:0}main{max-width:1000px;margin:50px auto;padding:24px}h1{font-size:32px}section{background:#1a2538;border:1px solid #33445e;border-radius:16px;padding:24px;margin:20px 0}input,button{font:inherit;padding:12px;border-radius:8px;border:1px solid #52627c;margin:5px;background:#101725;color:inherit}button{background:#4169e1;cursor:pointer}table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:12px;border-bottom:1px solid #33445e}small,p{color:#b6c3d7}.scroll{overflow:auto}#message{white-space:pre-wrap;overflow-wrap:anywhere}label{display:inline-block}a{color:#9cb6ff}</style>
<main><small>HAZEE / BẢN THỬ</small><h1>Quản lý key của bạn</h1>
<p>Tạo key có thời hạn, giới hạn thiết bị và thu hồi khi cần.</p>
<section><strong>Lưu ý lưu trữ bản thử</strong><p>Dữ liệu SQLite có thể mất khi Render Free ngủ, khởi động lại hoặc triển khai lại. Hãy xuất danh sách để theo dõi; bản xuất không khôi phục được key. Backend hỗ trợ ứng dụng Hazee Key và giao thức HE build 16 khi đã cấu hình module HE.</p></section>
<section id="login"><h2>Đăng nhập quản trị</h2><form id="loginForm"><input id="token" type="password" autocomplete="current-password" placeholder="Mã quản trị" required><button>Đăng nhập</button></form></section>
<div id="admin" hidden><section><h2>Tạo key</h2><form id="createForm"><input name="label" placeholder="Tên người dùng / ghi chú" maxlength="100" required><label>Ngày <input name="days" type="number" min="1" max="3650" value="7" required></label><label>Thiết bị <input name="max_devices" type="number" min="1" max="100" value="1" required></label><button>Tạo key</button></form><p>Key chỉ hiện một lần sau khi tạo. Lưu ngay để gửi cho người sử dụng.</p></section>
<section><h2>Danh sách key</h2><button id="refresh">Làm mới</button><button id="export">Xuất danh sách JSON</button><button id="logout">Đăng xuất</button><div class="scroll"><table><thead><tr><th>Tên</th><th>Hết hạn</th><th>Thiết bị</th><th>Trạng thái</th><th></th></tr></thead><tbody id="rows"></tbody></table></div></section></div><section id="message" role="status">Đang kết nối…</section></main>
<script>
let csrf='',licenses=[]; const $=id=>document.getElementById(id);const say=t=>$('message').textContent=t;
async function api(path,data){const r=await fetch(path,{method:data?'POST':'GET',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:data?JSON.stringify(data):undefined});const v=await r.json();if(!r.ok)throw Error(v.error||'Yêu cầu thất bại');return v}
function textCell(tr,text){const td=document.createElement('td');td.textContent=text;tr.append(td);return td}
async function refresh(){licenses=(await api('/api/keys')).keys;$('rows').replaceChildren();for(const k of licenses){const tr=document.createElement('tr');textCell(tr,k.label);textCell(tr,new Date(k.expires*1000).toLocaleString('vi-VN'));textCell(tr,k.devices+'/'+k.max_devices);textCell(tr,k.revoked?'Đã thu hồi':k.expires*1000<Date.now()?'Hết hạn':'Hoạt động');const td=textCell(tr,'');if(!k.revoked){const b=document.createElement('button');b.textContent='Thu hồi';b.onclick=async()=>{if(confirm('Thu hồi key của '+k.label+'?'))try{await api('/api/revoke',{id:k.id});await refresh();say('Đã thu hồi key.')}catch(e){say(e.message)}};td.append(b)}$('rows').append(tr)}}
async function boot(){try{const s=await api('/api/session');csrf=s.csrf;$('login').hidden=true;$('admin').hidden=false;await refresh();say('Đã kết nối.')}catch(e){$('login').hidden=false;$('admin').hidden=true;say('Nhập mã quản trị để tiếp tục.')}}
$('loginForm').onsubmit=async e=>{e.preventDefault();try{await api('/api/login',{token:$('token').value});$('token').value='';await boot()}catch(e){say(e.message)}};
$('createForm').onsubmit=async e=>{e.preventDefault();try{const f=new FormData(e.target);const k=await api('/api/keys',{label:f.get('label'),days:Number(f.get('days')),max_devices:Number(f.get('max_devices'))});await refresh();say('Key mới (lưu ngay):\\n'+k.key)}catch(e){say(e.message)}};
$('refresh').onclick=()=>refresh().catch(e=>say(e.message));$('logout').onclick=async()=>{await api('/api/logout',{});csrf='';boot()};
$('export').onclick=()=>{const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([JSON.stringify(licenses,null,2)],{type:'application/json'}));a.download='hazee-key-list.json';a.click();URL.revokeObjectURL(a.href)};boot();
</script></html>'''


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        # Never log request bodies, cookies or tokens.
        pass

    def send(self, status, value, cookie=None):
        html = isinstance(value, str)
        body = (value if html else json.dumps(value)).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'text/html; charset=utf-8' if html else 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'")
        if cookie:
            self.send_header('Set-Cookie', cookie)
        self.end_headers()
        self.wfile.write(body)

    def session(self):
        try:
            cookies = SimpleCookie(self.headers.get('Cookie', ''))
            token = cookies['hazee_session'].value
            data = SESSIONS.get(token)
            if data and data['expires'] > time.time():
                return token, data
        except (KeyError, ValueError):
            pass
        return None, None

    def cookie(self, token, age=28800):
        secure = '; Secure' if os.environ.get('RENDER') or self.headers.get('X-Forwarded-Proto') == 'https' else ''
        return f'hazee_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={age}{secure}'

    def send_asset(self):
        data = HE.blob_path.read_bytes()
        self.send_response(200)
        self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        route = urlsplit(self.path)
        if route.path == '/api/v1/android/menu/manifest':
            if HE is None:
                return self.send(503, {'ok': False, 'code': 'he_not_configured'})
            from he_compat import HEError
            try:
                query = {key: values[0] for key, values in parse_qs(route.query).items()}
                return self.send(200, HE.manifest(query))
            except HEError as error:
                return self.send(error.status, {'ok': False, 'code': error.code})
        if route.path.startswith('/api/v1/android/menu/assets/'):
            if HE is None or route.path != '/api/v1/android/menu/assets/' + HE.release['asset_sha256'] + '.bin':
                return self.send(404, {'error': 'not_found'})
            return self.send_asset()
        if self.path == '/health':
            return self.send(200, {'status': 'ok', 'app': 'hazee-key-trial'})
        if self.path == '/':
            return self.send(200, PAGE)
        _, session = self.session()
        if not session:
            return self.send(401, {'error': 'unauthorized'})
        if self.path == '/api/session':
            return self.send(200, {'csrf': session['csrf']})
        if self.path == '/api/keys':
            with connect() as db:
                keys = [dict(row) for row in db.execute('SELECT l.id,l.label,l.expires,l.max_devices,l.revoked,l.created,COUNT(d.device_hash) AS devices FROM licenses l LEFT JOIN devices d ON d.license_id=l.id GROUP BY l.id ORDER BY l.created DESC')]
            return self.send(200, {'keys': keys})
        self.send(404, {'error': 'not_found'})

    def do_POST(self):
        now = time.time()
        # Bound memory and throttle failures without storing raw client identifiers.
        for table in (SESSIONS, ATTEMPTS):
            for key in list(table):
                if table[key]['expires'] < now:
                    table.pop(key, None)
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= 4096:
                return self.send(413, {'error': 'invalid_body_size'})
            data = json.loads(self.rfile.read(length))
            if not isinstance(data, dict):
                raise ValueError()
        except (ValueError, UnicodeError):
            return self.send(400, {'error': 'invalid_json'})
        if self.path in ('/api/login', '/api/v1/licenses/verify') or self.path.startswith('/api/v2/licenses/key-vault/'):
            ip = digest(self.headers.get('X-Forwarded-For', self.client_address[0]).split(',')[-1].strip() + self.path)
            bucket = ATTEMPTS.setdefault(ip, {'expires': now + 60, 'count': 0})
            bucket['count'] += 1
            if bucket['count'] > 20:
                return self.send(429, {'error': 'too_many_requests'})
        if self.path == '/api/login':
            token = data.get('token', '')
            if not isinstance(token, str) or not ADMIN_TOKEN or not hmac.compare_digest(token.encode(), ADMIN_TOKEN.encode()):
                return self.send(401, {'error': 'Mã quản trị không đúng'})
            sid = secrets.token_urlsafe(32)
            SESSIONS[sid] = {'expires': now + 28800, 'csrf': secrets.token_urlsafe(32)}
            return self.send(200, {'ok': True}, self.cookie(sid))
        if self.path == '/api/v1/licenses/verify':
            if 'product' in data:
                if HE is None:
                    return self.send(503, {'ok': False, 'code': 'he_not_configured'})
                from he_compat import HEError
                try:
                    return self.send(200, HE.verify(data))
                except HEError as error:
                    return self.send(error.status, {'ok': False, 'code': error.code})
            status, result = verify_license(data.get('key'), data.get('device_id'))
            return self.send(status, result)
        if self.path.startswith('/api/v1/android/menu/assets/'):
            if HE is None or self.path != '/api/v1/android/menu/assets/' + HE.release['asset_sha256'] + '.bin':
                return self.send(404, {'error': 'not_found'})
            from he_compat import HEError
            try:
                HE.authorize(data)
            except HEError as error:
                return self.send(error.status, {'ok': False, 'code': error.code})
            return self.send_asset()
        if self.path.startswith('/api/v2/licenses/key-vault/'):
            if HE is None:
                return self.send(503, {'ok': False, 'code': 'he_not_configured'})
            from he_compat import HEError
            try:
                return self.send(200, HE.vault(self.path.rsplit('/', 1)[-1], data))
            except HEError as error:
                return self.send(error.status, {'ok': False, 'code': error.code})
        sid, session = self.session()
        if not session or not hmac.compare_digest(self.headers.get('X-CSRF-Token', ''), session['csrf']):
            return self.send(403, {'error': 'unauthorized_or_csrf'})
        if self.path == '/api/logout':
            SESSIONS.pop(sid, None)
            return self.send(200, {'ok': True}, self.cookie('', 0))
        if self.path == '/api/keys':
            label, days, maximum = data.get('label'), data.get('days'), data.get('max_devices')
            if not isinstance(label, str) or not 1 <= len(label.strip()) <= 100 or type(days) is not int or not 1 <= days <= 3650 or type(maximum) is not int or not 1 <= maximum <= 100:
                return self.send(400, {'error': 'Thông tin key không hợp lệ'})
            key = 'HZ-' + secrets.token_urlsafe(24)
            lid = secrets.token_hex(12)
            expires = int(now) + days * 86400
            with connect() as db:
                db.execute('INSERT INTO licenses VALUES (?,?,?,?,?,?,?)', (lid, digest(key), label.strip(), expires, maximum, 0, int(now)))
            return self.send(201, {'id': lid, 'key': key, 'expires_at': expires})
        if self.path == '/api/revoke':
            lid = data.get('id')
            if not isinstance(lid, str):
                return self.send(400, {'error': 'id_required'})
            with connect() as db:
                changed = db.execute('UPDATE licenses SET revoked=1 WHERE id=?', (lid,)).rowcount
            return self.send(200 if changed else 404, {'ok': bool(changed)})
        self.send(404, {'error': 'not_found'})


if __name__ == '__main__':
    if len(ADMIN_TOKEN) < 24:
        raise SystemExit('Set ADMIN_TOKEN to a random secret of at least 24 characters.')
    initialize()
    ThreadingHTTPServer(('0.0.0.0', int(os.environ.get('PORT', '10000'))), Handler).serve_forever()
