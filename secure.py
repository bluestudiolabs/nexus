"""HTTPS-only NEXUS web gateway. No host control or Docker socket."""
import dashboard as dash
import features as f3
import server as hostmon,core as c, ssl,hashlib,hmac,secrets,time,json,threading,os,base64,re,socket
from pathlib import Path
from http.cookies import SimpleCookie
from urllib.parse import urlsplit,parse_qs
from http.server import ThreadingHTTPServer
AUTH=Path(os.getenv('NEXUS_AUTH','/auth/password.json')); APP=Path(__file__).parent
HOST=os.getenv('NEXUS_HOST','127.0.0.1:3010'); ORIGIN='https://'+HOST
sessions={}; pending_totp={}; guard=threading.RLock(); attempts={}; slots=threading.BoundedSemaphore(20)
LOGIN=b'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>NEXUS / Sign in</title><style>body{background:#080d17;color:#eaf5ff;font:16px system-ui;display:grid;place-items:center;min-height:95vh}main{width:min(90vw,370px);padding:32px;border:1px solid #28425a;border-radius:16px;background:#111c2b}h1{color:#39e4ff}input,button{box-sizing:border-box;width:100%;padding:12px;margin:8px 0;background:#152436;color:white;border:1px solid #36536a;border-radius:8px}button{cursor:pointer}</style><main><h1>NEXUS / 3.0 clean preview</h1><p>Private infrastructure command center</p><form id="login"><label>Owner password<input id="pw" type="password" autocomplete="current-password" required maxlength="256"></label><label>Authenticator or recovery code (if enabled)<input id="otp" autocomplete="one-time-code" maxlength="100"></label><button>Sign in</button></form><p id="msg"></p></main><script src="/login.js" defer></script></html>'''
LOGINJS=b'''document.getElementById('login').onsubmit=async e=>{e.preventDefault();const pw=document.getElementById('pw'),m=document.getElementById('msg');try{const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pw.value,otp:document.getElementById('otp').value})});pw.value='';document.getElementById('otp').value='';if(r.ok)location.replace('/');else m.textContent=r.status===429?'Try again later':'Sign-in failed'}catch{m.textContent='Connection unavailable'}}'''
def check_password(p):
    if not isinstance(p,str) or len(p)>256:return False
    d=json.loads(AUTH.read_text());v=hashlib.scrypt(p.encode(),salt=bytes.fromhex(d['salt']),n=32768,r=8,p=1,maxmem=64*1024**2);return hmac.compare_digest(v.hex(),d['hash'])
def limited(key,count,window):
    now=time.monotonic()
    with guard:
        if len(attempts)>2048:
            for k in list(attempts):
                if now-attempts[k][0]>600:del attempts[k]
            if len(attempts)>2048:return True
        start,n=attempts.get(key,(now,0));start,n=(now,0) if now-start>=window else (start,n)
        if n>=count:return True
        attempts[key]=(start,n+1);return False
class Handler(hostmon.Handler):
    protocol_version='HTTP/1.0'
    def setup(self):self.request.settimeout(8);super().setup()
    def host_allowed(self):return self.headers.get('Host','')==HOST
    def end_headers(self):
        self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff');self.send_header('X-Frame-Options','DENY');self.send_header('Referrer-Policy','no-referrer');self.send_header('Permissions-Policy','camera=(), microphone=(), geolocation=()');self.send_header('Content-Security-Policy',"default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");super().end_headers()
    def send(self,data,typ,status=200,cookie=None):
        self.send_response(status);self.send_header('Content-Type',typ);self.send_header('Content-Length',str(len(data)))
        if cookie:self.send_header('Set-Cookie',cookie)
        self.end_headers();self.wfile.write(data)
    def reply(self,obj,status=200,cookie=None):self.send(json.dumps(obj,allow_nan=False).encode(),'application/json',status,cookie)
    def session(self):
        try:jar=SimpleCookie(self.headers.get('Cookie',''));key=jar['__Host-nexus'].value
        except (KeyError,ValueError):return None
        with guard:
            if sessions.get(key,0)>time.time():return key
            sessions.pop(key,None);return None
    def authorized(self):return bool(self.session())
    def body(self):
        if self.headers.get('Transfer-Encoding') or self.headers.get_content_type()!='application/json':raise ValueError()
        if len(self.headers.get_all('Content-Length',[]))!=1:raise ValueError()
        n=int(self.headers['Content-Length']);
        if not 0<n<=65536:raise ValueError()
        d=json.loads(self.rfile.read(n));
        if not isinstance(d,dict):raise ValueError()
        return d
    def do_GET(self):
        if not self.host_allowed():return self.reply({'error':'Invalid host'},403)
        p=urlsplit(self.path).path
        if p=='/login.js':return self.send(LOGINJS,'application/javascript')
        if not self.authorized():
            if p in ('/','/index.html'):return self.send(LOGIN,'text/html; charset=utf-8')
            return self.reply({'error':'Sign in required'},401)
        try:
            if p in ('/','/index.html'):return self.send((APP/'index.html').read_bytes(),'text/html; charset=utf-8')
            if p in ('/app.js','/extra.js','/dashboard.js','/dashboard.css','/agent-linux.py','/features.js','/nexus-agent-linux.zip','/NEXUS-Agent-Setup-x64.exe'):
                return self.send((APP/p[1:]).read_bytes(),'application/javascript' if p.endswith('.js') else 'text/css' if p.endswith('.css') else 'application/octet-stream')
            if p=='/api/dashboard':return self.reply(dash.load())
            if p=='/api/v3/rules':return self.reply(f3.rules())
            if p=='/api/v3/privacy':return self.reply(f3.privacy())
            if p=='/api/v3/security':return self.reply({'totp':bool(f3.auth_state().get('secret')),'webUninstall':f3.lifecycle_enabled()})
            if p=='/api/v3/milestones':return self.reply(f3.milestones(hostmon.current))
            if p=='/api/v3/history':
                q=parse_qs(urlsplit(self.path).query);return self.reply(f3.history_many(q.get('id',[]),q.get('hours',[24])[0]))
            if p=='/api/overview':
                with hostmon.lock: host=hostmon.current.copy(); kuma=hostmon.kuma.copy()
                return self.reply(dash.overview(host,kuma,snapshot(),insights()))
            if p=='/api/registry':return self.reply(c.registry())
            if p=='/api/devices':
                rows=c.registry()
                snap=snapshot(); lookup={r['id']:r for r in rows}; probes=[dict(x,name=lookup.get(x['id'],{}).get('name','Device'),type=lookup.get(x['id'],{}).get('kind','Unknown')) for x in snap.get('devices',[])];return self.reply({'devices':probes,'time':snap.get('time')})
            if p=='/api/console':
                q=parse_qs(urlsplit(self.path).query);return self.reply(c.console_history(q.get('id',[''])[0],q.get('hours',[24])[0]))
            if p=='/api/history':
                q=parse_qs(urlsplit(self.path).query);return self.reply(c.history(q.get('id',['host'])[0],q.get('hours',[24])[0]))
            if p=='/api/events':
                with c.db() as db:return self.reply([dict(r) for r in db.execute('SELECT * FROM events ORDER BY t DESC LIMIT 100')])
            if p=='/api/preferences':return self.reply(c.setting('preferences',{'notes':'','tasks':[]}))
            if p=='/api/insights':return self.reply(insights())
            if p=='/api/config':return self.reply(c.setting('config',{'cpuTemp':80,'gpuTemp':85,'diskUsed':90,'weather':False}))
            if p=='/api/weather':
                if not c.setting('config',{}).get('weather'):return self.reply({'error':'External requests disabled'},403)
                city=parse_qs(urlsplit(self.path).query).get('city',[''])[0]
                lat,lon=map(float,city.split(','))
                if not (-90<=lat<=90 and -180<=lon<=180):raise ValueError()
                if limited('weather',6,60):return self.reply({'error':'Rate limited'},429)
                import urllib.request
                url=f'https://api.open-meteo.com/v1/forecast?latitude={lat}&longitude={lon}&current=temperature_2m,relative_humidity_2m,wind_speed_10m&daily=temperature_2m_max,temperature_2m_min&forecast_days=3&timezone=auto'
                with urllib.request.urlopen(url,timeout=5) as r:return self.reply(json.loads(r.read(65536)))
            if p=='/api/backup':
                # Consistent SQLite snapshot: private, includes the TOTP seed if enabled.
                import sqlite3,tempfile
                with tempfile.TemporaryDirectory() as td:
                    target=Path(td)/'nexus.sqlite3';dest=sqlite3.connect(target)
                    try:
                        with c.db() as src:src.backup(dest)
                    finally:dest.close()
                    self.send(target.read_bytes(),'application/octet-stream')
                return
            if p=='/api/host':
                data=snapshot();return self.reply(data,200 if data else 503)
            if p in ('/api/state','/index.html'):return super().do_GET()
            return self.reply({'error':'Not found'},404)
        except (ValueError,TypeError,KeyError,OSError):return self.reply({'error':'Unavailable or invalid request'},400)
    def do_POST(self):
        if not self.host_allowed():return self.reply({'error':'Invalid host'},403)
        p=urlsplit(self.path).path;ip=self.client_address[0]
        try:
            if p in ('/api/pair','/api/ingest'):
                if self.headers.get('Origin') is not None:return self.reply({'error':'Agent only'},403)
                if limited('agent:'+ip,120,60):return self.reply({'error':'Rate limited'},429)
                d=self.body()
                if p=='/api/pair':
                    if limited('pair:'+ip,6,600) or limited('pair:global',40,600):return self.reply({'error':'Rate limited'},429)
                    if not isinstance(d.get('code'),str):raise ValueError()
                    return self.reply(c.pair(d['code']))
                token=self.headers.get('Authorization','');
                if not token.startswith('Bearer '):raise PermissionError()
                c.ingest(token[7:],d,ip);return self.reply({'ok':True})
            if self.headers.get('Origin')!=ORIGIN:return self.reply({'error':'Invalid origin'},403)
            d=self.body()
            if p=='/api/login':
                if limited('login:'+ip,5,300) or limited('login:global',20,300):return self.reply({'error':'Rate limited'},429)
                if not check_password(d.get('password')) or not f3.verify_totp(d.get('otp')):
                    with c.db() as db:c.event(db,'login','Failed owner login')
                    return self.reply({'error':'Invalid credentials'},401)
                key=secrets.token_urlsafe(32)
                with guard:
                    for k in list(sessions):
                        if sessions[k]<=time.time():del sessions[k]
                    if len(sessions)>=32:sessions.pop(next(iter(sessions)))
                    for k in list(pending_totp):
                        if k not in sessions or pending_totp[k][1]<time.time():pending_totp.pop(k,None)
                    sessions[key]=time.time()+8*3600
                with c.db() as db:c.event(db,'login','Owner session created')
                return self.reply({'ok':True},cookie='__Host-nexus='+key+'; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=28800')
            if not self.authorized():return self.reply({'error':'Sign in required'},401)
            if p=='/api/logout':
                with guard:sessions.pop(self.session(),None)
                return self.reply({'ok':True},cookie='__Host-nexus=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0')
            if p=='/api/dashboard':return self.reply(dash.save(d))
            if p=='/api/v3/rules':return self.reply(f3.save_rules(d))
            if p=='/api/v3/privacy':return self.reply(f3.save_privacy(d))
            if p in ('/api/v3/totp/start','/api/v3/totp/enable','/api/v3/totp/disable','/api/v3/uninstall'):
                if limited('sensitive:'+ip,5,300):return self.reply({'error':'Rate limited'},429)
                if not check_password(d.get('password')):return self.reply({'error':'Reauthentication failed'},403)
                if p=='/api/v3/totp/start':
                    if f3.auth_state().get('secret'):raise ValueError()
                    secret=f3.start_totp()
                    with guard:pending_totp[self.session()]=(secret,time.time()+300)
                    return self.reply({'secret':secret})
                if p=='/api/v3/totp/enable':
                    with guard:pending=pending_totp.pop(self.session(),None)
                    if not pending or pending[1]<time.time():raise ValueError()
                    codes=f3.enable_totp(pending[0],d.get('otp'))
                    with guard:
                        current=self.session();sessions.clear();sessions[current]=time.time()+8*3600;pending_totp.clear()
                    return self.reply({'recovery':codes})
                if p=='/api/v3/totp/disable':
                    if not f3.verify_totp(d.get('otp'),disable=True):return self.reply({'error':'Invalid code'},403)
                    with guard:
                        current=self.session();sessions.clear();sessions[current]=time.time()+8*3600;pending_totp.clear()
                    return self.reply({'ok':True})
                if d.get('confirm')!='UNINSTALL NEXUS' or not f3.verify_totp(d.get('otp')):return self.reply({'error':'Confirmation or code invalid'},403)
                f3.request_uninstall(d.get('mode'));return self.reply({'ok':True,'queued':True})
            if p=='/api/device':c.configure(d)
            elif p=='/api/register':return self.reply({'id':c.register(d)})
            elif p=='/api/pair-code':return self.reply({'code':c.pair_code(d['id']),'expiresIn':600})
            elif p=='/api/revoke':c.revoke(d['id'])
            elif p=='/api/preferences':
                notes=d.get('notes');tasks=d.get('tasks');
                if not isinstance(notes,str) or len(notes)>12000 or not isinstance(tasks,list) or len(tasks)>100 or any(not isinstance(t,dict) or not isinstance(t.get('text'),str) or len(t['text'])>300 or type(t.get('done')) is not bool for t in tasks):raise ValueError()
                c.set_setting('preferences',{'notes':notes,'tasks':tasks})
            elif p=='/api/config':
                if any(type(d.get(k)) not in (float,int) or not lo<=d[k]<=hi for k,lo,hi in [('cpuTemp',40,100),('gpuTemp',40,110),('diskUsed',50,99)]) or type(d.get('weather')) is not bool:raise ValueError()
                c.set_setting('config',{k:d[k] for k in ('cpuTemp','gpuTemp','diskUsed','weather')})
            else:return self.reply({'error':'Not found'},404)
            return self.reply({'ok':True})
        except PermissionError:return self.reply({'error':'Unauthorized agent'},401)
        except BlockingIOError:return self.reply({'error':'Sample rate exceeded'},429)
        except (ValueError,TypeError,KeyError,AttributeError,OSError):return self.reply({'error':'Invalid request or unavailable'},400)
def snapshot():
    try:return json.loads((Path(os.getenv('NEXUS_TELEMETRY','/host/telemetry'))/'snapshot.json').read_text())
    except (OSError,ValueError):return {}
def insights():
    out=[];cfg=c.setting('config',{'cpuTemp':80,'gpuTemp':85,'diskUsed':90});s=snapshot();v=hostmon.current
    def add(level,msg):out.append({'level':level,'message':msg})
    if time.time()-s.get('time',0)>240:add('warning','Host collector missing or stale')
    if isinstance(v.get('temp'),(int,float)) and v['temp']>=cfg['cpuTemp']:add('critical','Host CPU temperature above configured threshold')
    for k in ('ssd','media'):
        d=v.get(k); 
        if d and d['total'] and 100*(1-d['free']/d['total'])>=cfg['diskUsed']:add('warning',k+' capacity threshold exceeded')
    for d in s.get('smart',[]):
        if d.get('passed') is False or (d.get('pending') or 0)>0 or (d.get('uncorrectable') or 0)>0:add('critical',d['device']+' SMART requires attention')
        elif (d.get('reallocated') or 0)>0:add('warning',d['device']+' has reallocated sectors; compare trends and maintain backup')
    if s.get('failed'):add('warning','Failed systemd services detected')
    if s.get('rebootRequired'):add('info','Host reboot required')
    for r in c.registry():
        if r['mode']=='pending':continue
        if r['mode']=='full' and r['sample']:
            a=json.loads(r['sample']);
            if time.time()-a['time']>60:add('info',r['name']+' telemetry stale; may be asleep')
            elif (a.get('gpuTemp') or 0)>=cfg['gpuTemp']:add('warning',r['name']+' GPU temperature above threshold')
    return out
def background():
    last=0;pruned=0;previous=set(); evaluator=f3.Evaluator()
    while True:
        try:
            s=snapshot()
            if s.get('time',0)>last and time.time()-s['time']<300:
                c.observe(s.get('observed') or []);c.record_network(s);last=s['time']
            if hostmon.current.get('time'):
                with c.db() as db:c.metric(db,'host',hostmon.current.copy())
            current={(x['level'],x['message']) for x in insights()}
            with c.db() as db:
                for level,msg in current-previous:c.event(db,level,msg)
            previous=current
            evaluator.tick(hostmon.current.copy())
            if time.time()-pruned>3600:c.prune();pruned=time.time()
        except Exception as e:print('Background error:',type(e).__name__,flush=True)
        time.sleep(10)
class BoundedServer(ThreadingHTTPServer):
    daemon_threads=True;request_queue_size=32
    def process_request(self,request,address):
        if not slots.acquire(False):self.shutdown_request(request);return
        try:super().process_request(request,address)
        except BaseException:slots.release();raise
    def process_request_thread(self,request,address):
        try:
            request.settimeout(8);request.do_handshake();super().process_request_thread(request,address)
        except (OSError,ssl.SSLError):self.shutdown_request(request)
        finally:slots.release()
if __name__=='__main__':
    os.umask(0o077);c.init()
    for f in (hostmon.collect,hostmon.monitor,background):threading.Thread(target=f,daemon=True).start()
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.minimum_version=ssl.TLSVersion.TLSv1_2;ctx.load_cert_chain(os.getenv('NEXUS_TLS_CERT','/tls/server.crt'),os.getenv('NEXUS_TLS_KEY','/tls/server.key'))
    http=BoundedServer((os.getenv('NEXUS_LISTEN','0.0.0.0'),int(os.getenv('NEXUS_INTERNAL_PORT','8080'))),Handler);http.socket=ctx.wrap_socket(http.socket,server_side=True,do_handshake_on_connect=False);http.serve_forever()
