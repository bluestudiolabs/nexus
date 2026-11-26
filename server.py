import os, time, json, glob, threading, urllib.request, hmac
from urllib.parse import urlsplit
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
P=Path(os.getenv('NEXUS_PROC','/host/proc')); S=Path(os.getenv('NEXUS_SYS','/host/sys')); IFACE=os.getenv('NEXUS_INTERFACE',''); NET=Path(os.getenv('NEXUS_NETDEV',str(P/'net/dev'))); lock=threading.Lock(); history=deque(maxlen=180); current={}; kuma={}; last=None; prior_cores={}; prior_disks={}

def disk(path):
    try:
        s=os.statvfs(path); return {'total':s.f_blocks*s.f_frsize,'free':s.f_bavail*s.f_frsize}
    except OSError: return None

def sample():
    global last
    a=list(map(int,(P/'stat').read_text().splitlines()[0].split()[1:9])); total=sum(a); idle=a[3]+a[4]
    m={x.split(':')[0]:int(x.split()[1])*1024 for x in (P/'meminfo').read_text().splitlines() if x.split(':')[0] in ('MemTotal','MemAvailable','SwapTotal','SwapFree')}
    rx=tx=None
    for line in NET.read_text().splitlines()[2:]:
        name,values=line.split(':'); v=values.split()
        if name.strip()==IFACE: rx=int(v[0]); tx=int(v[8])
    now=time.monotonic(); cpu=down=up=None
    if last:
        dt=now-last[0]; delta=total-last[1]
        if delta>0: cpu=round(100*(1-(idle-last[2])/delta),1)
        if rx is not None and last[3] is not None:
            down=max(0,(rx-last[3])/dt); up=max(0,(tx-last[4])/dt)
    last=(now,total,idle,rx,tx)
    temps=[]
    for f in glob.glob(str(S/'class/hwmon/hwmon*/temp*_input')):
        try:
            if (Path(f).parent/'name').read_text().strip() in ('coretemp','k10temp','zenpower','cpu_thermal'): temps.append(int(Path(f).read_text())/1000)
        except (OSError,ValueError): pass
    cores=[]
    for line in (P/'stat').read_text().splitlines():
        fields=line.split()
        if not fields or not fields[0].startswith('cpu') or not fields[0][3:].isdigit(): continue
        a=list(map(int,fields[1:9])); t=sum(a); i=a[3]+a[4]; old=prior_cores.get(fields[0]); prior_cores[fields[0]]=(t,i)
        cores.append({'name':fields[0],'usage':round(100*(1-(i-old[1])/(t-old[0])),1) if old and t>old[0] else None})
    fans=[]
    for f in sorted((S/'class/hwmon').glob('hwmon*/fan*_input')):
        try:
            label=f.with_name(f.name.replace('_input','_label'))
            fans.append({'name':label.read_text().strip() if label.exists() else f.stem.replace('_input',''), 'rpm':int(f.read_text())})
        except (OSError,ValueError): pass
    drives={}
    for name in sorted(p.name for p in (S/'block').glob('*') if not p.name.startswith(('loop','ram','zram','dm-'))):
        try:
            a=list(map(int,(S/'block'/name/'stat').read_text().split())); old=prior_disks.get(name); prior_disks[name]=(now,a)
            dt=now-old[0] if old else 0
            drives[name]={'read':max(0,(a[2]-old[1][2])*512/dt) if dt else None,'write':max(0,(a[6]-old[1][6])*512/dt) if dt else None,'busy':min(100,max(0,(a[9]-old[1][9])/dt/10)) if dt else None}
        except (OSError,ValueError,IndexError): pass
    def readnum(path):
        try: return int(path.read_text())
        except (OSError,ValueError): return None
    return {'cores':cores,'fans':fans,'drives':drives,'swapTotal':m.get('SwapTotal'),'swapUsed':m.get('SwapTotal',0)-m.get('SwapFree',0),'linkSpeed':readnum(S/'class/net'/IFACE/'speed'),'time':int(time.time()),'cpu':cpu,'ram':round(100*(1-m['MemAvailable']/m['MemTotal']),1),'available':m['MemAvailable'],'memTotal':m['MemTotal'],'temp':max(temps) if temps else None,'rx':down,'tx':up,'uptime':float((P/'uptime').read_text().split()[0]),'ssd':disk(os.getenv('NEXUS_SYSTEM_METER','/host/ssd')),'media':disk(os.getenv('NEXUS_EXTRA_METER','/host/media'))}

def collect():
    global current
    while True:
        try:
            d=sample()
            with lock: current=d; history.append(d)
        except Exception as e: print('metrics:',str(e),flush=True)
        time.sleep(5)

def monitor():
    global kuma
    base=os.getenv('KUMA_URL','').rstrip('/'); slug=os.getenv('KUMA_SLUG','')
    if not base or not slug:
        with lock:kuma={'rows':[],'error':'Uptime Kuma not configured'}
        return
    def get(path):
        with urllib.request.urlopen(base+path,timeout=5) as r: return json.load(r)
    while True:
        try:
            page=get('/api/status-page/'+slug); hb=get('/api/status-page/heartbeat/'+slug); beats=hb.get('heartbeatList',{}); uptimes=hb.get('uptimeList',{}); rows=[]
            for group in page.get('publicGroupList',[]):
                for mon in group.get('monitorList',[]):
                    key=str(mon['id']); seq=beats.get(key,[]); val=uptimes.get(key+'_24'); rows.append({'name':mon['name'],'status':seq[-1].get('status') if seq else None,'uptime':val,'beats':[b.get('status') for b in seq[-40:]]})
            with lock: kuma={'rows':rows,'time':int(time.time())}
        except Exception:
            with lock: kuma={'error':'Kuma status unavailable','rows':[]}
        time.sleep(30)

class Handler(BaseHTTPRequestHandler):
    def host_allowed(self):
        return self.headers.get('Host','')==os.getenv('NEXUS_HOST','127.0.0.1:3010')
    def reply(self, obj, status=200):
        data=json.dumps(obj).encode(); self.send_response(status); self.send_header('Content-Type','application/json'); self.send_header('Cache-Control','no-store'); self.send_header('Content-Length',str(len(data))); self.send_header('X-Content-Type-Options','nosniff'); self.end_headers(); self.wfile.write(data)
    def do_GET(self):
        if not self.host_allowed():return self.reply({'error':'Invalid host'},403)
        p=urlsplit(self.path).path
        if p=='/api/state':
            with lock:data={'current':current,'history':list(history),'kuma':kuma}
            return self.reply(data)
        return self.reply({'error':'Not found'},404)
    def log_message(self,*args):pass
