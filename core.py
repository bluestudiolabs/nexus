"""NEXUS 2 local database, identities and bounded history."""
import sqlite3,json,time,secrets,hashlib,re,ipaddress,os,math,threading
from pathlib import Path
from contextlib import contextmanager
DATA=Path(os.getenv('NEXUS_DATA','/data')); DB=DATA/'nexus.sqlite3'
projection_lock=threading.Lock()
LAN=ipaddress.ip_network(os.getenv('NEXUS_LAN','127.0.0.0/8'))
def digest(s): return hashlib.sha256(s.encode()).hexdigest()
def ip_ok(s):
    try:return isinstance(s,str) and ipaddress.ip_address(s) in LAN
    except ValueError:return False
def mac_ok(s):return isinstance(s,str) and bool(re.fullmatch(r'[0-9a-f]{2}(:[0-9a-f]{2}){5}',s))
@contextmanager
def db():
    c=sqlite3.connect(DB,timeout=10); c.row_factory=sqlite3.Row
    try:
        with c:yield c
    finally:c.close()
def init():
    DATA.mkdir(parents=True,exist_ok=True)
    with db() as c:
        c.execute('pragma journal_mode=WAL')
        c.executescript('''CREATE TABLE IF NOT EXISTS devices(id TEXT PRIMARY KEY,name TEXT NOT NULL,kind TEXT NOT NULL,mode TEXT NOT NULL,mac TEXT,ip TEXT,last INTEGER,token TEXT UNIQUE,code TEXT UNIQUE,expires INTEGER, sample TEXT); CREATE UNIQUE INDEX IF NOT EXISTS mac_unique ON devices(mac) WHERE mac IS NOT NULL; CREATE TABLE IF NOT EXISTS metrics(id TEXT,t INTEGER,cpu REAL,ram REAL,gpu REAL,temp REAL,rx REAL,tx REAL,PRIMARY KEY(id,t)); CREATE TABLE IF NOT EXISTS events(t INTEGER,kind TEXT,message TEXT); CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY,v TEXT);''')
        c.execute("CREATE TABLE IF NOT EXISTS network_metrics(id TEXT,t INTEGER,status TEXT,latency REAL,loss REAL,variation REAL,PRIMARY KEY(id,t))")
    project()
def event(c,k,m):c.execute('INSERT INTO events VALUES(?,?,?)',(int(time.time()),k,m[:300]))
def project():
    with projection_lock:
        with db() as c: rows=[dict(x) for x in c.execute("SELECT id,ip,mac FROM devices WHERE mode='network' AND ip IS NOT NULL LIMIT 32")]
        tmp=DATA/'probes.tmp';tmp.write_text(json.dumps(rows));tmp.chmod(0o600);tmp.replace(DATA/'probes.json')
def observe(rows):
    with db() as c:
        for r in rows[:1024]:
            ip,mac=r.get('ip'),str(r.get('mac','')).lower()
            if not ip_ok(ip) or not mac_ok(mac):continue
            old=c.execute('SELECT * FROM devices WHERE mac=?',(mac,)).fetchone()
            if old:
                if old['ip']!=ip and old['mode'] not in ('ignored','known'):event(c,'ip',old['name']+' IP changed to '+ip)
                c.execute('UPDATE devices SET ip=?,last=? WHERE id=?',(ip,int(time.time()),old['id']));continue
            # Never bind a known identity solely from an IP address. Owner must approve MAC.
            if c.execute('SELECT count(*) FROM devices').fetchone()[0]>=512:continue
            id=secrets.token_hex(12);c.execute('INSERT INTO devices(id,name,kind,mode,mac,ip,last) VALUES(?,?,?,?,?,?,?)',(id,'Unclassified device','Unknown','pending',mac,ip,int(time.time())))
            event(c,'discovery','New device observed: '+ip)
    project()
def registry():
    with db() as c:return [dict(r) for r in c.execute('SELECT id,name,kind,mode,mac,ip,last,sample, token IS NOT NULL AS paired FROM devices ORDER BY mode,name')]
def configure(d):
    id=d['id']; name=d['name']; kind=d['kind']; mode=d['mode']; merge=d.get('merge')
    if not isinstance(name,str) or not 1<=len(name.strip())<=80 or kind not in ('Windows','Linux','Console','Tablet','Phone','Router','IoT','Other','Unknown') or mode not in ('pending','full','network','known','ignored'):raise ValueError('Invalid profile')
    with db() as c:
        row=c.execute('SELECT * FROM devices WHERE id=?',(id,)).fetchone()
        if not row:raise ValueError('Unknown device')
        if merge:
            target=c.execute('SELECT * FROM devices WHERE id=?',(merge,)).fetchone()
            if not target or row['mode']!='pending' or not row['mac'] or target['mac'] or target['id']==id:raise ValueError('Invalid association')
            c.execute('DELETE FROM devices WHERE id=?',(id,));id=merge
            c.execute('UPDATE devices SET mac=?,ip=?,last=? WHERE id=?',(row['mac'],row['ip'],row['last'],id))
        c.execute("UPDATE devices SET name=?,kind=?,mode=?,token=CASE WHEN ?='full' THEN token ELSE NULL END,sample=CASE WHEN ?='full' THEN sample ELSE NULL END,code=NULL,expires=NULL WHERE id=?",(name.strip(),kind,mode,mode,mode,id));event(c,'device','Profile updated: '+name)
    project()
def register(d):
    name=d.get('name');kind=d.get('kind')
    if not isinstance(name,str) or not 1<=len(name.strip())<=80 or kind not in ('Windows','Linux'):raise ValueError('Invalid computer profile')
    with db() as c:
        c.execute('BEGIN IMMEDIATE')
        if c.execute('SELECT count(*) FROM devices').fetchone()[0]>=512:raise ValueError('Registry full')
        if c.execute('SELECT 1 FROM devices WHERE lower(name)=lower(?)',(name.strip(),)).fetchone():raise ValueError('Name already exists')
        id=secrets.token_hex(12);c.execute('INSERT INTO devices(id,name,kind,mode) VALUES(?,?,?,?)',(id,name.strip(),kind,'full'));event(c,'device','Computer registered: '+name.strip())
    return id
def pair_code(id):
    code=secrets.token_urlsafe(18)
    with db() as c:
        if c.execute("UPDATE devices SET code=?,expires=? WHERE id=? AND mode='full'",(digest(code),int(time.time())+600,id)).rowcount!=1:raise ValueError('Enable full telemetry first')
        event(c,'pair','Pairing requested')
    return code
def pair(code):
    token=secrets.token_urlsafe(32)
    with db() as c:
        c.execute('BEGIN IMMEDIATE');r=c.execute("SELECT id FROM devices WHERE code=? AND expires>? AND mode='full'",(digest(code),time.time())).fetchone()
        if not r:raise ValueError('Invalid or expired code')
        if c.execute("SELECT count(*) FROM devices WHERE token IS NOT NULL AND id!=?",(r['id'],)).fetchone()[0]>=16:raise ValueError('Agent limit reached')
        c.execute('UPDATE devices SET token=?,code=NULL,expires=NULL WHERE id=?',(digest(token),r['id']));event(c,'pair','Agent enrolled: '+r['id'])
    return {'token':token,'id':r['id']}
def revoke(id):
    with db() as c:c.execute('UPDATE devices SET token=NULL,code=NULL,expires=NULL WHERE id=?',(id,));event(c,'revoke','Agent revoked: '+id)
def clean(d):
    out={'time':int(time.time())}
    for k in ('cpu','ram','gpu','vram','gpuTemp','gpuPower','cpuTemp','diskFree','diskTotal','rx','tx','uptime','fps','frameTime','agentCpu','agentRam','cpuMHz','cpuPower','fanRpm','ramTotal','cpuCores'):
        v=d.get(k);out[k]=v if type(v) in (int,float) and math.isfinite(v) and 0<=v<1e16 and (k not in ('cpu','ram','gpu','vram','agentCpu') or v<=100) else None
    for k in ('gpuName','cpuName','osName','model'):out[k]=str(d.get(k) or '')[:160]
    return out
def ingest(token,d,ip):
    sample=clean(d)
    with db() as c:
        c.execute('BEGIN IMMEDIATE');r=c.execute("SELECT * FROM devices WHERE token=? AND mode='full'",(digest(token),)).fetchone()
        if not r:raise PermissionError()
        import features
        policy=c.execute("SELECT v FROM settings WHERE k='privacy_v3'").fetchone()
        if policy:features.filter_sample(sample,json.loads(policy[0]).get(r['id'],[]))
        if r['last'] and r['sample'] and sample['time']-json.loads(r['sample'])['time']<4:raise BlockingIOError()
        c.execute('UPDATE devices SET sample=?,last=?,ip=? WHERE id=?',(json.dumps(sample),sample['time'],ip if ip_ok(ip) else r['ip'],r['id']))
        metric(c,r['id'],sample)
def metric(c,id,s):
    c.execute('INSERT OR REPLACE INTO metrics VALUES(?,?,?,?,?,?,?,?)',(id,s['time'],s.get('cpu'),s.get('ram'),s.get('gpu'),s.get('temp',s.get('gpuTemp')),s.get('rx'),s.get('tx')))
def history(id,hours):
    hours=max(1,min(24*30,int(hours))); step=10 if hours<=1 else 60 if hours<=24 else 3600
    with db() as c:return [dict(r) for r in c.execute('SELECT (t/?)*? AS time,avg(cpu) cpu,avg(ram) ram,avg(gpu) gpu,avg(temp) temp,avg(rx) rx,avg(tx) tx FROM metrics WHERE id=? AND t>=? GROUP BY time ORDER BY time LIMIT 3000',(step,step,id,int(time.time()-hours*3600)))]
def setting(k,default):
    with db() as c:r=c.execute('SELECT v FROM settings WHERE k=?',(k,)).fetchone();return json.loads(r['v']) if r else default
def set_setting(k,v):
    with db() as c:c.execute('INSERT OR REPLACE INTO settings VALUES(?,?)',(k,json.dumps(v)))
def prune():
    with db() as c:
        # retain minute averages older than 24h (one row/minute per device)
        cutoff=int(time.time()-86400); start=int(time.time()-30*86400)
        c.execute('DELETE FROM metrics WHERE t<?',(start,));c.execute('DELETE FROM network_metrics WHERE t<?',(start,))
        # consolidate remaining old minutes atomically
        c.execute('CREATE TEMP TABLE roll AS SELECT id,(t/60)*60 t,avg(cpu) cpu,avg(ram) ram,avg(gpu) gpu,avg(temp) temp,avg(rx) rx,avg(tx) tx FROM metrics WHERE t<? GROUP BY id,t/60',(cutoff,));c.execute('DELETE FROM metrics WHERE t<?',(cutoff,));c.execute('INSERT OR REPLACE INTO metrics SELECT * FROM roll');c.execute('DELETE FROM events WHERE t<?',(int(time.time()-90*86400),))


def record_network(snapshot):
    t=snapshot.get('time')
    if type(t) is not int or not 0<=time.time()-t<300:return
    def number(v,maximum):return v if type(v) in (int,float) and math.isfinite(v) and 0<=v<=maximum else None
    with db() as conn:
        for r in snapshot.get('devices',[])[:32]:
            if not isinstance(r,dict):continue
            row=conn.execute("SELECT mac FROM devices WHERE id=? AND mode='network'",(r.get('id'),)).fetchone()
            if not row or not row['mac'] or row['mac']!=r.get('mac'):continue
            status=r.get('status')
            if status not in ('Reachable','No reply / unknown','Identity not confirmed'):continue
            measured=status!='Identity not confirmed'
            conn.execute('INSERT OR IGNORE INTO network_metrics VALUES(?,?,?,?,?,?)',(r['id'],t,status,number(r.get('latency'),10000) if measured else None,number(r.get('loss'),100) if measured else None,number(r.get('variation'),10000) if measured else None))

def console_history(id,hours):
    hours=max(1,min(720,int(hours)))
    with db() as conn:
        row=conn.execute("SELECT id,name,ip,mac,last FROM devices WHERE id=? AND mode='network' AND kind='Console'",(id,)).fetchone()
        if not row:raise ValueError('Console not registered for monitoring')
        now=int(time.time())
        samples=[dict(r) for r in conn.execute('SELECT t AS time,status,latency,loss,variation FROM network_metrics WHERE id=? AND t>=? ORDER BY t DESC LIMIT 24000',(id,now-hours*3600))][::-1]
        latest=conn.execute('SELECT t AS time,status,latency,loss,variation FROM network_metrics WHERE id=? ORDER BY t DESC LIMIT 1',(id,)).fetchone()
        # Only credit intervals bounded by successful samples; gaps and sleep are unknown.
        seconds=sum(b['time']-a['time'] for a,b in zip(samples,samples[1:]) if a['status']==b['status']=='Reachable' and 0<b['time']-a['time']<=240)
        valid=[r['latency'] for r in samples if r['latency'] is not None]; losses=[r['loss'] for r in samples if r['loss'] is not None]
        step=120 if hours<=24 else 1800
        bins={}
        for r in samples:
            k=r['time']//step*step; bins.setdefault(k,[]).append(r)
        def avg(rows,key):
            a=[r[key] for r in rows if r[key] is not None];return sum(a)/len(a) if a else None
        return {'device':dict(row),'latest':dict(latest) if latest else None,'hours':hours,'reachableSeconds':seconds,'samples':len(samples),'averageLatency':sum(valid)/len(valid) if valid else None,'averageLoss':sum(losses)/len(losses) if losses else None,'history':[{'time':k,'latency':avg(v,'latency'),'loss':avg(v,'loss'),'variation':avg(v,'variation')} for k,v in sorted(bins.items())]}
