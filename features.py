"""Local-only V3 extensions. Rules have no command execution or network actions."""
import core as c, time, re, math, os, json, secrets, base64, hashlib, hmac, struct
from pathlib import Path
KEYS={'cpu','ram','gpu','vram','cpuTemp','gpuTemp','temp','diskUsed','agentCpu','fps'}

def rules():return c.setting('rules_v3',[])
def save_rules(d):
    items=d.get('rules'); out=[]; ids=set()
    if not isinstance(items,list) or len(items)>32:raise ValueError('Rules limit')
    valid={'host'}|{r['id'] for r in c.registry() if r['mode']=='full'}
    for r in items:
        if not isinstance(r,dict):raise ValueError()
        i=r.get('id'); label=r.get('name'); threshold=r.get('threshold'); sec=r.get('seconds')
        if not isinstance(i,str) or not re.fullmatch('[a-zA-Z0-9_-]{1,64}',i) or i in ids or not isinstance(label,str) or not 1<=len(label.strip())<=80 or r.get('device') not in valid or r.get('metric') not in KEYS or r.get('op') not in ('above','below') or type(threshold) not in (int,float) or not math.isfinite(threshold) or not 0<=threshold<=100000 or type(sec) is not int or not 10<=sec<=3600 or type(r.get('enabled')) is not bool:raise ValueError('Invalid rule')
        ids.add(i);out.append(dict(id=i,name=label.strip(),device=r['device'],metric=r['metric'],op=r['op'],threshold=threshold,seconds=sec,enabled=r['enabled']))
    c.set_setting('rules_v3',out);return out

class Evaluator:
    def __init__(self):self.state={}
    def tick(self,host,now=None):
        now=int(time.time()) if now is None else now
        samples={'host':host}
        for r in c.registry():
            if r['mode']=='full' and r['paired'] and r['sample']:samples[r['id']]=json.loads(r['sample'])
        active=set()
        for r in rules():
            i=r['id'];active.add(i);s=samples.get(r['device'],{});value=s.get(r['metric']);key=json.dumps(r,sort_keys=True)
            if r['metric']=='diskUsed':
                total=s.get('diskTotal');free=s.get('diskFree')
                if r['device']=='host':total=s.get('ssd',{}).get('total');free=s.get('ssd',{}).get('free')
                value=100*(1-free/total) if isinstance(total,(int,float)) and total>0 and isinstance(free,(int,float)) else None
            fresh=type(s.get('time')) is int and 0<=now-s['time']<=60
            match=r['enabled'] and fresh and type(value) in (int,float) and (value>r['threshold'] if r['op']=='above' else value<r['threshold'])
            if not match:self.state.pop(i,None);continue
            old=self.state.get(i)
            if not old or old[0]!=key or now-old[3]>30:old=[key,now,False,now]
            old[3]=now
            if not old[2] and now-old[1]>=r['seconds']:
                with c.db() as db:c.event(db,'automation',f"{r['name']}: {r['metric']} {r['op']} {r['threshold']} ({value:.2f})")
                old[2]=True
            self.state[i]=old
        for i in set(self.state)-active:self.state.pop(i,None)

def privacy():return c.setting('privacy_v3',{})
GROUPS={'hardware':('cpuName','gpuName','osName','model','ramTotal','cpuCores'), 'gaming':('fps','frameTime','gpu','vram','gpuTemp','gpuPower'), 'network':('rx','tx'), 'storage':('diskFree','diskTotal')}
def save_privacy(d):
    i=d.get('id');groups=d.get('groups')
    if i not in {r['id'] for r in c.registry() if r['mode']=='full'} or not isinstance(groups,list) or any(x not in GROUPS for x in groups) or len(groups)!=len(set(groups)):raise ValueError()
    with c.db() as db:
        row=db.execute("SELECT v FROM settings WHERE k='privacy_v3'").fetchone();p=json.loads(row[0]) if row else {};p[i]=groups
        db.execute("INSERT OR REPLACE INTO settings VALUES('privacy_v3',?)",(json.dumps(p),))
        # Clear excluded fields from the current sample, historical rows are explicitly retained.
        row=db.execute('SELECT sample FROM devices WHERE id=?',(i,)).fetchone()
        if row and row[0]:
            s=json.loads(row[0]);filter_sample(s,groups);db.execute('UPDATE devices SET sample=? WHERE id=?',(json.dumps(s),i))
    return p

def filter_sample(s,groups):
    for group in groups:
        for key in GROUPS.get(group,()):s[key]=None
    return s

def history_many(ids,hours):
    valid={'host'}|{r['id'] for r in c.registry() if r['mode']=='full'}
    if not 1<=len(ids)<=4 or len(set(ids))!=len(ids) or any(i not in valid for i in ids):raise ValueError()
    return {i:c.history(i,hours) for i in ids}

def milestones(host):
    rows=c.registry();out=[{'name':'First Contact','earned':any(r['paired'] for r in rows),'detail':'At least one paired computer'}, {'name':'Fleet Commander','earned':sum(r['paired'] for r in rows)>=10,'detail':'Ten paired computers'}, {'name':'Always Online','earned':(host.get('uptime') or 0)>=30*86400,'detail':'Host uptime of 30 days'}, {'name':'Architect','earned':c.setting('dashboard_v3',None) is not None,'detail':'Saved a custom dashboard'}]
    return out

# RFC 6238 TOTP, authenticator enrollment and one-use recovery codes.
def totp(secret,step):
    key=base64.b32decode(secret);h=hmac.new(key,struct.pack('>Q',step),hashlib.sha1).digest();offset=h[-1]&15
    return f'{(struct.unpack(">I",h[offset:offset+4])[0]&0x7fffffff)%1000000:06d}'
def match_totp(secret,code,now=None):
    if not isinstance(code,str) or not re.fullmatch('[0-9]{6}',code):return None
    t=int(time.time() if now is None else now)//30
    return next((x for x in (t,t-1,t+1) if hmac.compare_digest(totp(secret,x),code)),None)
def auth_state():return c.setting('totp_v3',{})
def start_totp():return base64.b32encode(secrets.token_bytes(20)).decode()
def enable_totp(secret,code):
    step=match_totp(secret,code)
    if step is None:raise ValueError('Invalid code')
    recovery=[secrets.token_hex(10) for _ in range(8)]
    with c.db() as db:
        db.execute('BEGIN IMMEDIATE');row=db.execute("SELECT v FROM settings WHERE k='totp_v3'").fetchone()
        if row and json.loads(row[0]).get('secret'):raise ValueError('Already enabled')
        db.execute("INSERT OR REPLACE INTO settings VALUES('totp_v3',?)",(json.dumps({'secret':secret,'last':step,'recovery':[c.digest(x) for x in recovery]}),))
    return recovery

def verify_totp(code,disable=False):
    with c.db() as db:
        db.execute('BEGIN IMMEDIATE');row=db.execute("SELECT v FROM settings WHERE k='totp_v3'").fetchone();s=json.loads(row[0]) if row else {}
        if not s.get('secret'):return not disable
        if not isinstance(code,str) or len(code)>100:return False
        step=match_totp(s['secret'],code);hashed=c.digest(code)
        if step is not None and step>s.get('last',-1):s['last']=step
        elif hashed in s.get('recovery',[]):s['recovery'].remove(hashed)
        else:return False
        db.execute("INSERT OR REPLACE INTO settings VALUES('totp_v3',?)",(json.dumps({} if disable else s),));return True

def lifecycle_enabled():return False  # No privileged browser-to-host bridge in the portable edition.
def request_uninstall(mode):
    if not lifecycle_enabled() or mode not in ('keep','purge'):raise ValueError('Host opt-in required')
    # Fixed data-only message, consumed by independent host service. No shell or paths.
    p=c.DATA/'uninstall-request.json';tmp=c.DATA/('request-'+secrets.token_hex(8));
    try:
        fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w') as f:json.dump({'mode':mode,'time':int(time.time())},f)
        os.replace(tmp,p)
    finally:tmp.unlink(missing_ok=True)
