"""V3 dashboard preferences: validated, declarative, no executable extensions."""
import re, time, json
import core as c
METRICS = {'cpu','ram','gpu','vram','cpuTemp','gpuTemp','temp','rx','tx','uptime','diskFree','diskTotal','agentCpu','agentRam','cpuMHz','gpuPower','fanRpm','fps','frameTime'}
TYPES = {'pulse','fleet','metric','services','storage','alerts','clock','network','passport','history'}
THEMES = {'original':('#39e4ff','#090e17'),'galaxy':('#b28aff','#170d29'),'emerald':('#48e9ac','#0a2018'),'crimson':('#ff7189','#250d13'),'solar':('#ffba62','#251d14'),'mono':('#d2d9e2','#151515')}

def default():
    def w(i,t,size='medium',**kw):return dict(id=i,type=t,size=size,**kw)
    return {'active':'daily','mode':'advanced','theme':{'accent':'#39e4ff','background':'#090e17','opacity':90,'radius':12,'density':'comfortable','effect':'aurora'},'profiles':[{'id':'daily','name':'Daily overview','widgets':[w('pulse','pulse','wide'),w('fleet','fleet','wide'),w('storage','storage'),w('services','services'),w('alerts','alerts'),w('clock','clock')]},{'id':'gaming','name':'Gaming','widgets':[w('fleet','fleet','wide'),w('history','history','wide'),w('network','network')]},{'id':'server','name':'Server administration','widgets':[w('pulse','pulse','wide'),w('passport','passport'),w('storage','storage'),w('services','services'),w('alerts','alerts')]}]}

def validate(d):
    def identifier(x): return isinstance(x,str) and bool(re.fullmatch(r'[a-zA-Z0-9_-]{1,64}',x))
    def text(x): return isinstance(x,str) and 1<=len(x.strip())<=80
    def color(x): return isinstance(x,str) and bool(re.fullmatch(r'#[0-9a-fA-F]{6}',x))
    if not isinstance(d,dict): raise ValueError('Invalid dashboard')
    theme=d.get('theme',{}); profiles=d.get('profiles'); mode=d.get('mode')
    if not isinstance(theme,dict) or not color(theme.get('accent')) or not color(theme.get('background')) or type(theme.get('opacity')) is not int or not 50<=theme['opacity']<=100 or type(theme.get('radius')) is not int or not 0<=theme['radius']<=24 or theme.get('density') not in ('compact','comfortable','spacious') or theme.get('effect') not in ('solid','aurora','grid','stars'): raise ValueError('Invalid theme')
    if mode not in ('easy','advanced','einstein') or not isinstance(profiles,list) or not 1<=len(profiles)<=8:raise ValueError('Invalid profiles')
    out=[]; ids=set()
    for p in profiles:
        if not isinstance(p,dict) or not identifier(p.get('id')) or p['id'] in ids or not text(p.get('name')) or not isinstance(p.get('widgets'),list) or len(p['widgets'])>24:raise ValueError('Invalid profile')
        ids.add(p['id']); widgets=[]; wi=set()
        for w in p['widgets']:
            if not isinstance(w,dict) or not identifier(w.get('id')) or w['id'] in wi or w.get('type') not in TYPES or w.get('size') not in ('small','medium','wide'):raise ValueError('Invalid widget')
            wi.add(w['id']); a={k:w[k] for k in ('id','type','size')}
            if w['type']=='metric':
                if not identifier(w.get('device')) or w.get('metric') not in METRICS or w.get('view') not in ('number','bar','chart'):raise ValueError('Invalid metric widget')
                a.update({k:w[k] for k in ('device','metric','view')})
            widgets.append(a)
        out.append({'id':p['id'],'name':p['name'].strip(),'widgets':widgets})
    if d.get('active') not in ids:raise ValueError('Invalid active profile')
    return {'active':d['active'],'mode':mode,'theme':{k:theme[k] for k in ('accent','background','opacity','radius','density','effect')},'profiles':out}

def load():return c.setting('dashboard_v3',default())
def save(d):
    d=validate(d);c.set_setting('dashboard_v3',d);return d

def overview(current,kuma,snapshot,insights):
    now=int(time.time()); host=dict(current); rows=[]
    for r in c.registry():
        if r['mode']=='ignored':continue
        a=json.loads(r['sample']) if r['sample'] and r['paired'] and r['mode']=='full' else None
        rows.append({k:r[k] for k in ('id','name','kind','mode','ip','last','paired')}|{'sample':a,'fresh':bool(a and 0<=now-a.get('time',0)<=60)})
    return {'time':now,'hostName':__import__('os').getenv('NEXUS_DISPLAY_NAME','NEXUS Host'),'host':host,'hostFresh':bool(host and 0<=now-host.get('time',0)<=20),'devices':rows,'services':kuma,'collectorTime':snapshot.get('time'),'smart':snapshot.get('smart',[]),'insights':insights,'gateway':snapshot.get('internet',{}).get('gateway'),'probes':snapshot.get('devices',[])}
