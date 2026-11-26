#!/usr/bin/env python3
import os,json,time,ssl,urllib.request,urllib.error,getpass,shutil
from pathlib import Path
base='' ;root=Path.home()/'.config/nexus-agent';root.mkdir(parents=True,mode=0o700,exist_ok=True);root.chmod(0o700)
if (root/'server.txt').exists():base=(root/'server.txt').read_text().strip()
from urllib.parse import urlsplit
u=urlsplit(base)
if u.scheme!='https' or not u.hostname or u.username or u.password or u.path not in ('','/') or u.query or u.fragment:raise SystemExit('Invalid HTTPS origin')
base=base.rstrip('/')
ctx=ssl.create_default_context(cafile=str(root/'ca.crt') if (root/'ca.crt').exists() else None)
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ctx),NoRedirect())
def send(path,data,token=None):
    h={'Content-Type':'application/json'}
    if token:h['Authorization']='Bearer '+token
    with opener.open(urllib.request.Request(base+path,json.dumps(data).encode(),h),timeout=10) as r:return json.load(r)
p=root/'token';os.umask(0o077)
import sys
if '--run' in sys.argv and not p.exists():raise SystemExit('Pair through setup first')
if not p.exists():p.write_text(send('/api/pair',{'code':getpass.getpass('Pairing code: ')})['token'])
p.chmod(0o600);token=p.read_text().strip();prev=None
if '--pair-only' in sys.argv:raise SystemExit(0)
while True:
    try:
        a=list(map(int,Path('/proc/stat').read_text().splitlines()[0].split()[1:9]));t=sum(a);idle=a[3]+a[4];m={x.split(':')[0]:int(x.split()[1]) for x in Path('/proc/meminfo').read_text().splitlines() if x.startswith(('MemTotal:','MemAvailable:'))};disk=shutil.disk_usage('/');now=time.monotonic();rx=tx=0
        for l in Path('/proc/net/dev').read_text().splitlines()[2:]:
            n,v=l.split(':');v=v.split()
            if n.strip()!='lo':rx+=int(v[0]);tx+=int(v[8])
        d={'ram':100*(1-m['MemAvailable']/m['MemTotal']),'diskFree':disk.free,'diskTotal':disk.total,'uptime':float(Path('/proc/uptime').read_text().split()[0])}
        if prev and t>prev[0]:d.update(cpu=max(0,min(100,100*(1-(idle-prev[1])/(t-prev[0])))),rx=max(0,(rx-prev[2])/(now-prev[4])),tx=max(0,(tx-prev[3])/(now-prev[4])))
        prev=(t,idle,rx,tx,now);send('/api/ingest',d,token);print('Sample accepted',flush=True)
    except urllib.error.HTTPError as e:
        if e.code==401:raise SystemExit('Credential revoked; delete local token and pair again')
        print('HTTP',e.code,flush=True)
    except (OSError,ValueError) as e:print('Unavailable:',type(e).__name__,flush=True)
    time.sleep(10)
