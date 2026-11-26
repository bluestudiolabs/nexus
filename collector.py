#!/usr/bin/env python3
"""Host-only, fixed-command telemetry. Never accepts network input."""
import json, subprocess, time, os, tempfile, re, ipaddress
from pathlib import Path
ROOT=Path(os.environ['NEXUS_RUNTIME']); OUT=ROOT/'telemetry'
LAN=ipaddress.ip_network(os.environ.get('NEXUS_LAN','127.0.0.0/8')); IFACE=os.environ.get('NEXUS_INTERFACE',''); GATEWAY=os.environ.get('NEXUS_GATEWAY','')
DISCOVERY=os.environ.get('NEXUS_DISCOVERY')=='1'
if DISCOVERY and (LAN.version!=4 or LAN.num_addresses>4096 or not IFACE):raise SystemExit('Discovery requires an explicit IPv4 subnet of /20 or smaller and interface')
def run(args, timeout=12):
    try:
        p=subprocess.run(args,capture_output=True,text=True,timeout=timeout,env={**os.environ,'LC_ALL':'C'},stdin=subprocess.DEVNULL)
        return p.returncode,p.stdout
    except (OSError,subprocess.TimeoutExpired): return None,''
def jrun(args):
    rc,s=run(args)
    try:return json.loads(s)
    except ValueError:return None
def lines(args):
    rc,s=run(args); return s.splitlines() if rc==0 else None
def main():
    d={'time':int(time.time())}
    rows=lines(['/usr/bin/docker','stats','--no-stream','--format','{{json .}}'])
    d['containers']=None if rows is None else [{k:r.get(k) for k in ('Name','CPUPerc','MemUsage','MemPerc','NetIO','BlockIO','PIDs')} for r in map(json.loads,rows)]
    states=lines(['/usr/bin/docker','ps','-a','--format','{{json .}}'])
    d['containerStates']=None if states is None else [{k:r.get(k) for k in ('Names','Status')} for r in map(json.loads,states)]
    d['smart']=[]
    for dev in (os.environ.get('NEXUS_SMART_DEVICES','').split()):
        s=jrun(['/usr/sbin/smartctl','-a','-j','-n','standby,0',dev]) or {}
        attrs={a['id']:a.get('raw',{}).get('value') for a in s.get('ata_smart_attributes',{}).get('table',[])}
        d['smart'].append({'device':dev,'model':s.get('model_name'),'passed':s.get('smart_status',{}).get('passed'),'temperature':s.get('temperature',{}).get('current'),'hours':s.get('power_on_time',{}).get('hours'),'reallocated':attrs.get(5),'pending':attrs.get(197),'uncorrectable':attrs.get(198)})
    neigh=jrun(['ip','-j','neigh','show','dev',IFACE]) if DISCOVERY else []; d['neighbors']=None if neigh is None else [{'ip':r.get('dst'),'state':r.get('state')} for r in neigh if r.get('lladdr') and 'FAILED' not in r.get('state',[])]
    failed=lines(['/usr/bin/systemctl','--failed','--no-legend','--plain']); d['failed']=None if failed is None else [x.split()[0] for x in failed if x.split()]
    apt=lines(['/usr/bin/apt','list','--upgradable']); d['updates']=None if apt is None else sum('/' in x for x in apt if not x.startswith('Listing'))
    d['rebootRequired']=Path('/run/reboot-required').exists()
    rc,s=run(['/usr/bin/journalctl','-k','--since','1 hour ago','--no-pager','-o','cat','-q']); d['firewallBlocks']=s.count('[UFW BLOCK]') if rc==0 else None
    rc,s=run(['/usr/bin/journalctl','-u','ssh.service','--since','1 hour ago','--no-pager','-o','cat','-q']); d['sshFailures']=sum(bool(re.search(r'Failed password|Failed publickey|Invalid user|maximum authentication attempts',x,re.I)) for x in s.splitlines()) if rc==0 else None
    d['services']={n:run(['/usr/bin/systemctl','is-active',n])[1].strip() or 'unknown' for n in os.environ.get('NEXUS_SERVICES','').split()}
    d['mount']=None
    d['observed']=[]
    known={}
    for r in neigh or []:
        if r.get('lladdr') and r.get('dst') and not set(r.get('state',[])) & {'FAILED','INCOMPLETE','STALE'}:known[r['dst']]=r['lladdr'].lower()
    # Optional bounded ARP discovery, never packet capture. Only the existing LAN.
    if DISCOVERY and Path('/usr/sbin/arp-scan').exists():
        rc,out=run(['/usr/sbin/arp-scan','--interface='+IFACE,'--retry=1',str(LAN)],timeout=35)
        for line in out.splitlines():
            m=re.match(r'^(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]{17})\s',line)
            if m:known[m[1]]=m[2].lower()
    d['observed']=[{'ip':i,'mac':m} for i,m in known.items() if ':' not in i and ipaddress.IPv4Address(i) in LAN]
    d['devices']=[]
    try:
        p=ROOT/'data/probes.json'
        # Refuse symlinks, bound size, untrusted input is never a shell command.
        fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as f:devices=json.loads(f.read(32768))
    except (OSError,ValueError):devices=[]
    from concurrent.futures import ThreadPoolExecutor
    def probe(item):
        try:
            ip=ipaddress.IPv4Address(item['ip'])
            if ip not in LAN:return None
            mac=item.get('mac')
            matches=[addr for addr,value in known.items() if value==mac]
            if not mac or len(matches)!=1:return {'id':str(item['id'])[:50],'ip':str(ip),'mac':mac,'status':'Identity not confirmed','latency':None,'loss':None,'variation':None}
            ip=ipaddress.IPv4Address(matches[0])
            if ip not in LAN:return None
            rc,output=run(['/usr/bin/ping','-n','-c','2','-W','1',str(ip)],timeout=5)
            match=re.search(r'= ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)',output)
            loss=re.search(r'([\d.]+)% packet loss',output)
            return {'id':str(item['id'])[:50],'ip':str(ip),'mac':mac,'status':'Reachable' if rc==0 else 'No reply / unknown','latency':float(match[2]) if match else None,'loss':float(loss[1]) if loss else None,'variation':float(match[4]) if match else None}
        except (ValueError,KeyError,TypeError):return None
    with ThreadPoolExecutor(max_workers=4) as pool:d['devices']=[v for v in pool.map(probe,devices[:32] if isinstance(devices,list) else []) if v]
    # Gateway and external tests are separate. Internet tests opt-in via root marker.
    d['internet']={}
    for name,ip in ([('gateway',GATEWAY)] if GATEWAY else [])+([('internet','1.1.1.1')] if os.environ.get('NEXUS_INTERNET_PROBE')=='1' else []):
        rc,out=run(['/usr/bin/ping','-n','-c','3','-W','1',ip],timeout=7)
        m=re.search(r'= ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)',out);loss=re.search(r'([\d.]+)% packet loss',out)
        d['internet'][name]={'latency':float(m[2]) if m else None,'jitter':float(m[4]) if m else None,'loss':float(loss[1]) if loss else None}
    OUT.mkdir(mode=0o755,parents=True,exist_ok=True)
    fd,tmp=tempfile.mkstemp(dir=OUT); os.fchmod(fd,0o640); os.fchown(fd,OUT.stat().st_uid,OUT.stat().st_gid) if os.geteuid()==0 else None
    with os.fdopen(fd,'w') as f: json.dump(d,f)
    os.replace(tmp,OUT/'snapshot.json')
if __name__=='__main__':main()
