#!/usr/bin/env python3
"""Local, unprivileged lifecycle utility. Never modifies another Compose project."""
import argparse, getpass, hashlib, ipaddress, json, os, re, secrets, shutil, sqlite3, subprocess, sys, tarfile, time
from pathlib import Path
BASE=Path(__file__).resolve().parent
R=BASE/'.nexus'
ENV=R/'config.env'
MARK=R/'installation.json'

def run(*args, **kw):return subprocess.run(args,check=True,**kw)
def read_config():
    if R.is_symlink() or MARK.is_symlink() or ENV.is_symlink():raise ValueError('Unsafe runtime path')
    m=json.loads(MARK.read_text()); project=m['project']
    if not re.fullmatch(r'nexus-[0-9a-f]{12}',project):raise ValueError('Invalid installation marker')
    cfg=dict(line.split('=',1) for line in ENV.read_text().splitlines() if line and not line.startswith('#'))
    if cfg['COMPOSE_PROJECT_NAME']!=project:raise ValueError('Installation identity mismatch')
    return cfg

def compose(*args):
    cfg=read_config();run('docker','compose','--project-directory',str(BASE),'--env-file',str(ENV),'-p',cfg['COMPOSE_PROJECT_NAME'],'-f',str(BASE/'compose.yaml'),*args,env={k:v for k,v in os.environ.items() if not k.startswith(('NEXUS_','COMPOSE_','KUMA_'))})

def setup(args):
    if os.getuid()==0:raise ValueError('Run as a normal user with Docker access, not root')
    if R.exists() or R.is_symlink():raise ValueError('Runtime already exists; use start or repair, never overwrite existing credentials')
    address=ipaddress.IPv4Address(args.address or input('Server IPv4 address [127.0.0.1]: ').strip() or '127.0.0.1')
    allowed=[ipaddress.ip_network(n) for n in ('127.0.0.0/8','10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')]
    if not any(address in n for n in allowed):raise ValueError('Use loopback or RFC1918 IPv4; public binding is not supported')
    port=args.port
    if not 1024<=port<=65535:raise ValueError('Choose port 1024–65535')
    lan=ipaddress.IPv4Network(args.lan or f'{address}/32',strict=False)
    if not any(lan.subnet_of(n) for n in allowed) or address not in lan:raise ValueError('LAN must contain server address and remain private')
    if args.discovery and (not args.interface or lan.num_addresses>4096):raise ValueError('Discovery requires explicit interface and subnet of /20 or smaller')
    if args.interface and not re.fullmatch(r'[a-zA-Z0-9_.:-]{1,15}',args.interface):raise ValueError('Invalid interface')
    if args.gateway and ipaddress.IPv4Address(args.gateway) not in lan:raise ValueError('Gateway must be inside LAN')
    if not args.interface:
        try:
            data=json.loads(subprocess.check_output(['ip','-j','addr'],text=True));args.interface=next(x['ifname'] for x in data if any(a.get('local')==str(address) for a in x.get('addr_info',[])))
        except (OSError,subprocess.SubprocessError,ValueError,StopIteration):args.interface=''
    p=getpass.getpass('Owner password (14+ characters): ')
    if len(p)<14 or len(p)>256 or p!=getpass.getpass('Confirm password: '):raise ValueError('Password invalid or mismatch')
    os.umask(0o077);R.mkdir(mode=0o700)
    try:
        for name in ('auth','tls','ca','data','telemetry','meter'): (R/name).mkdir(mode=0o700)
        salt=secrets.token_bytes(16);h=hashlib.scrypt(p.encode(),salt=salt,n=32768,r=8,p=1,maxmem=64*1024**2)
        (R/'auth/password.json').write_text(json.dumps({'salt':salt.hex(),'hash':h.hex()}));del p
        run('openssl','req','-x509','-newkey','rsa:3072','-nodes','-sha256','-days','3650','-subj','/CN=NEXUS Local CA','-addext','basicConstraints=critical,CA:TRUE,pathlen:0','-addext','keyUsage=critical,keyCertSign,cRLSign','-keyout',str(R/'ca/ca.key'),'-out',str(R/'ca/ca.crt'),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        run('openssl','req','-new','-newkey','rsa:2048','-nodes','-subj',f'/CN={address}','-keyout',str(R/'tls/server.key'),'-out',str(R/'ca/server.csr'),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        (R/'ca/extensions').write_text(f'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:{address}\n')
        run('openssl','x509','-req','-in',str(R/'ca/server.csr'),'-CA',str(R/'ca/ca.crt'),'-CAkey',str(R/'ca/ca.key'),'-CAcreateserial','-days','397','-sha256','-extfile',str(R/'ca/extensions'),'-out',str(R/'tls/server.crt'),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        run('openssl','verify','-CAfile',str(R/'ca/ca.crt'),'-verify_ip',str(address),str(R/'tls/server.crt'))
        project='nexus-'+secrets.token_hex(6)
        cfg={'COMPOSE_PROJECT_NAME':project,'NEXUS_BIND':str(address),'NEXUS_PORT':str(port),'NEXUS_HOST':f'{address}:{port}','NEXUS_LAN':str(lan),'NEXUS_INTERFACE':args.interface,'NEXUS_GATEWAY':args.gateway or '', 'NEXUS_DISCOVERY':str(int(args.discovery)),'NEXUS_INTERNET_PROBE':'0','NEXUS_UID':str(os.getuid()),'NEXUS_GID':str(os.getgid()),'KUMA_URL':'','KUMA_SLUG':'','NEXUS_SMART_DEVICES':'','NEXUS_SERVICES':''}
        ENV.write_text(''.join(f'{k}={v}\n' for k,v in cfg.items()));MARK.write_text(json.dumps({'project':project,'schema':1}))
    except BaseException:
        shutil.rmtree(R);raise
    print('Server:', 'https://'+cfg['NEXUS_HOST']);print('Public CA:',R/'ca/ca.crt');run('openssl','x509','-in',str(R/'ca/ca.crt'),'-noout','-fingerprint','-sha256')
    if not args.prepare_only:compose('up','-d','--build')
    else:print('Configuration prepared; no containers started.')

def collect():
    cfg=read_config();env={**os.environ,**cfg,'NEXUS_RUNTIME':str(R)};run(sys.executable,str(BASE/'collector.py'),env=env)

def collector_service(enable):
    cfg=read_config(); name=cfg['COMPOSE_PROJECT_NAME']+'-collector'; directory=Path.home()/'.config/systemd/user'; service=directory/(name+'.service'); timer=directory/(name+'.timer')
    if enable:
        if os.getuid()==0:raise ValueError('Use your normal user')
        # systemd quoted paths, percent and dollar escaping
        def quote(s):return '"'+str(s).replace('\\','\\\\').replace('"','\\"').replace('%','%%').replace('$','$$')+'"'
        if '\n' in str(BASE) or '\r' in str(BASE):raise ValueError('Invalid install directory')
        directory.mkdir(parents=True,exist_ok=True)
        service.write_text('[Unit]\nDescription=NEXUS optional host collector\n[Service]\nType=oneshot\nExecStart='+quote(sys.executable)+' '+quote(BASE/'manage.py')+' collect\nNoNewPrivileges=yes\nTimeoutStartSec=180\n')
        timer.write_text('[Unit]\nDescription=NEXUS collector schedule\n[Timer]\nOnBootSec=30s\nOnUnitInactiveSec=120s\n[Install]\nWantedBy=timers.target\n')
        run('systemctl','--user','daemon-reload');run('systemctl','--user','enable','--now',name+'.timer')
    elif service.exists() or timer.exists():
        run('systemctl','--user','disable','--now',name+'.timer');run('systemctl','--user','stop',name+'.service');service.unlink(missing_ok=True);timer.unlink(missing_ok=True);run('systemctl','--user','daemon-reload')

def backup():
    read_config();dest=BASE/('nexus-backup-'+time.strftime('%Y%m%d-%H%M%S')+'-'+secrets.token_hex(3)+'.tar.gz')
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        db=R/'data/nexus.sqlite3';snap=Path(td)/'nexus.sqlite3'
        if db.exists():
            with sqlite3.connect(f'{db.as_uri()}?mode=ro',uri=True) as a,sqlite3.connect(snap) as b:a.backup(b)
        fd=os.open(dest,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        with os.fdopen(fd,'wb') as stream,tarfile.open(fileobj=stream,mode='w:gz') as tar:
            for name in ('auth','tls','ca','config.env','installation.json'):tar.add(R/name,arcname=name)
            if snap.exists():tar.add(snap,arcname='data/nexus.sqlite3')
    print('Private backup (includes credentials and CA key):',dest)

def uninstall(args):
    cfg=read_config();print('Target Compose project:',cfg['COMPOSE_PROJECT_NAME']);print('Runtime:',R);print('Data:', 'DELETE' if args.purge else 'KEEP');print('Source checkout, other containers, shared dependencies and external backups are preserved.')
    if args.dry_run:return
    if not args.purge and not args.keep_data:raise ValueError('Select --keep-data or --purge')
    if args.purge and input('Type DELETE NEXUS to permanently remove local data: ')!='DELETE NEXUS':raise ValueError('Cancelled')
    collector_service(False)
    compose('down','--rmi','local')
    if args.purge:shutil.rmtree(R)
    print('Removed server containers. Remove client agents separately.')

def main():
    p=argparse.ArgumentParser(description=__doc__);s=p.add_subparsers(dest='action',required=True)
    a=s.add_parser('setup');a.add_argument('--address');a.add_argument('--port',type=int,default=3010);a.add_argument('--lan');a.add_argument('--interface',default='');a.add_argument('--gateway');a.add_argument('--discovery',action='store_true');a.add_argument('--prepare-only',action='store_true')
    for name in ('start','stop','status','doctor','repair','backup','collect','collector-enable','collector-disable'):s.add_parser(name)
    a=s.add_parser('uninstall');g=a.add_mutually_exclusive_group();g.add_argument('--keep-data',action='store_true');g.add_argument('--purge',action='store_true');a.add_argument('--dry-run',action='store_true')
    args=p.parse_args()
    if args.action=='setup':setup(args)
    elif args.action=='collect':collect()
    elif args.action=='collector-enable':collector_service(True)
    elif args.action=='collector-disable':collector_service(False)
    elif args.action=='backup':backup()
    elif args.action=='uninstall':uninstall(args)
    elif args.action=='doctor':
        cfg=read_config();print('Installation marker OK');run('openssl','verify','-CAfile',str(R/'ca/ca.crt'),'-verify_ip',cfg['NEXUS_BIND'],str(R/'tls/server.crt'));compose('config','--quiet');compose('ps');run('curl','--fail','--max-time','10','--cacert',str(R/'ca/ca.crt'),'https://'+cfg['NEXUS_HOST']+'/', '-o','/dev/null')
    else:compose(*{'start':('up','-d'),'stop':('stop',),'status':('ps',),'repair':('up','-d','--build','--force-recreate')}[args.action])
if __name__=='__main__':
    try:main()
    except (ValueError,OSError,KeyError,subprocess.SubprocessError) as e:sys.exit('NEXUS: '+str(e))
