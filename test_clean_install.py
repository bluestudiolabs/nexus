import unittest,tempfile,os,sys,subprocess,ssl,json,urllib.request,urllib.error,time,socket,ipaddress
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace
import core,manage

class CleanInstall(unittest.TestCase):
    def test_fresh_empty_and_explicit_lan(self):
        with tempfile.TemporaryDirectory() as td,patch.object(core,'DATA',Path(td)),patch.object(core,'DB',Path(td)/'nexus.sqlite3'),patch.object(core,'LAN',ipaddress.ip_network('192.0.2.0/24')):
            core.init();self.assertEqual(core.registry(),[])
            core.observe([{'ip':'198.51.100.7','mac':'02:00:00:00:00:09'}]);self.assertEqual(core.registry(),[])
            core.observe([{'ip':'192.0.2.7','mac':'02:00:00:00:00:09'}]);self.assertEqual(core.registry()[0]['mode'],'pending')
    def test_setup_and_real_server(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td);r=base/'.nexus'
            with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
            args=SimpleNamespace(address='127.0.0.1',port=port,lan='127.0.0.0/8',interface='lo',gateway=None,discovery=False,prepare_only=True)
            with patch.multiple(manage,BASE=base,R=r,ENV=r/'config.env',MARK=r/'installation.json'),patch('manage.getpass.getpass',return_value='local-test-password-123'),patch('manage.os.getuid',return_value=1000):
                manage.setup(args);cfg=manage.read_config();self.assertEqual(cfg['KUMA_URL'],'');self.assertEqual(cfg['NEXUS_DISCOVERY'],'0')
                with self.assertRaises(ValueError):manage.setup(args)
            env={**os.environ,**cfg,'NEXUS_AUTH':str(r/'auth/password.json'),'NEXUS_DATA':str(r/'data'),'NEXUS_TLS_CERT':str(r/'tls/server.crt'),'NEXUS_TLS_KEY':str(r/'tls/server.key'),'NEXUS_TELEMETRY':str(r/'telemetry'),'NEXUS_LISTEN':'127.0.0.1','NEXUS_INTERNAL_PORT':str(port),'NEXUS_PROC':'/proc','NEXUS_SYS':'/sys','NEXUS_NETDEV':'/proc/net/dev','NEXUS_SYSTEM_METER':str(r/'meter'),'NEXUS_EXTRA_METER':'/unconfigured'}
            p=subprocess.Popen([sys.executable,'-B','secure.py'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            origin='https://'+cfg['NEXUS_HOST'];ctx=ssl.create_default_context(cafile=str(r/'ca/ca.crt'))
            def req(path,data=None,cookie=None,agent=None):
                h={};
                if cookie:h['Cookie']=cookie
                if data is not None:
                    h['Content-Type']='application/json'
                    if agent is None:h['Origin']=origin
                    elif agent:h['Authorization']='Bearer '+agent
                with urllib.request.urlopen(urllib.request.Request(origin+path,None if data is None else json.dumps(data).encode(),h),context=ctx,timeout=4) as res:return res.read(),res.headers
            try:
                for _ in range(40):
                    try:req('/');break
                    except OSError:time.sleep(.1)
                else:self.fail('TLS startup failed')
                with self.assertRaises(urllib.error.HTTPError) as e:req('/api/registry')
                self.assertEqual(e.exception.code,401)
                _,h=req('/api/login',{'password':'local-test-password-123'});cookie=h['Set-Cookie'].split(';')[0]
                self.assertEqual(json.loads(req('/api/registry',cookie=cookie)[0]),[])
                ident=json.loads(req('/api/register',{'name':'Example computer','kind':'Linux'},cookie)[0])['id']
                code=json.loads(req('/api/pair-code',{'id':ident},cookie)[0])['code']
                token=json.loads(req('/api/pair',{'code':code},agent='')[0])['token']
                self.assertTrue(json.loads(req('/api/ingest',{'cpu':35},agent=token)[0])['ok'])
                rows=json.loads(req('/api/registry',cookie=cookie)[0]);self.assertEqual(len(rows),1);self.assertEqual(json.loads(rows[0]['sample'])['cpu'],35)
            finally:p.terminate();p.wait(timeout=10)
if __name__=='__main__':unittest.main()
