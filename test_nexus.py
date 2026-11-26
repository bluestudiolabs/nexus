import unittest,tempfile,os,time,json,ssl,threading,urllib.request,urllib.error,subprocess,hashlib
from pathlib import Path
import core as c,secure as web
def seed_fixture():
    import ipaddress
    c.LAN=ipaddress.ip_network('192.0.2.0/24')
    with c.db() as conn:
        conn.executemany('INSERT INTO devices(id,name,kind,mode) VALUES(?,?,?,?)', [('fixture-pc','Example PC','Windows','full'),('fixture-console','Example console','Console','network'),('fixture-tablet','Example tablet','Tablet','known'),('fixture-router','Example router','Router','known')])
class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();p=Path(self.tmp.name);c.DATA=p/'data';c.DB=c.DATA/'nexus.sqlite3';c.init();seed_fixture();web.AUTH=p/'auth.json';salt=b'x'*16;web.AUTH.write_text(json.dumps({'salt':salt.hex(),'hash':hashlib.scrypt(b'testpassword-long',salt=salt,n=32768,r=8,p=1,maxmem=64*1024**2).hex()}));web.sessions.clear();web.attempts.clear()
    def tearDown(self):self.tmp.cleanup()
    def test_registry(self):
        c.observe([{'ip':'192.0.2.55','mac':'02:00:00:00:00:01'}]);r=next(x for x in c.registry() if x['mode']=='pending');c.configure(dict(id=r['id'],name='Example console',kind='Console',mode='network',merge='fixture-console'));c.observe([{'ip':'192.0.2.99','mac':'02:00:00:00:00:01'}]);c.observe([{'ip':'192.0.2.99','mac':'02:00:00:00:00:01'}]);self.assertEqual(next(x for x in c.registry() if x['id']=='fixture-console')['ip'],'192.0.2.99');self.assertEqual(len(c.registry()),4)
    def test_register(self):
        id=c.register({'name':'New laptop','kind':'Windows'})
        self.assertTrue(any(r['id']==id and r['mode']=='full' for r in c.registry()))
        with self.assertRaises(ValueError):c.register({'name':'New laptop','kind':'Windows'})
        with self.assertRaises(ValueError):c.register({'name':'Other','kind':'Router'})
        token=c.pair(c.pair_code(id))['token'];c.ingest(token,{'cpu':22},'192.0.2.80')
        self.assertEqual(c.history(id,1)[0]['cpu'],22)
    def test_agent(self):
        code=c.pair_code('fixture-pc');a=c.pair(code)
        with self.assertRaises(ValueError):c.pair(code)
        c.ingest(a['token'],{'cpu':50,'ram':33,'gpu':101},'192.0.2.58');self.assertEqual(c.history('fixture-pc',1)[0]['cpu'],50);self.assertIsNone(c.history('fixture-pc',1)[0]['gpu']);c.revoke('fixture-pc')
        with self.assertRaises(PermissionError):c.ingest(a['token'],{},'192.0.2.58')
    def test_prune(self):
        t=int(time.time()-90000)
        with c.db() as db:
            for i in (0,1):c.metric(db,'host',{'time':t+i,'cpu':50})
        c.prune();self.assertEqual(c.history('host',168)[0]['cpu'],50)
    def test_console_history(self):
        mac='02:00:00:00:00:01';c.observe([{'ip':'192.0.2.55','mac':mac}]);r=next(x for x in c.registry() if x['mode']=='pending');c.configure(dict(id=r['id'],name='Example console',kind='Console',mode='network',merge='fixture-console'))
        now=int(time.time());base={'id':'fixture-console','mac':mac,'status':'Reachable','latency':6.0,'loss':0,'variation':1.2}
        for t in [now-250,now-125]:c.record_network({'time':t,'devices':[base,dict(base,mac='02:00:00:00:00:02')]})
        c.record_network({'time':now-125,'devices':[base]})
        c.record_network({'time':now,'devices':[dict(base,status='Identity not confirmed',latency=999,loss=100)]})
        d=c.console_history('fixture-console',24);self.assertEqual(d['samples'],3);self.assertEqual(d['reachableSeconds'],125);self.assertEqual(d['averageLatency'],6);self.assertEqual(d['averageLoss'],0);self.assertIsNone(d['latest']['latency']);self.assertIsNone(d['latest']['loss']);self.assertEqual(d['latest']['status'],'Identity not confirmed')
        with self.assertRaises(ValueError):c.console_history('fixture-pc',24)
        with c.db() as conn:conn.execute('INSERT INTO network_metrics VALUES(?,?,?,?,?,?)',('fixture-console',now-31*86400,'Reachable',1,0,0))
        c.prune()
        with c.db() as conn:self.assertEqual(conn.execute('SELECT count(*) FROM network_metrics').fetchone()[0],3)
    def test_agent_health(self):
        token=c.pair(c.pair_code('fixture-pc'))['token'];c.ingest(token,{'agentCpu':.034,'agentRam':160*1048576,'cpuMHz':3000,'cpuTemp':54,'cpuPower':35,'fanRpm':900},'192.0.2.58');s=json.loads(next(r for r in c.registry() if r['id']=='fixture-pc')['sample']);self.assertEqual(s['agentCpu'],.034);self.assertEqual(s['agentRam'],160*1048576);self.assertEqual(s['fanRpm'],900);self.assertIsNone(c.clean({'agentCpu':101})['agentCpu'])
    def test_https(self):
        p=Path(self.tmp.name);subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost','-keyout',str(p/'key'),'-out',str(p/'cert')],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(p/'cert',p/'key');srv=web.BoundedServer(('127.0.0.1',0),web.Handler);srv.socket=ctx.wrap_socket(srv.socket,server_side=True,do_handshake_on_connect=False);web.HOST='localhost:'+str(srv.server_port);web.ORIGIN='https://'+web.HOST;threading.Thread(target=srv.serve_forever,daemon=True).start();client=ssl.create_default_context(cafile=str(p/'cert'))
        def req(path,body=None,cookie=None,origin=None):
            h={};
            if cookie:h['Cookie']=cookie
            if origin:h['Origin']=origin
            if body is not None:h['Content-Type']='application/json'
            try:return urllib.request.urlopen(urllib.request.Request(web.ORIGIN+path,json.dumps(body).encode() if body is not None else None,h),context=client,timeout=5)
            except urllib.error.HTTPError as e:return e
        try:
            self.assertEqual(req('/api/v3/rules').code,401);self.assertEqual(req('/api/v3/security').code,401);self.assertEqual(req('/api/dashboard').code,401);self.assertEqual(req('/api/overview').code,401);self.assertEqual(req('/api/registry').code,401);self.assertEqual(req('/api/console?id=fixture-console').code,401);self.assertEqual(req('/?utm_source=test').code,200);self.assertEqual(req('/api/login',{'password':'wrong'},origin=web.ORIGIN).code,401);self.assertEqual(req('/api/login',{'password':'testpassword-long'},origin='https://evil.example').code,403);r=req('/api/login',{'password':'testpassword-long'},origin=web.ORIGIN);self.assertEqual(r.code,200);cookie=r.headers['Set-Cookie'].split(';')[0];self.assertEqual(req('/api/dashboard',cookie=cookie).code,200);self.assertEqual(req('/api/overview',cookie=cookie).code,200);self.assertEqual(req('/api/dashboard',{},cookie=cookie,origin=web.ORIGIN).code,400);self.assertEqual(req('/api/dashboard',web.dash.default(),cookie=cookie,origin=web.ORIGIN).code,200);self.assertEqual(req('/api/dashboard',web.dash.default(),cookie=cookie,origin='https://evil.example').code,403);self.assertEqual(req('/api/registry',cookie=cookie).code,200);self.assertEqual(req('/api/console?id=fixture-console',cookie=cookie).code,200);self.assertEqual(req('/api/device',{},cookie=cookie,origin='https://evil.example').code,403);self.assertEqual(req('/api/v3/rules',cookie=cookie).code,200);self.assertEqual(req('/api/v3/history?id=host&id=fixture-pc',cookie=cookie).code,200);self.assertEqual(req('/api/v3/uninstall',{'password':'wrong'},cookie=cookie,origin=web.ORIGIN).code,403);start=req('/api/v3/totp/start',{'password':'testpassword-long'},cookie=cookie,origin=web.ORIGIN);secret=json.load(start)['secret'];code=web.f3.totp(secret,int(time.time())//30);enabled=req('/api/v3/totp/enable',{'password':'testpassword-long','otp':code},cookie=cookie,origin=web.ORIGIN);self.assertEqual(enabled.code,200);codes=json.load(enabled)['recovery'];self.assertEqual(req('/api/logout',{},cookie=cookie,origin=web.ORIGIN).code,200);self.assertEqual(req('/api/login',{'password':'testpassword-long'},origin=web.ORIGIN).code,401);r=req('/api/login',{'password':'testpassword-long','otp':codes[0]},origin=web.ORIGIN);self.assertEqual(r.code,200);cookie=r.headers['Set-Cookie'].split(';')[0];self.assertEqual(req('/api/v3/totp/disable',{'password':'testpassword-long','otp':codes[1]},cookie=cookie,origin=web.ORIGIN).code,200);self.assertEqual(req('/api/logout',{},cookie=cookie,origin=web.ORIGIN).code,200);self.assertEqual(req('/api/registry',cookie=cookie).code,401)
        finally:srv.shutdown();srv.server_close()
if __name__=='__main__':unittest.main(verbosity=2)
