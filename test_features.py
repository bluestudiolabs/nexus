import unittest,tempfile,time,json,importlib.util,os
from pathlib import Path
from unittest.mock import patch
import core as c,features as f
def seed_fixture():
    import ipaddress
    c.LAN=ipaddress.ip_network('192.0.2.0/24')
    with c.db() as conn:
        conn.executemany('INSERT INTO devices(id,name,kind,mode) VALUES(?,?,?,?)', [('fixture-pc','Example PC','Windows','full'),('fixture-console','Example console','Console','network'),('fixture-tablet','Example tablet','Tablet','known'),('fixture-router','Example router','Router','known')])
class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();c.DATA=Path(self.tmp.name);c.DB=c.DATA/'nexus.sqlite3';c.init();seed_fixture()
    def tearDown(self):self.tmp.cleanup()
    def rule(self):return dict(id='test',name='Hot CPU',device='host',metric='cpu',op='above',threshold=80,seconds=20,enabled=True)
    def events(self):
        with c.db() as db:return db.execute("SELECT count(*) FROM events WHERE kind='automation'").fetchone()[0]
    def test_rule_debounce_and_stale(self):
        f.save_rules({'rules':[self.rule()]});r=f.Evaluator();t=int(time.time())
        for i in (0,10,20,30):r.tick({'time':t+i,'cpu':90},t+i)
        self.assertEqual(self.events(),1)
        r.tick({'time':t,'cpu':99},t+100);r.tick({'time':t+110,'cpu':91},t+110);r.tick({'time':t+130,'cpu':91},t+130);self.assertEqual(self.events(),2)
    def test_rules_validation(self):
        for change in ({'metric':'shell'},{'device':'missing'},{'threshold':float('nan')},{'seconds':0},{'enabled':1}):
            with self.assertRaises(ValueError):f.save_rules({'rules':[self.rule()|change]})
        with self.assertRaises(ValueError):f.save_rules({'rules':[self.rule(),self.rule()]})
    def test_privacy(self):
        t=c.pair(c.pair_code('fixture-pc'))['token'];c.ingest(t,{'gpu':50,'cpu':20,'rx':10},'192.0.2.58');f.save_privacy({'id':'fixture-pc','groups':['gaming','network']});r=next(x for x in c.registry() if x['id']=='fixture-pc');self.assertIsNone(json.loads(r['sample'])['gpu']);self.assertEqual(c.history('fixture-pc',1)[0]['gpu'],50)
        with c.db() as db:db.execute("UPDATE devices SET last=NULL WHERE id='fixture-pc'")
        c.ingest(t,{'gpu':70,'cpu':25,'rx':123},'192.0.2.58');r=next(x for x in c.registry() if x['id']=='fixture-pc');self.assertIsNone(json.loads(r['sample'])['rx']);self.assertEqual(json.loads(r['sample'])['cpu'],25)
    def test_totp_and_recovery(self):
        s=f.start_totp();now=1800000000;step=now//30
        with patch('features.time.time',return_value=now):
            recovery=f.enable_totp(s,f.totp(s,step));self.assertEqual(len(recovery),8);self.assertFalse(f.verify_totp(f.totp(s,step)));self.assertTrue(f.verify_totp(recovery[0]));self.assertFalse(f.verify_totp(recovery[0]));self.assertNotIn(recovery[1],json.dumps(f.auth_state()))
        with patch('features.time.time',return_value=now+30):
            self.assertTrue(f.verify_totp(f.totp(s,step+1)));self.assertFalse(f.verify_totp(f.totp(s,step+1)));self.assertTrue(f.verify_totp(recovery[1],disable=True));self.assertFalse(f.auth_state())
    def test_totp_reference(self):
        import base64
        self.assertEqual(f.totp(base64.b32encode(b'12345678901234567890').decode(),59//30),'287082')
    def test_history_bounds(self):
        self.assertEqual(set(f.history_many(['host','fixture-pc'],1)),{'host','fixture-pc'})
        for x in ([],['unknown'],['host','host']):
            with self.assertRaises(ValueError):f.history_many(x,1)
    def test_uninstall_disabled(self):
        with patch('features.lifecycle_enabled',return_value=False):
            with self.assertRaises(ValueError):f.request_uninstall('purge')
        with patch('features.lifecycle_enabled',return_value=True):
            with self.assertRaises(ValueError):f.request_uninstall('../../')
            f.request_uninstall('keep');d=json.loads((c.DATA/'uninstall-request.json').read_text());self.assertEqual(set(d),{'mode','time'});self.assertEqual(d['mode'],'keep')

if __name__=='__main__':unittest.main()
