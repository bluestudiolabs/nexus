import unittest,tempfile,time,json
from pathlib import Path
import core as c,dashboard as d
def seed_fixture():
    import ipaddress
    c.LAN=ipaddress.ip_network('192.0.2.0/24')
    with c.db() as conn:
        conn.executemany('INSERT INTO devices(id,name,kind,mode) VALUES(?,?,?,?)', [('fixture-pc','Example PC','Windows','full'),('fixture-console','Example console','Console','network'),('fixture-tablet','Example tablet','Tablet','known'),('fixture-router','Example router','Router','known')])
class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();c.DATA=Path(self.tmp.name);c.DB=c.DATA/'nexus.sqlite3';c.init();seed_fixture()
    def tearDown(self): self.tmp.cleanup()
    def test_persist_and_preserve(self):
        t=c.pair(c.pair_code('fixture-pc'))['token'];c.ingest(t,{'cpu':12},'192.0.2.58');v=d.default();v['theme']['accent']='#abcd12';v['profiles'][0]['widgets'].append({'id':'metric1','type':'metric','size':'small','device':'fixture-pc','metric':'cpu','view':'chart'});self.assertEqual(d.save(v),d.load());self.assertEqual(c.history('fixture-pc',1)[0]['cpu'],12);self.assertTrue(next(r for r in c.registry() if r['id']=='fixture-pc')['paired'])
    def test_validation(self):
        for key,value in [('accent','url(https://example.org)'),('radius',True),('effect','script')]:
            v=d.default();v['theme'][key]=value
            with self.assertRaises(ValueError):d.save(v)
        v=d.default();v['profiles'][0]['widgets'].append(v['profiles'][0]['widgets'][0])
        with self.assertRaises(ValueError):d.save(v)
        v=d.default();v['profiles'][0]['widgets'].append({'id':'x','type':'shell','size':'wide'})
        with self.assertRaises(ValueError):d.save(v)
    def test_fleet_state(self):
        t=c.pair(c.pair_code('fixture-pc'))['token'];c.ingest(t,{'gpu':42},'192.0.2.58');c.register({'name':'Laptop test','kind':'Linux'});now=int(time.time());v=d.overview({'time':now,'cpu':4},{},{},[]);self.assertTrue(v['hostFresh']);a=next(r for r in v['devices'] if r['id']=='fixture-pc');self.assertTrue(a['fresh']);self.assertEqual(a['sample']['gpu'],42);self.assertNotIn('token',a);self.assertFalse(next(r for r in v['devices'] if r['name']=='Laptop test')['fresh']);c.revoke('fixture-pc');a=next(r for r in d.overview({}, {}, {}, [])['devices'] if r['id']=='fixture-pc');self.assertIsNone(a['sample']);self.assertFalse(a['fresh'])
if __name__=='__main__':unittest.main()
