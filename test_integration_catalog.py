import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch

import core
import integration_center as ic


class IntegrationCatalogTests(unittest.TestCase):
    def test_catalog_plans(self):
        for kind, item in ic.CATALOG.items():
            with self.subTest(kind=kind):
                result = ic.plan({'kind': kind, 'library': '/srv/media/library' if item['library'] else ''})
                service = result['compose']['services'][kind]
                self.assertEqual(service['image'], item['image'])
                self.assertEqual(service['ports'][0]['host_ip'], '127.0.0.1')
                self.assertEqual(service['ports'][0]['target'], item['port'])
                self.assertNotIn('privileged', service)
                self.assertNotIn('network_mode', service)
                self.assertNotIn('container_name', service)
                self.assertNotIn('docker.sock', str(service))
                if item['library']:
                    self.assertTrue(service['volumes'][-1]['read_only'])
                    self.assertFalse(service['volumes'][-1]['bind']['create_host_path'])

    def test_independent_projects(self):
        first = ic.plan({'kind': 'uptime-kuma', 'bind': '192.168.1.50', 'port': 9000, 'restart': False})
        second = ic.plan({'kind': 'uptime-kuma'})
        self.assertNotEqual(first['compose']['name'], second['compose']['name'])
        self.assertEqual(first['url'], 'http://192.168.1.50:9000')
        self.assertEqual(first['compose']['services']['uptime-kuma']['restart'], 'no')

    def test_invalid_plans(self):
        base = {'kind': 'jellyfin', 'library': '/srv/media/library'}
        for change in ({'kind': 'arbitrary'}, {'bind': '0.0.0.0'}, {'bind': '8.8.8.8'},
                       {'bind': '::1'}, {'bind': 1}, {'port': True}, {'port': 80}, {'port': 65536},
                       {'restart': 'yes'}, {'library': '/'}, {'library': '/etc'},
                       {'library': '/home/user'}, {'library': '/srv/../etc'},
                       {'library': '/srv/$SECRET'}, {'library': '/home/user/.ssh'},
                       {'library': '/srv/media\nx'}, {'library': '/srv/media:rw'}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                ic.plan(base | change)

    def test_untrusted_fields_ignored(self):
        result = ic.plan({'kind': 'uptime-kuma', 'image': 'untrusted:latest', 'privileged': True,
                          'volumes': ['/:/host'], 'command': 'anything'})
        service = result['compose']['services']['uptime-kuma']
        self.assertEqual(service['image'], ic.CATALOG['uptime-kuma']['image'])
        self.assertNotIn('privileged', service)
        self.assertNotIn('command', service)
        self.assertEqual(service['volumes'], [{'type': 'volume', 'source': 'data', 'target': '/app/data'}])

    def test_connection_validation(self):
        good = {'kind': 'jellyfin', 'label': 'Media', 'url': 'https://media.example.test:8096/'}
        self.assertEqual(ic.normalize_connections({'connections': [good]}), [good])
        for url in ('javascript:alert(1)', 'file:///etc/passwd', 'http://user:pass@host',
                    'https://host/?token=abc', 'https://host/#token', 'https://host:99999',
                    'https://host\\@other', 'https://host\n'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                ic.normalize_connections({'connections': [good | {'url': url}]})
        with self.assertRaises(ValueError):
            ic.normalize_connections({'connections': [good, good]})

    def test_connection_persistence(self):
        row = {'kind': 'kavita', 'label': 'Books', 'url': 'http://reader.example.test:5000'}
        with tempfile.TemporaryDirectory() as td, patch.object(core, 'DATA', Path(td)), patch.object(core, 'DB', Path(td)/'db.sqlite3'):
            core.init()
            core.set_setting(ic.SETTING, [row])
            initial = ic.state()
            self.assertEqual(initial['revision'], 0)
            saved = initial['connections'][0]
            self.assertEqual(len(saved['id']), 32)
            self.assertEqual(ic.state()['connections'], [saved])
            result = ic.save({'expectedRevision': 0, 'connections': [saved]})
            self.assertEqual(result['revision'], 1)
            with self.assertRaises(ic.RevisionConflict) as err:
                ic.save({'expectedRevision': 0, 'connections': []})
            self.assertEqual(err.exception.current['connections'], [saved])
            with self.assertRaises(ValueError):
                ic.save({'expectedRevision': 1, 'connections': [dict(saved, id='unknown')]})
            self.assertEqual(ic.state()['revision'], 1)
            ic.save({'expectedRevision': 1, 'connections': []})
            self.assertEqual(ic.state()['connections'], [])
            added = ic.save({'expectedRevision': 2, 'connections': [row]})
            self.assertNotEqual(added['connections'][0]['id'], saved['id'])


if __name__ == '__main__':
    unittest.main()
