import json
import sqlite3
import threading
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


    def test_legacy_migration_persists(self):
        legacy = [
            {'kind': 'jellyfin', 'label': 'Media', 'url': 'http://media.example.test:8096'},
            {'kind': 'kavita', 'label': 'Books', 'url': 'http://reader.example.test:5000'},
        ]
        with tempfile.TemporaryDirectory() as td, patch.object(core, 'DATA', Path(td)), patch.object(core, 'DB', Path(td) / 'db.sqlite3'):
            core.init()
            core.set_setting(ic.SETTING, legacy)
            first = ic.state()
            self.assertEqual(first['revision'], 0)
            self.assertEqual(len(first['connections']), 2)
            ids = [row['id'] for row in first['connections']]
            self.assertEqual(len(set(ids)), 2)
            for ident in ids:
                self.assertEqual(len(ident), 32)
            stored = self._raw_setting()
            self.assertIsInstance(stored, dict)
            self.assertEqual(set(stored), {'revision', 'connections'})
            self.assertEqual(stored['revision'], 0)
            self.assertEqual([row['id'] for row in stored['connections']], ids)
            second = ic.state()
            self.assertEqual(second['connections'], first['connections'])
            self.assertEqual(self._raw_setting(), stored)

    def test_invalid_ids_and_kind_lock(self):
        row = {'kind': 'kavita', 'label': 'Books', 'url': 'http://reader.example.test:5000'}
        with tempfile.TemporaryDirectory() as td, patch.object(core, 'DATA', Path(td)), patch.object(core, 'DB', Path(td) / 'db.sqlite3'):
            core.init()
            saved = ic.save({'expectedRevision': 0, 'connections': [row]})
            ident = saved['connections'][0]['id']
            before = ic.state()
            invalid = (
                {'expectedRevision': 1, 'connections': [dict(row, id='unknown')]},
                {'expectedRevision': 1, 'connections': [dict(row, id='')]},
                {'expectedRevision': 1, 'connections': [dict(row, id=ident + ident[:4])]},
                {'expectedRevision': 1, 'connections': [dict(row, id=123)]},
                {'expectedRevision': 1, 'connections': [dict(row, id=None)]},
                {'expectedRevision': 1, 'connections': [dict(row, id=ident), dict(row, id=ident, label='Copy', url='http://other.example.test:5000')]},
                {'expectedRevision': 1, 'connections': [dict(saved['connections'][0], kind='jellyfin')]},
            )
            for payload in invalid:
                with self.subTest(payload=payload), self.assertRaises(ValueError):
                    ic.save(payload)
                self.assertEqual(ic.state()['revision'], 1)
                self.assertEqual(ic.state()['connections'], before['connections'])
                self.assertEqual(self._raw_setting()['revision'], 1)

    def test_new_row_omits_id(self):
        existing = {'kind': 'kavita', 'label': 'Books', 'url': 'http://reader.example.test:5000'}
        added = {'kind': 'uptime-kuma', 'label': 'Status', 'url': 'http://status.example.test:3001'}
        with tempfile.TemporaryDirectory() as td, patch.object(core, 'DATA', Path(td)), patch.object(core, 'DB', Path(td) / 'db.sqlite3'):
            core.init()
            first = ic.save({'expectedRevision': 0, 'connections': [existing]})
            ident = first['connections'][0]['id']
            result = ic.save({'expectedRevision': 1, 'connections': [first['connections'][0], added]})
            self.assertEqual(result['revision'], 2)
            self.assertEqual(result['connections'][0]['id'], ident)
            self.assertNotEqual(result['connections'][1]['id'], ident)
            self.assertEqual(len(result['connections'][1]['id']), 32)
            self.assertNotIn('id', added)

    def test_save_rollback_on_invalid_revision(self):
        row = {'kind': 'kavita', 'label': 'Books', 'url': 'http://reader.example.test:5000'}
        with tempfile.TemporaryDirectory() as td, patch.object(core, 'DATA', Path(td)), patch.object(core, 'DB', Path(td) / 'db.sqlite3'):
            core.init()
            saved = ic.save({'expectedRevision': 0, 'connections': [row]})
            before = self._raw_setting()
            for expected in (-1, True, False, 1.0, '1', None):
                with self.subTest(expected=expected), self.assertRaises(ValueError):
                    ic.save({'expectedRevision': expected, 'connections': []})
            self.assertEqual(self._raw_setting(), before)
            self.assertEqual(ic.state()['revision'], 1)
            self.assertEqual(ic.state()['connections'], saved['connections'])

    def test_simultaneous_writers(self):
        for round_number in range(5):
            with self.subTest(round=round_number):
                with tempfile.TemporaryDirectory() as td, patch.object(core, 'DATA', Path(td)), patch.object(core, 'DB', Path(td) / 'db.sqlite3'):
                    core.init()
                    self.assertEqual(ic.state()['revision'], 0)
                    rows = [
                        {'kind': 'kavita', 'label': 'Books A', 'url': 'http://a.example.test:5000'},
                        {'kind': 'kavita', 'label': 'Books B', 'url': 'http://b.example.test:5000'},
                    ]
                    results, errors = [], []
                    barrier = threading.Barrier(2)

                    def write(row):
                        try:
                            barrier.wait(timeout=5)
                            results.append(ic.save({'expectedRevision': 0, 'connections': [row]}))
                        except Exception as exc:
                            errors.append(exc)

                    threads = [threading.Thread(target=write, args=(row,)) for row in rows]
                    for thread in threads:
                        thread.start()
                    for thread in threads:
                        thread.join(timeout=15)
                        self.assertFalse(thread.is_alive())
                    self.assertEqual(len(results), 1, results)
                    self.assertEqual(len(errors), 1, errors)
                    self.assertIsInstance(errors[0], ic.RevisionConflict)
                    winner = results[0]
                    conflict = errors[0].current
                    self.assertEqual(winner['revision'], 1)
                    self.assertEqual(len(winner['connections']), 1)
                    self.assertEqual(set(conflict), {'revision', 'connections', 'catalog'})
                    self.assertEqual(conflict['revision'], 1)
                    self.assertEqual(conflict['connections'], winner['connections'])
                    final = ic.state()
                    self.assertEqual(final['revision'], 1)
                    self.assertEqual(final['connections'], winner['connections'])
                    self.assertEqual(self._raw_setting()['revision'], 1)
                    self.assertEqual(len(self._raw_setting()['connections']), 1)

    def _raw_setting(self):
        connection = sqlite3.connect(core.DB)
        try:
            row = connection.execute('SELECT v FROM settings WHERE k=?', (ic.SETTING,)).fetchone()
        finally:
            connection.close()
        return json.loads(row[0]) if row else None


if __name__ == '__main__':
    unittest.main()
