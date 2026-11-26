import hashlib
import http.client
import json
import ssl
import subprocess
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

import core as c
import secure as web


class IntegrationApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        c.DATA = root / 'data'
        c.DB = c.DATA / 'nexus.sqlite3'
        c.init()
        web.AUTH = root / 'auth.json'
        salt = b'x' * 16
        web.AUTH.write_text(json.dumps({
            'salt': salt.hex(),
            'hash': hashlib.scrypt(b'testpassword-long', salt=salt, n=32768, r=8, p=1, maxmem=64 * 1024 ** 2).hex(),
        }))
        web.sessions.clear()
        web.attempts.clear()
        subprocess.run(
            ['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
             '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
             '-keyout', str(root / 'key'), '-out', str(root / 'cert')],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(root / 'cert', root / 'key')
        self.server = web.BoundedServer(('127.0.0.1', 0), web.Handler)
        self.server.socket = ctx.wrap_socket(self.server.socket, server_side=True, do_handshake_on_connect=False)
        web.HOST = 'localhost:' + str(self.server.server_port)
        web.ORIGIN = 'https://' + web.HOST
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.client = ssl.create_default_context(cafile=str(root / 'cert'))

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.tmp.cleanup()

    def request(self, path, body=None, cookie=None, origin=None, method=None):
        headers = {}
        if cookie:
            headers['Cookie'] = cookie
        if origin:
            headers['Origin'] = origin
        if body is not None:
            headers['Content-Type'] = 'application/json'
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(web.ORIGIN + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, context=self.client, timeout=5) as response:
                return response.status, json.loads(response.read()), response.headers
        except urllib.error.HTTPError as error:
            raw = error.read()
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                payload = raw.decode()
            return error.code, payload, error.headers

    def sign_in(self):
        status, payload, headers = self.request('/api/login', {'password': 'testpassword-long'}, origin=web.ORIGIN)
        self.assertEqual(status, 200)
        self.assertTrue(payload.get('ok'))
        return headers['Set-Cookie'].split(';')[0]

    def test_owner_auth_and_origin(self):
        status, payload, _ = self.request('/api/integrations')
        self.assertEqual(status, 401)
        self.assertEqual(payload, {'error': 'Sign in required'})
        status, payload, _ = self.request('/api/integrations', {'expectedRevision': 0, 'connections': []})
        self.assertEqual(status, 403)
        self.assertEqual(payload, {'error': 'Invalid origin'})
        status, payload, _ = self.request(
            '/api/integrations', {'expectedRevision': 0, 'connections': []}, origin='https://evil.example')
        self.assertEqual(status, 403)
        self.assertEqual(payload, {'error': 'Invalid origin'})
        status, payload, _ = self.request(
            '/api/integrations', {'expectedRevision': 0, 'connections': []}, origin=web.ORIGIN)
        self.assertEqual(status, 401)
        self.assertEqual(payload, {'error': 'Sign in required'})
        status, payload, _ = self.request('/api/integrations/plan', {'kind': 'uptime-kuma'}, origin=web.ORIGIN)
        self.assertEqual(status, 401)

        connection = http.client.HTTPSConnection('localhost', self.server.server_port, context=self.client, timeout=5)
        try:
            connection.request('GET', '/api/integrations', headers={'Host': 'evil.example'})
            response = connection.getresponse()
            body = json.loads(response.read())
            self.assertEqual(response.status, 403)
            self.assertEqual(body, {'error': 'Invalid host'})
        finally:
            connection.close()

        cookie = self.sign_in()
        status, payload, _ = self.request('/api/integrations', cookie=cookie)
        self.assertEqual(status, 200)
        self.assertEqual(set(payload), {'catalog', 'connections', 'revision'})
        self.assertEqual(payload['revision'], 0)
        self.assertEqual(payload['connections'], [])
        self.assertEqual(set(payload['catalog']), set(web.integrations.CATALOG))
        status, payload, _ = self.request(
            '/api/integrations', {'expectedRevision': 0, 'connections': []}, cookie=cookie, origin='https://evil.example')
        self.assertEqual(status, 403)

    def test_stale_conflict_body(self):
        cookie = self.sign_in()
        row = {'kind': 'kavita', 'label': 'Books', 'url': 'http://reader.example.test:5000'}
        status, first, _ = self.request(
            '/api/integrations', {'expectedRevision': 0, 'connections': [row]}, cookie=cookie, origin=web.ORIGIN)
        self.assertEqual(status, 200)
        self.assertEqual(set(first), {'catalog', 'connections', 'revision'})
        self.assertEqual(first['revision'], 1)
        self.assertEqual(len(first['connections'][0]['id']), 32)
        status, conflict, _ = self.request(
            '/api/integrations', {'expectedRevision': 0, 'connections': []}, cookie=cookie, origin=web.ORIGIN)
        self.assertEqual(status, 409)
        self.assertEqual(set(conflict), {'error', 'catalog', 'connections', 'revision'})
        self.assertEqual(conflict['error'], 'Registry changed')
        self.assertEqual(conflict['revision'], 1)
        self.assertEqual(conflict['connections'], first['connections'])
        self.assertEqual(conflict['catalog'], first['catalog'])
        status, current, _ = self.request('/api/integrations', cookie=cookie)
        self.assertEqual(status, 200)
        self.assertEqual(current['revision'], 1)
        self.assertEqual(current['connections'], first['connections'])

    def test_plan_validation(self):
        cookie = self.sign_in()
        status, payload, _ = self.request(
            '/api/integrations/plan',
            {'kind': 'uptime-kuma', 'image': 'untrusted:latest', 'privileged': True},
            cookie=cookie, origin=web.ORIGIN,
        )
        self.assertEqual(status, 200)
        service = payload['compose']['services']['uptime-kuma']
        self.assertEqual(service['image'], web.integrations.CATALOG['uptime-kuma']['image'])
        self.assertNotIn('privileged', service)
        self.assertEqual(service['ports'][0]['host_ip'], '127.0.0.1')
        self.assertTrue(any('Plan only' in warning for warning in payload['warnings']))
        for change in (
            {'kind': 'arbitrary'},
            {'kind': 'jellyfin', 'library': '/etc'},
            {'kind': 'uptime-kuma', 'bind': '0.0.0.0'},
            {'kind': 'uptime-kuma', 'port': 80},
        ):
            with self.subTest(change=change):
                status, payload, _ = self.request('/api/integrations/plan', change, cookie=cookie, origin=web.ORIGIN)
                self.assertEqual(status, 400)
                self.assertEqual(payload, {'error': 'Invalid request or unavailable'})


if __name__ == '__main__':
    unittest.main()
