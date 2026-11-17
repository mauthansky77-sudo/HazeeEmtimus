import http.client
import json
import os
import secrets
import tempfile
import threading
import unittest

os.environ['ADMIN_TOKEN'] = secrets.token_urlsafe(32)
import server


class APITest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        server.ADMIN_TOKEN = secrets.token_urlsafe(32)
        cls.tmp = tempfile.TemporaryDirectory()
        server.DB_PATH = os.path.join(cls.tmp.name, 'test.sqlite3')
        server.initialize()
        cls.http = server.ThreadingHTTPServer(('127.0.0.1', 0), server.Handler)
        cls.thread = threading.Thread(target=cls.http.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.http.shutdown()
        cls.http.server_close()
        cls.thread.join()
        cls.tmp.cleanup()

    def request(self, method, path, body=None, auth=True, csrf=True):
        headers = {'Content-Type': 'application/json'}
        if auth and getattr(self, 'cookie', None):
            headers['Cookie'] = self.cookie
        if csrf and getattr(self, 'csrf', None):
            headers['X-CSRF-Token'] = self.csrf
        conn = http.client.HTTPConnection(*self.http.server_address)
        conn.request(method, path, None if body is None else json.dumps(body), headers)
        response = conn.getresponse()
        status, cookie = response.status, response.getheader('Set-Cookie')
        value = json.loads(response.read())
        conn.close()
        return status, value, cookie

    def login(self):
        status, _, cookie = self.request('POST', '/api/login', {'token': server.ADMIN_TOKEN})
        self.assertEqual(status, 200)
        self.cookie = cookie.split(';')[0]
        self.assertIn('HttpOnly', cookie)
        self.assertIn('SameSite=Strict', cookie)
        self.csrf = self.request('GET', '/api/session')[1]['csrf']

    def test_authorization_and_csrf(self):
        self.assertEqual(self.request('GET', '/api/keys', auth=False)[0], 401)
        self.assertEqual(self.request('POST', '/api/login', {'token': 'wrong'})[0], 401)
        self.login()
        self.assertEqual(self.request('POST', '/api/keys', {'label': 'A', 'days': 7, 'max_devices': 1}, csrf=False)[0], 403)
        self.assertEqual(self.request('POST', '/api/keys', {'label': 'A', 'days': -1, 'max_devices': 1})[0], 400)

    def test_key_lifecycle_device_binding_and_revocation(self):
        self.login()
        status, key, _ = self.request('POST', '/api/keys', {'label': 'Test', 'days': 7, 'max_devices': 1})
        self.assertEqual(status, 201)
        verify = lambda device: self.request('POST', '/api/v1/licenses/verify', {'key': key['key'], 'device_id': device}, auth=False)
        self.assertTrue(verify('device-a')[1]['valid'])
        self.assertTrue(verify('device-a')[1]['valid'])
        self.assertEqual(verify('device-b')[1]['error'], 'device_limit')
        rows = self.request('GET', '/api/keys')[1]['keys']
        self.assertNotIn(key['key'], json.dumps(rows))
        with server.connect() as db:
            self.assertNotIn(key['key'], str([tuple(row) for row in db.execute('SELECT * FROM licenses')]))
        self.assertEqual(self.request('POST', '/api/revoke', {'id': key['id']})[0], 200)
        self.assertEqual(verify('device-a')[0], 403)
        self.request('POST', '/api/logout', {})
        self.assertEqual(self.request('GET', '/api/keys')[0], 401)

    def test_expired_key(self):
        self.login()
        key = self.request('POST', '/api/keys', {'label': 'Expired', 'days': 1, 'max_devices': 1})[1]
        with server.connect() as db:
            db.execute('UPDATE licenses SET expires=0 WHERE id=?', (key['id'],))
        self.assertEqual(self.request('POST', '/api/v1/licenses/verify', {'key': key['key'], 'device_id': 'x'}, auth=False)[0], 403)


if __name__ == '__main__':
    unittest.main()
