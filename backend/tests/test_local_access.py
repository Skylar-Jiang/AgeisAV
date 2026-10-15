from fastapi.testclient import TestClient

from aegisav.api import create_app


class Scanner:
    def scan(self, data):
        raise AssertionError('unauthorized request reached scanner')


def test_local_session_rejects_unauthorized_cross_origin_and_rebinding(tmp_path):
    token = 'local-test-access-' * 4
    frontend = tmp_path / 'ui'
    frontend.mkdir()
    (frontend / 'index.html').write_text('<h1>Local workbench</h1>')
    with TestClient(create_app(Scanner(), access_token=token, frontend_dir=frontend),
                    base_url='http://127.0.0.1:3418', client=('127.0.0.1', 40000)) as client:
        assert client.get('/').status_code == 200
        assert client.get('/v1/tasks').status_code == 401
        assert client.get('/openapi.json').status_code == 401
        assert client.post('/v1/session', headers={'Authorization': 'Bearer wrong'}).status_code == 401
        assert client.post('/v1/session', headers={'Authorization': 'Bearer '+token,
                                                  'Origin': 'https://untrusted.example'}).status_code == 403
        assert client.get('/v1/tasks', headers={'Host': 'rebind.example',
                                               'Authorization': 'Bearer '+token}).status_code == 403
        response = client.post('/v1/session', headers={'Authorization': 'Bearer '+token,
                                                      'Origin': 'http://127.0.0.1:3418'})
        assert response.status_code == 200
        assert token not in response.text and token not in response.headers['set-cookie']
        assert 'HttpOnly' in response.headers['set-cookie'] and 'SameSite=strict' in response.headers['set-cookie']
        assert client.get('/v1/tasks').status_code == 200
        assert client.post('/v1/tasks', json={'files': []}).status_code == 403  # cookie writes require Origin
        assert client.post('/v1/tasks', json={'files': []},
                           headers={'Origin': 'http://127.0.0.1:3418'}).status_code == 422
        assert client.delete('/v1/session', headers={'Origin': 'http://127.0.0.1:3418'}).status_code == 200
        assert client.get('/v1/tasks').status_code == 401


def test_bearer_cli_access_and_non_loopback_peer_rejection():
    token = 'local-test-access-' * 4
    with TestClient(create_app(Scanner(), access_token=token), base_url='http://127.0.0.1',
                    client=('127.0.0.1', 1234)) as client:
        assert client.get('/v1/tasks', headers={'Authorization': 'Bearer '+token}).status_code == 200
    with TestClient(create_app(Scanner(), access_token=token), base_url='http://127.0.0.1',
                    client=('192.0.2.1', 1234)) as client:
        assert client.get('/v1/tasks', headers={'Authorization': 'Bearer '+token}).status_code == 403


def test_session_tampering_expiry_and_key_file_reuse(tmp_path, monkeypatch):
    from aegisav.local_access import LocalAccess, load_access_token
    from starlette.requests import Request
    key = tmp_path / 'local.key'
    token = load_access_token(key)
    assert load_access_token(key) == token and len(token) >= 32
    access = LocalAccess(token)
    monkeypatch.setattr('aegisav.local_access.time.time', lambda: 100000)
    value = access.session()
    def request(cookie):
        return Request({'type':'http','headers':[(b'cookie', ('aegisav_local_session='+cookie).encode())]})
    assert access.valid_session(request(value))
    assert not access.valid_session(request(value+'x'))
    monkeypatch.setattr('aegisav.local_access.time.time', lambda: 100000 + 8*3600 + 1)
    assert not access.valid_session(request(value))
