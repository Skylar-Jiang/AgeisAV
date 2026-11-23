"""Loopback-only, same-origin sessions for the local static workbench."""
import hashlib
import hmac
import ipaddress
import os
from pathlib import Path
import secrets
import time

from fastapi.responses import JSONResponse

COOKIE = 'aegisav_local_session'
SESSION_SECONDS = 8 * 60 * 60


def load_access_token(path: Path) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        pass
    else:
        with os.fdopen(descriptor, 'w', encoding='ascii') as stream:
            stream.write(secrets.token_urlsafe(32))
    token = path.read_text(encoding='ascii').strip()
    if len(token) < 32:
        raise ValueError('Local access key must contain at least 32 characters')
    return token


class LocalAccess:
    def __init__(self, token):
        if len(token) < 32:
            raise ValueError('Local access key is too short')
        self.token = token.encode()

    def bearer(self, request):
        scheme, _, value = request.headers.get('authorization', '').partition(' ')
        return scheme.lower() == 'bearer' and hmac.compare_digest(value.encode(), self.token)

    def session(self):
        payload = str(int(time.time())) + '.' + secrets.token_urlsafe(16)
        signature = hmac.new(self.token, payload.encode(), hashlib.sha256).hexdigest()
        return payload + '.' + signature

    def valid_session(self, request):
        value = request.cookies.get(COOKIE, '')
        try:
            issued, nonce, signature = value.split('.')
            age = time.time() - int(issued)
            expected = hmac.new(self.token, (issued+'.'+nonce).encode(), hashlib.sha256).hexdigest()
            return 0 <= age <= SESSION_SECONDS and hmac.compare_digest(signature.encode(), expected.encode())
        except (ValueError, TypeError):
            return False

    async def guard(self, request, call_next):
        try:
            local = request.client is not None and ipaddress.ip_address(request.client.host).is_loopback
        except ValueError:
            local = False
        if not local or request.url.hostname not in {'127.0.0.1', 'localhost', '::1'}:
            return JSONResponse({'detail': 'Loopback access required'}, status_code=403)
        origin = request.headers.get('origin')
        if origin is not None and origin != str(request.base_url).rstrip('/'):
            return JSONResponse({'detail': 'Same-origin access required'}, status_code=403)
        protected = request.url.path.startswith('/v1/') or request.url.path in {'/docs', '/redoc', '/openapi.json'}
        bearer = self.bearer(request)
        if protected:
            if not bearer and not self.valid_session(request):
                return JSONResponse({'detail': 'Local authentication required'}, status_code=401,
                                    headers={'WWW-Authenticate': 'Bearer'})
            if request.method not in {'GET', 'HEAD', 'OPTIONS'} and not bearer and origin is None:
                return JSONResponse({'detail': 'Origin required for cookie-authenticated writes'}, status_code=403)
        response = await call_next(request)
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
            "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        if protected:
            response.headers['Cache-Control'] = 'no-store'
        return response
