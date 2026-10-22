import hashlib
import os
import re
import threading
import time
from base64 import b64encode
from urllib.parse import urlparse


def _decode_bytes(val):
    if isinstance(val, bytes):
        try:
            return val.decode('utf-8')
        except UnicodeDecodeError:
            return val.decode('latin1')
    return val


def parse_dict_header(value):
    result = {}
    for item in re.findall(r'(\w+)=(?:"([^"]*)"|([^,\s]*))', value):
        result[item[0]] = item[1] if item[1] != '' else item[2]
    return result


def _basic_auth_str(username, password):
    if isinstance(username, str):
        username = username.encode('latin1')
    if isinstance(password, str):
        password = password.encode('latin1')
    return 'Basic ' + b64encode(b':'.join((username, password))).strip().decode('ascii')


class AuthBase:
    def __call__(self, r):
        raise NotImplementedError('Auth hooks must be callable.')


class HTTPBasicAuth(AuthBase):
    def __init__(self, username, password):
        self.username = _decode_bytes(username)
        self.password = _decode_bytes(password)

    def __eq__(self, other):
        return all([
            self.username == getattr(other, 'username', None),
            self.password == getattr(other, 'password', None)
        ])

    def __ne__(self, other):
        return not self == other

    def __call__(self, r):
        r.headers['Authorization'] = _basic_auth_str(self.username, self.password)
        return r


class HTTPProxyAuth(HTTPBasicAuth):
    def __call__(self, r):
        r.headers['Proxy-Authorization'] = _basic_auth_str(self.username, self.password)
        return r


class HTTPDigestAuth(AuthBase):
    """Attaches HTTP Digest Authentication to the given Request object."""

    def __init__(self, username, password):
        self.username = _decode_bytes(username)
        self.password = _decode_bytes(password)
        self._thread_local = threading.local()

    def init_per_thread_state(self):
        if not hasattr(self._thread_local, 'init'):
            self._thread_local.init = True
            self._thread_local.last_nonce = ''
            self._thread_local.nonce_count = 0
            self._thread_local.chal = {}
            self._thread_local.pos = None
            self._thread_local.num_401_calls = None

    def build_digest_header(self, method, url):
        realm = self._thread_local.chal.get('realm')
        nonce = self._thread_local.chal.get('nonce')
        qop = self._thread_local.chal.get('qop')
        algorithm = self._thread_local.chal.get('algorithm')
        opaque = self._thread_local.chal.get('opaque')

        if algorithm is None:
            _algorithm = 'MD5'
        else:
            _algorithm = algorithm.upper()

        if _algorithm == 'MD5' or _algorithm == 'MD5-SESS':
            def md5_utf8(x):
                if isinstance(x, str):
                    x = x.encode('utf-8')
                return hashlib.md5(x).hexdigest()
            hash_utf8 = md5_utf8
        elif _algorithm == 'SHA':
            def sha_utf8(x):
                if isinstance(x, str):
                    x = x.encode('utf-8')
                return hashlib.sha1(x).hexdigest()
            hash_utf8 = sha_utf8
        elif _algorithm == 'SHA-256':
            def sha256_utf8(x):
                if isinstance(x, str):
                    x = x.encode('utf-8')
                return hashlib.sha256(x).hexdigest()
            hash_utf8 = sha256_utf8
        elif _algorithm == 'SHA-512':
            def sha512_utf8(x):
                if isinstance(x, str):
                    x = x.encode('utf-8')
                return hashlib.sha512(x).hexdigest()
            hash_utf8 = sha512_utf8
        else:
            return None

        KD = lambda s, d: hash_utf8("%s:%s" % (s, d))

        if hash_utf8 is None:
            return None

        if qop:
            chal_qop = [x.strip() for x in qop.split(",")]
            if "auth" in chal_qop:
                qop = "auth"
            elif "auth-int" in chal_qop:
                qop = "auth-int"
            else:
                return None

        if nonce != self._thread_local.last_nonce:
            self._thread_local.nonce_count = 1
            self._thread_local.last_nonce = nonce
        else:
            self._thread_local.nonce_count += 1

        ncvalue = '%08x' % self._thread_local.nonce_count
        s = str(self._thread_local.nonce_count).encode('ascii')
        s += nonce.encode('ascii') if nonce else b''
        s += time.ctime().encode('ascii')
        s += os.urandom(8)

        cnonce = hashlib.sha1(s).hexdigest()[:16]
        username = _decode_bytes(self.username)
        password = _decode_bytes(self.password)

        if _algorithm == 'MD5-SESS':
            HA1 = hash_utf8('%s:%s:%s:%s:%s' % (
                hash_utf8('%s:%s:%s' % (username, realm, password)),
                nonce,
                cnonce,
                username,
                realm
            ))
        else:
            HA1 = hash_utf8('%s:%s:%s' % (username, realm, password))

        parsed_path = urlparse(url).path
        path = parsed_path if parsed_path else '/'

        if qop == 'auth':
            HA2 = hash_utf8('%s:%s' % (method, path))
            resp_hash = KD(HA1, '%s:%s:%s:%s:%s' % (nonce, ncvalue, cnonce, qop, HA2))
        elif qop == 'auth-int':
            HA2 = hash_utf8('%s:%s' % (method, path))
            resp_hash = KD(HA1, '%s:%s:%s:%s:%s' % (nonce, ncvalue, cnonce, qop, HA2))
        else:
            HA2 = hash_utf8('%s:%s' % (method, path))
            resp_hash = KD(HA1, '%s:%s' % (nonce, HA2))

        base = 'username="%s", realm="%s", nonce="%s", uri="%s", ' \
               'response="%s"' % (
                   username, realm, nonce, path, resp_hash
               )
        if opaque:
            base += ', opaque="%s"' % opaque
        if algorithm:
            base += ', algorithm="%s"' % algorithm
        if qop:
            base += ', qop="%s", nc=%s, cnonce="%s"' % (qop, ncvalue, cnonce)

        return 'Digest %s' % (base)

    def handle_401(self, r, **kwargs):
        if self._thread_local.pos is not None:
            r.request.body.seek(self._thread_local.pos)
        num_401_calls = getattr(self._thread_local, 'num_401_calls', 1)

        s_auth = r.headers.get('www-authenticate', '')

        if 'digest' in s_auth.lower() and num_401_calls < 2:
            self._thread_local.num_401_calls += 1
            pat = re.compile(r'digest ', flags=re.IGNORECASE)
            self._thread_local.chal = parse_dict_header(pat.sub('', s_auth, count=1))

            _ = r.content
            if hasattr(r, 'raw') and hasattr(r.raw, 'release_conn'):
                r.raw.release_conn()
            prep = r.request.copy()
            if hasattr(prep, '_cookies') and hasattr(r, 'raw'):
                try:
                    from .cookies import extract_cookies_to_jar
                    extract_cookies_to_jar(prep._cookies, r.request, r.raw)
                    prep.prepare_cookies(prep._cookies)
                except Exception:
                    pass

            prep.headers['Authorization'] = self.build_digest_header(
                prep.method, prep.url)
            _r = r.connection.send(prep, **kwargs)
            _r.history.append(r)
            _r.request = prep

            return _r

        self._thread_local.num_401_calls = 1
        return r

    def __call__(self, r):
        self.init_per_thread_state()
        if self._thread_local.last_nonce:
            r.headers['Authorization'] = self.build_digest_header(r.method, r.url)
        try:
            self._thread_local.pos = r.body.tell()
        except AttributeError:
            self._thread_local.pos = None
        r.register_hook('response', self.handle_401)
        self._thread_local.num_401_calls = 1
        return r

    def __eq__(self, other):
        return all([
            self.username == getattr(other, 'username', None),
            self.password == getattr(other, 'password', None)
        ])

    def __ne__(self, other):
        return not self == other
