import base64
from hashlib import sha256
from ecdsa import NIST256p, numbertheory, VerifyingKey
from ecdsa._compat import normalise_bytes
from ecdsa.keys import _truncate_and_convert_digest
from ecdsa.util import number_to_string

import jwt

def verify(pem, data):
    jwt.decode(data, pem, algorithms="ES256")
    parts = data.split('.')
    tmp = bytearray(b64decode(parts[2]))
    message = parts[0] + "." + parts[1]
    key = VerifyingKey.from_pem(pem, hashfunc=sha256)
    key.verify(tmp, bytearray(message.encode('utf-8')))

def split_token(token):
    parts = token.split('.')
    message = parts[0] + '.' + parts[1]
    signature = b64decode(parts[2])
    return bytearray(message.encode('utf-8')), signature

def extract_r_s(digest):
    r_digest = digest[0:32]
    s_digest = digest[32:]
    r = _truncate_and_convert_digest(r_digest, NIST256p, True)
    s = _truncate_and_convert_digest(s_digest, NIST256p, True)
    return r, s

def extract_private_key(m1, m2, sig1, sig2):
    m1 = normalise_bytes(m1)
    m2 = normalise_bytes(m2)
    h1 = normalise_bytes(sha256(m1).digest())
    h2 = normalise_bytes(sha256(m2).digest())
    h1 = _truncate_and_convert_digest(h1, NIST256p, True)
    h2 = _truncate_and_convert_digest(h2, NIST256p, True)
    #print((h1, h2))
    r1, s1 = extract_r_s(sig1)
    r2, s2 = extract_r_s(sig2)
    n = NIST256p.order

    """
            s1 = numbertheory.inverse_mod(k, n) * (h1 + (d * r1) % n)
            s2 = numbertheory.inverse_mod(k, n) * (h2 + (d * r2) % n)
            
            s2 / (h2 + (d * r2)) = numbertheory.inverse_mod(k, n)
            
            s1 = s2 / (h2 + (d * r2)) * (h1 + (d * r1))
            s1 * (h2 + (d * r2)) = s2 * (h1 + (d * r1))
            s1*h2 + s1*d*r2 = s2*h1 + s2*d*r1
            s1*h2 - s2*h1 = d(s2*r1 - s1*r2)
    """
    d = ((s1*h2 % n - s2*h1 % n) * numbertheory.inverse_mod((s2*r1 % n - s1*r2 % n), n) % n)
    return d, number_to_string(d, NIST256p.order)

def b64decode(s):
    return base64.urlsafe_b64decode(s + '=' * (4 - len(s) % 4))
def b64encode(s):
    return base64.urlsafe_b64encode(s).rstrip(b'=')