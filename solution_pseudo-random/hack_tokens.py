import base64
import time
from hashlib import sha256
import jwt
from ecdsa import NIST256p, numbertheory, VerifyingKey
from ecdsa import SigningKey
from ecdsa._compat import normalise_bytes
from ecdsa.keys import _truncate_and_convert_digest
from ecdsa.util import number_to_string
from jwcrypto import jwk
import requests

# requirements.txt:
# - ecdsa
# - pyjwt
# - jwcrypto

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


def recover_key_from_duplicate_r(sig1, msg1, sig2, msg2):
    r1 = int.from_bytes(sig1[:32], 'big')
    s1 = int.from_bytes(sig1[32:], 'big')
    r2 = int.from_bytes(sig2[:32], 'big')
    s2 = int.from_bytes(sig2[32:], 'big')
    m1 = int.from_bytes(sha256(msg1).digest(), 'big')
    m2 = int.from_bytes(sha256(msg2).digest(), 'big')

    order = NIST256p.order
    inv = pow(s1 - s2, -1, order)

    k1 = (inv * (m1 * s2 - m2 * s1)) % order
    k2 = (inv * (r1 * s2 - r2 * s1)) % order

    d = (inv * (s1 * k1 - m1)) % order
    print(d)
    sk = SigningKey.from_secret_exponent(d, curve=NIST256p, hashfunc=sha256)
    return sk

def b64decode(s):
    return base64.urlsafe_b64decode(s + '=' * (4 - len(s) % 4))
def b64encode(s):
    return base64.urlsafe_b64encode(s).rstrip(b'=')


tokens = [
    "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2ODM0MjA5MTEsInNjb3BlcyI6WyJjYXB0dXJlIl19.pRkS7dFZjw9mwURa9OaDpkZmhanXHGKnazVrsC9Oyf4Q-avxcJwsembKUibgpHmvAWml2vmAGTJnnsEpvG-Drw",
    "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2ODM0MjA5MTIsInNjb3BlcyI6WyJjYXB0dXJlIl19.pRkS7dFZjw9mwURa9OaDpkZmhanXHGKnazVrsC9Oyf7DhYKI5ksm10sp3twPcwZySjDtVkumO48Yg6wzUVYB6w",
    "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2ODM0MjA5MTMsInNjb3BlcyI6WyJjYXB0dXJlIl19.pRkS7dFZjw9mwURa9OaDpkZmhanXHGKnazVrsC9Oyf7CVPaoTiFWEBp63JaDKF2eU6ZU5xU-XJIIq9SecXFe8g",
]

r_values = {}
r_reuse = None
for token in tokens:
    parts = token.split('.')
    signature = b64decode(parts[2])
    r = signature[0:32]
    s = signature[32:]
    if r in r_values.keys():
        r_values[r].append(token)
    else:
        r_values[r] = [token]
    if len(r_values[r]) > 1:
        r_reuse = r_values[r]
        break

message1, sig1 = split_token(r_reuse[0])
message2, sig2 = split_token(r_reuse[1])

p, d = extract_private_key(message1, message2, sig1, sig2)
print(p)


extracted_key = SigningKey.from_string(d, curve=NIST256p, hashfunc=sha256)
extracted_jwk = jwk.JWK.from_pem(extracted_key.to_pem())

payload = {
    "exp": int(time.time()) + 3600,
    "scopes": [
        "capture"
    ]
}

data = jwt.encode(payload, extracted_jwk.export_to_pem(private_key=True, password=None), algorithm="ES256")
print("Generated extracted JWT")
print(data)

import requests

#url = 'http://localhost:4280/api/capture'
url = 'https://lemon-pebble-07f764303.3.azurestaticapps.net/api/capture'
headers = {'x-authorization': f"Bearer {data}"}
response = requests.get(url, headers=headers)
print(response.text)