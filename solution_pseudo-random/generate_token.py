from ecdsa import SigningKey, NIST256p
from hashlib import sha256
from jwcrypto import jwk
import jwt
import time
from random import randrange

from crypto_util import extract_private_key, b64decode, b64encode, verify, split_token

with open("key.pem") as key_file:
    pem = key_file.readlines()
pem = ''.join(pem)

sk = SigningKey.from_pem(pem, hashfunc=sha256)
jwk = jwk.JWK.from_pem(pem.encode('utf-8'))

now = int(time.time())

payload = {
    "exp": now + 3600,
    "scopes": [
        "capture"
    ]
}

print("Token content: ")
print(payload)
print("Generated valid JWT")
data = jwt.encode(payload, jwk.export_to_pem(private_key=True, password=None), algorithm="ES256")
print(data)
parts = data.split('.')
message = parts[0] + "." + parts[1]
# Test
verify(jwk.export_to_pem(), data)

payload["exp"] = now + 1
data = jwt.encode(payload, jwk.export_to_pem(private_key=True, password=None), algorithm="ES256")
verify(jwk.export_to_pem(), data)

# Generate bad tokens
bad_seeds = []
for _ in range(15):
    k = randrange(NIST256p.order, None)
    bad_seeds.append(k)

tokens = []
for i in range(0, 25):
    k = bad_seeds[0]
    now = int(time.time())
    claims = '{"exp":%s,"scopes":["capture"]}' % (now + 10 + i)
    claims = b64encode(claims.encode('utf-8')).decode('utf-8')
    message = parts[0] + "." + claims
    signature = sk.sign(bytearray(message.encode('utf-8')), k=k)
    token = message + "." + b64encode(signature).decode('utf-8')
    tokens.append(token)
    verify(jwk.export_to_pem(), token)


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
_, d = extract_private_key(message1, message2, sig1, sig2)

extracted_key = SigningKey.from_string(d, curve=NIST256p, hashfunc=sha256)
extracted_jwk = jwk.from_pem(extracted_key.to_pem())
payload["exp"] = now + 7200
data = jwt.encode(payload, jwk.export_to_pem(private_key=True, password=None), algorithm="ES256")
print("Generated extracted JWT")
print(data)


print("Tokens:")
for token in tokens:
    print(token)