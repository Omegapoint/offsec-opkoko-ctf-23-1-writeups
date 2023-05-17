from ecdsa import SigningKey, NIST256p
from hashlib import sha256
from jwcrypto import jwk
import json

sk = SigningKey.generate(curve=NIST256p, hashfunc=sha256)


print(sk.to_pem())
with open("key.pem", "w") as key_file:
    key_file.write(sk.to_pem().decode('utf-8'))

#private static readonly Dictionary<string, object> JwkDict = new()
#{
#    { "crv", "P-256" },
#    { "kid", "V5Q1HwqhFJTLU-QXUwj4sArvajA3y4vBsiyadMvGWPc" },
#    { "kty", "EC" },
#    { "x", "eRtIBzhTRBlPNyiOjNWoiR7WkqNjvNPFSsFHE1TOUqQ" },
#    { "y", "BVVoV8x-5AvsOw2HU2Ajao4HFOs4WMhgIL7y4tP7jo4" }
#};

key = jwk.JWK.from_pem(sk.to_pem())
key_object = json.loads(key.export())

print("private static readonly Dictionary<string, object> JwkDict = new()")
print("{")
for k in key_object:
    print("    { \"%s\", \"%s\" }," % (k, key_object[k]))
print("}")