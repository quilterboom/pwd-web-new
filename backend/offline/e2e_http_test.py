"""E2E HTTP test for features 3,4,5 against live container (port 9012).
Encryption happens server-side in the container, so a host HTTP client is safe.
"""
import json, urllib.request, urllib.error, base64, csv, io, sys

BASE = "http://localhost:9012"

def req(method, path, body=None, token=None, raw=False, headers=None, files=None):
    url = BASE + path
    data = None
    hdrs = {}
    if token:
        hdrs["Authorization"] = "Bearer " + token
    if files is not None:
        # multipart/form-data
        boundary = "----e2eboundary1234567890"
        parts = []
        for field, (fname, fdata, ftype) in files.items():
            parts.append(("--" + boundary).encode())
            parts.append(f'Content-Disposition: form-data; name="{field}"; filename="{fname}"'.encode())
            parts.append(f"Content-Type: {ftype}".encode())
            parts.append(b"")
            parts.append(fdata if isinstance(fdata, bytes) else fdata.encode("utf-8"))
        parts.append(("--" + boundary + "--").encode())
        parts.append(b"")
        data = b"\r\n".join(parts)
        hdrs["Content-Type"] = f"multipart/form-data; boundary={boundary}"
    elif body is not None:
        if isinstance(body, (bytes, bytearray)):
            data = body
        else:
            data = json.dumps(body).encode("utf-8")
            hdrs["Content-Type"] = "application/json"
    if headers:
        hdrs.update(headers)
    r = urllib.request.Request(url, data=data, method=method, headers=hdrs)
    try:
        resp = urllib.request.urlopen(r, timeout=30)
        raw_b = resp.read()
        return resp.status, raw_b, resp.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read(), e.headers

def scram_login(username, password):
    st, b, _ = req("POST", "/api/auth/login/begin", {"username": username})
    assert st == 200, f"begin failed {st} {b[:200]}"
    chal = json.loads(b)
    # Reuse a tiny pure-python SM3 to compute proof (same as server)
    from sm3pure import sm3_hex
    salt_b = bytes.fromhex(chal["salt"])
    T = sm3_hex(password.encode("utf-8") + salt_b)
    nonce_b = bytes.fromhex(chal["nonce"])
    proof = sm3_hex(bytes.fromhex(T) + nonce_b)
    st2, b2, _ = req("POST", "/api/auth/login/verify",
                       {"username": username, "nonce": chal["nonce"], "proof": proof})
    assert st2 == 200, f"verify failed {st2} {b2[:200]}"
    return json.loads(b2)["access_token"]

# ---- minimal pure-python SM3 (GM/T 0003-2012) ----
import struct
_SM3_IV = [0x7380166f,0x4914b2b9,0x172442d7,0xda8a0600,0xa96f30bc,0x163138aa,0xe38dee4d,0xb0fb0e4e]
def _rotl(x,n): x&=0xffffffff; return ((x<<n)|(x>>(32-n)))&0xffffffff
def _p0(x): return x^_rotl(x,9)^_rotl(x,17)
def _p1(x): return x^_rotl(x,15)^_rotl(x,23)
def _ff(x,y,z,j): return (x^y^z) if j<16 else ((x&y)|(x&z)|(y&z))
def _gg(x,y,z,j): return (x^y^z) if j<16 else ((x&y)|((~x)&z))
def _tj(j): return 0x79cc4519 if j<16 else 0x7a879d8a
def _cf(V,B):
    W=[0]*68
    for i in range(16):
        W[i]=struct.unpack(">I",B[i*4:i*4+4])[0]
    for i in range(16,68):
        x=W[i-16]^W[i-9]^_rotl(W[i-3],15)
        W[i]=_p1(x)^_rotl(W[i-13],7)^W[i-6]
    W1=[W[i]^W[i+4] for i in range(64)]
    A,B2,C,D,E,F,G,H=V
    for j in range(64):
        SS1=_rotl(_rotl(A,12)+E+_rotl(_tj(j),j%32),7)&0xffffffff
        SS2=SS1^_rotl(A,12)
        TT1=(_ff(A,B2,C,j)+D+SS2+W1[j])&0xffffffff
        TT2=(_gg(E,F,G,j)+H+SS1+W[j])&0xffffffff
        D=C;C=_rotl(B2,9);B2=A;A=TT1
        H=G;G=_rotl(F,19);F=E;E=_p0(TT2)
    return [V[i]^v for i,v in enumerate([A,B2,C,D,E,F,G,H])]
def sm3_hex(data: bytes):
    V=_SM3_IV[:]
    bitlen=len(data)*8
    msg=bytearray(data); msg.append(0x80)
    while len(msg)%64!=56: msg.append(0)
    msg+=struct.pack(">Q",bitlen)
    for i in range(0,len(msg),64):
        V=_cf(V,msg[i:i+64])
    return b"".join(struct.pack(">I",v) for v in V).hex()
sys.modules["sm3pure"]=sys.modules[__name__]

# =================== MAIN ===================
print("=== Feature 4: SCRAM login ===")
tok = scram_login("admin", "TestPass!2026")
print("  admin token OK, len", len(tok))

print("\n=== Feature 5: download xlsx template ===")
st,b,h = req("GET", "/api/admin/users/template?fmt=xlsx", token=tok)
print("  status", st, "content-type", h.get("Content-Type"), "bytes", len(b))
assert st==200 and b[:2]==b"PK", "xlsx template not returned"

print("\n=== Feature 5: download csv template ===")
st,b,h = req("GET", "/api/admin/users/template?fmt=csv", token=tok)
print("  status", st, "bytes", len(b), "head", b[:30])
assert st==200

print("\n=== Feature 5: bulk CSV import (3 rows: 2 ok + 1 dup error) ===")
# admin already exists; try import admin (error) + two new users
import datetime
suffix = datetime.datetime.now().strftime("%H%M%S")
u1, u2 = f"dave_{suffix}", f"erin_{suffix}"
buf=io.StringIO()
w=csv.writer(buf)
w.writerow(["用户名","密码","是否管理员","所属分组"])
w.writerow([u1,"DavePass!1","否",""])
w.writerow([u2,"ErinPass!2","否",""])
w.writerow(["admin","AdminDup!3","是",""])  # duplicate -> error
csv_bytes=("\ufeff"+buf.getvalue()).encode("utf-8")
st,b,h=req("POST","/api/admin/users/batch",
            token=tok,
            files={"file": ("users.csv", csv_bytes, "text/csv")})
print("  status", st)
res=json.loads(b)
print("  total/created/errored:", res["total"], res["created"], res["errored"])
for r in res["rows"]:
    print("   -", r["row"], r["status"], r["username"], r["message"])
assert res["created"]==2 and res["errored"]>=1, "bulk import counts wrong"

print("\n=== Feature 3: import GPG key WITH passphrase ===")
# Build a GPG private key (no passphrase) then protect with passphrase via pgpy in container?
# Simpler: ask server to generate a GPG key via /api/orgkeys/generate, then we can't easily get
# a passphrase-protected armored key from outside. Instead: generate one inside container via exec.
import subprocess
gen_script = '''
import sys, types
sys.path.insert(0,"/app")
# stub imghdr (removed in py3.13) so pgpy can import
sys.modules["imghdr"] = types.ModuleType("imghdr")
from pgpy import PGPKey, PGPUID
from pgpy.constants import SymmetricKeyAlgorithm, HashAlgorithm, KeyFlags, PubKeyAlgorithm
key = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
uid = PGPUID.new("batch test", email="batch@test.local")
key.add_uid(uid, usage={KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage})
key.protect("gpg-pass-2026", SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)
arm = str(key)
pub_arm = str(key.pubkey)
open("/tmp/gpg_prot.asc","w").write(arm)
open("/tmp/gpg_prot_pub.asc","w").write(pub_arm)
print("LEN", len(arm))
'''
out = subprocess.run(["docker","exec","pm-test2","python3","-c",gen_script],
                     capture_output=True, text=True)
print("  key gen:", out.stdout.strip(), out.stderr.strip()[:200])
arm = subprocess.run(["docker","exec","pm-test2","cat","/tmp/gpg_prot.asc"],
                     capture_output=True, text=True).stdout
pub_arm = subprocess.run(["docker","exec","pm-test2","cat","/tmp/gpg_prot_pub.asc"],
                     capture_output=True, text=True).stdout

st,b,h = req("POST", "/api/orgkeys/import", token=tok,
              body={"name":"GPG受口令保护测试密钥",
                    "public_key": pub_arm,
                    "private_key": arm,
                    "algorithm":"gpg",
                    "group_id": 1,
                    "private_passphrase":"gpg-pass-2026"})
print("  import status", st, b.decode("utf-8")[:200])
assert st==200, "protected GPG import failed"
kid = json.loads(b)["id"]
print("  imported orgkey id", kid)

print("\n=== Feature 3: encrypt a password with that GPG key, then unlock ===")
st,b,h = req("POST", "/api/passwords", token=tok, body={
    "username":"gpg_pw_test",
    "secret":"super-secret-123",
    "algorithm":"gpg",
    "orgkey_id": kid,
    "entry_password":"entry-pw-2026",
    "group_id": 1,
    "notes":"", "comment":""
})
print("  create status", st, b.decode("utf-8")[:120])
assert st==200, "create with protected gpg key failed"
entry_id = json.loads(b)["id"]

# unlock via entry password (no gpg passphrase needed at unlock since outer uses orgkey private key server-side)
st,b,h = req("POST", f"/api/passwords/{entry_id}/unlock", token=tok,
              body={"entry_password":"entry-pw-2026"})
print("  unlock status", st, b.decode("utf-8")[:120])
assert st==200, "unlock failed"
assert json.loads(b)["secret"]=="super-secret-123"
print("  secret matches ✓")

print("\n=== CLEANUP: delete test users + entry + key ===")
req("DELETE", f"/api/passwords/{entry_id}", token=tok)
req("DELETE", f"/api/orgkeys/{kid}", token=tok)
for u in [u1, u2]:
    # find id
    st,b,h=req("GET","/api/admin/users", token=tok)
    if st==200:
        for usr in json.loads(b):
            if usr["username"]==u:
                req("DELETE", f"/api/admin/users/{usr['id']}", token=tok)
                print("  deleted user", u)

print("\nALL E2E HTTP TESTS PASSED")
