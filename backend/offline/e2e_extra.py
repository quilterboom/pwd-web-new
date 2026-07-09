"""Extra E2E checks: xlsx template round-trip + wrong GPG passphrase rejection."""
import json, urllib.request, urllib.error, io, sys, datetime

BASE = "http://localhost:9012"

def req(method, path, body=None, token=None, files=None):
    url = BASE + path
    data = None; hdrs = {}
    if token: hdrs["Authorization"] = "Bearer " + token
    if files is not None:
        boundary = "----e2eboundaryXYZ"
        parts = []
        for field,(fn,fd,ft) in files.items():
            parts.append(("--"+boundary).encode())
            parts.append(f'Content-Disposition: form-data; name="{field}"; filename="{fn}"'.encode())
            parts.append(f"Content-Type: {ft}".encode())
            parts.append(b""); parts.append(fd if isinstance(fd,bytes) else fd.encode())
        parts.append(("--"+boundary+"--").encode()); parts.append(b"")
        data = b"\r\n".join(parts)
        hdrs["Content-Type"] = f"multipart/form-data; boundary={boundary}"
    elif body is not None:
        data = json.dumps(body).encode(); hdrs["Content-Type"]="application/json"
    r = urllib.request.Request(url, data=data, method=method, headers=hdrs)
    try:
        resp = urllib.request.urlopen(r, timeout=30); return resp.status, resp.read(), resp.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read(), e.headers

# SM3 for admin login
import struct
_SM3_IV=[0x7380166f,0x4914b2b9,0x172442d7,0xda8a0600,0xa96f30bc,0x163138aa,0xe38dee4d,0xb0fb0e4e]
def _rotl(x,n): x&=0xffffffff; return ((x<<n)|(x>>(32-n)))&0xffffffff
def _p0(x): return x^_rotl(x,9)^_rotl(x,17)
def _p1(x): return x^_rotl(x,15)^_rotl(x,23)
def _ff(x,y,z,j): return (x^y^z) if j<16 else ((x&y)|(x&z)|(y&z))
def _gg(x,y,z,j): return (x^y^z) if j<16 else ((x&y)|((~x)&z))
def _tj(j): return 0x79cc4519 if j<16 else 0x7a879d8a
def _cf(V,B):
    W=[0]*68
    for i in range(16): W[i]=struct.unpack(">I",B[i*4:i*4+4])[0]
    for i in range(16,68):
        x=W[i-16]^W[i-9]^_rotl(W[i-3],15); W[i]=_p1(x)^_rotl(W[i-13],7)^W[i-6]
    W1=[W[i]^W[i+4] for i in range(64)]
    A,B2,C,D,E,F,G,H=V
    for j in range(64):
        SS1=_rotl(_rotl(A,12)+E+_rotl(_tj(j),j%32),7)&0xffffffff
        SS2=SS1^_rotl(A,12)
        TT1=(_ff(A,B2,C,j)+D+SS2+W1[j])&0xffffffff
        TT2=(_gg(E,F,G,j)+H+SS1+W[j])&0xffffffff
        D=C;C=_rotl(B2,9);B2=A;A=TT1;H=G;G=_rotl(F,19);F=E;E=_p0(TT2)
    return [V[i]^v for i,v in enumerate([A,B2,C,D,E,F,G,H])]
def sm3_hex(data):
    V=_SM3_IV[:]; bitlen=len(data)*8; msg=bytearray(data); msg.append(0x80)
    while len(msg)%64!=56: msg.append(0)
    msg+=struct.pack(">Q",bitlen)
    for i in range(0,len(msg),64): V=_cf(V,msg[i:i+64])
    return b"".join(struct.pack(">I",v) for v in V).hex()

# login
st,b,_=req("POST","/api/auth/login/begin",{"username":"admin"})
chal=json.loads(b); T=sm3_hex(("TestPass!2026").encode()+bytes.fromhex(chal["salt"]))
proof=sm3_hex(bytes.fromhex(T)+bytes.fromhex(chal["nonce"]))
st,b,_=req("POST","/api/auth/login/verify",{"username":"admin","nonce":chal["nonce"],"proof":proof})
tok=json.loads(b)["access_token"]
print("logged in, token len", len(tok))

print("\n=== xlsx template round-trip ===")
st,xlsx,_=req("GET","/api/admin/users/template?fmt=xlsx",token=tok)
assert st==200 and xlsx[:2]==b"PK"
suffix=datetime.datetime.now().strftime("%H%M%S")
# re-upload the downloaded template (it has example rows alice/bob/carol)
st,b,h=req("POST","/api/admin/users/batch",token=tok,
            files={"file":("tpl.xlsx",xlsx,"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")})
res=json.loads(b)
print("  xlsx re-import: status",st,"total/created/errored",res["total"],res["created"],res["errored"])
for r in res["rows"]: print("   -",r["status"],r["username"] or "<empty>",r["message"])
# alice/bob/carol should import (or skip if exist). Just assert it parsed rows.
assert res["total"]>=3, "xlsx template not parsed into rows"
# cleanup any created
for u in ["alice","bob","carol"]:
    st2,b2,_=req("GET","/api/admin/users",token=tok)
    if st2==200:
        for usr in json.loads(b2):
            if usr["username"]==u:
                req("DELETE",f"/api/admin/users/{usr['id']}",token=tok)
                print("  cleaned",u)

print("\n=== wrong GPG passphrase rejected on import ===")
import subprocess, types
gen='''
import sys, types
sys.modules["imghdr"]=types.ModuleType("imghdr")
from pgpy import PGPKey, PGPUID
from pgpy.constants import SymmetricKeyAlgorithm, HashAlgorithm, KeyFlags, PubKeyAlgorithm
key=PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign,2048)
uid=PGPUID.new("wp test",email="wp@t.local")
key.add_uid(uid,usage={KeyFlags.EncryptCommunications,KeyFlags.EncryptStorage})
key.protect("right-pass-2026",SymmetricKeyAlgorithm.AES256,HashAlgorithm.SHA256)
open("/tmp/wp_priv.asc","w").write(str(key))
open("/tmp/wp_pub.asc","w").write(str(key.pubkey))
print("OK")
'''
subprocess.run(["docker","exec","pm-test2","python3","-c",gen],capture_output=True,text=True)
priv=subprocess.run(["docker","exec","pm-test2","cat","/tmp/wp_priv.asc"],capture_output=True,text=True).stdout
pub=subprocess.run(["docker","exec","pm-test2","cat","/tmp/wp_pub.asc"],capture_output=True,text=True).stdout
# import with WRONG passphrase -> should fail
st,b,_=req("POST","/api/orgkeys/import",token=tok,
            body={"name":"wrong-pw-key","public_key":pub,"private_key":priv,
                  "algorithm":"gpg","group_id":1,"private_passphrase":"WRONG-pass"})
print("  wrong-pass import status",st,"->",b.decode()[:120])
assert st!=200, "wrong GPG passphrase should be rejected!"
# import with RIGHT passphrase -> should succeed
st,b,_=req("POST","/api/orgkeys/import",token=tok,
            body={"name":"right-pw-key","public_key":pub,"private_key":priv,
                  "algorithm":"gpg","group_id":1,"private_passphrase":"right-pass-2026"})
print("  right-pass import status",st,"->",b.decode()[:120])
assert st==200, "correct GPG passphrase should be accepted"
kid=json.loads(b)["id"]
req("DELETE",f"/api/orgkeys/{kid}",token=tok)
print("  cleaned key",kid)

print("\nALL EXTRA E2E TESTS PASSED")
