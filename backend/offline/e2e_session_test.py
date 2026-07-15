"""端到端验证：服务端强制失效（JWT 吊销 + 空闲超时）。
- MODE=logout（默认）：登录 → 调 /api/auth/logout → 同一令牌再请求应 401（吊销生效）。
- MODE=idle：容器需用 SESSION_IDLE_SECONDS=2 启动；登录 → 静置 3s → 请求应 401（空闲超时吊销）。
目标地址通过环境变量 BASE 指定（默认 http://localhost:9014）。
"""
import json, os, sys, struct, time, urllib.request, urllib.error

BASE = os.getenv("BASE", "http://localhost:9014")
MODE = os.getenv("MODE", "logout")

_SM3_IV = [0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
           0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e]
def _rotl(x, n):
    x &= 0xffffffff
    return ((x << n) | (x >> (32 - n))) & 0xffffffff
def _p0(x): return x ^ _rotl(x, 9) ^ _rotl(x, 17)
def _p1(x): return x ^ _rotl(x, 15) ^ _rotl(x, 23)
def _ff(x, y, z, j): return (x ^ y ^ z) if j < 16 else ((x & y) | (x & z) | (y & z))
def _gg(x, y, z, j): return (x ^ y ^ z) if j < 16 else ((x & y) | ((~x) & z))
def _tj(j): return 0x79cc4519 if j < 16 else 0x7a879d8a
def _cf(V, B):
    W = [0]*68
    for i in range(16): W[i] = struct.unpack(">I", B[i*4:i*4+4])[0]
    for i in range(16, 68):
        x = W[i-16] ^ W[i-9] ^ _rotl(W[i-3], 15)
        W[i] = _p1(x) ^ _rotl(W[i-13], 7) ^ W[i-6]
    W1 = [W[i] ^ W[i+4] for i in range(64)]
    A,B2,C,D,E,F,G,H = V
    for j in range(64):
        SS1 = _rotl(_rotl(A,12)+E+_rotl(_tj(j), j%32), 7) & 0xffffffff
        SS2 = SS1 ^ _rotl(A,12)
        TT1 = (_ff(A,B2,C,j)+D+SS2+W1[j]) & 0xffffffff
        TT2 = (_gg(E,F,G,j)+H+SS1+W[j]) & 0xffffffff
        D=C; C=_rotl(B2,9); B2=A; A=TT1
        H=G; G=_rotl(F,19); F=E; E=_p0(TT2)
    return [V[i]^v for i,v in enumerate([A,B2,C,D,E,F,G,H])]
def sm3_hex(data):
    V=_SM3_IV[:]; bl=len(data)*8; msg=bytearray(data); msg.append(0x80)
    while len(msg)%64!=56: msg.append(0)
    msg+=struct.pack(">Q", bl)
    for i in range(0,len(msg),64): V=_cf(V, msg[i:i+64])
    return b"".join(struct.pack(">I", v) for v in V).hex()

def req(method, path, body=None, token=None):
    url=BASE+path; h={}
    if token: h["Authorization"]="Bearer "+token
    data=None
    if body is not None:
        data=json.dumps(body).encode("utf-8"); h["Content-Type"]="application/json"
    r=urllib.request.Request(url, data=data, method=method, headers=h)
    try:
        resp=urllib.request.urlopen(r, timeout=30); rb=resp.read()
        return resp.status, (rb if False else (json.loads(rb) if rb else None))
    except urllib.error.HTTPError as e:
        return e.code, None

def scram_login(username, password):
    st, chal = req("POST", "/api/auth/login/begin", {"username": username})
    if st == 409:
        st, b = req("POST", "/api/auth/login", {"username": username, "password": password})
        return b["access_token"]
    T = sm3_hex(password.encode("utf-8") + bytes.fromhex(chal["salt"]))
    proof = sm3_hex(bytes.fromhex(T) + bytes.fromhex(chal["nonce"]))
    st, b = req("POST", "/api/auth/login/verify", {"username": username, "nonce": chal["nonce"], "proof": proof})
    return b["access_token"]

fails=0
def check(cond, msg):
    global fails
    print(("  ✅ "+msg) if cond else ("  ❌ "+msg))
    if not cond: fails+=1

print(f"=== 服务端强制失效 E2E (MODE={MODE}) ===")
admin = scram_login("admin", "TestPass!2026")
print("admin token len:", len(admin))

if MODE == "idle":
    print("\n=== 空闲超时：静置超过 SESSION_IDLE_SECONDS 后令牌失效 ===")
    st, me = req("GET", "/api/auth/me", token=admin)
    check(st==200, f"登录后立即请求 200 (实际 {st})")
    print("  静置 3 秒…")
    time.sleep(3)
    st, _ = req("GET", "/api/auth/me", token=admin)
    check(st==401, f"空闲 3s 后请求 401（服务端吊销）(实际 {st})")
else:
    print("\n=== 登出吊销：/api/auth/logout 后令牌立即失效 ===")
    st, me = req("GET", "/api/auth/me", token=admin)
    check(st==200, f"登录后 /me 200 (实际 {st})")
    st, lo = req("POST", "/api/auth/logout", token=admin)
    check(st==200, f"/api/auth/logout 200 (实际 {st})")
    st, _ = req("GET", "/api/auth/me", token=admin)
    check(st==401, f"登出后同令牌 /me 401（已吊销）(实际 {st})")
    # 重新登录应得到全新可用会话
    admin2 = scram_login("admin", "TestPass!2026")
    st, _ = req("GET", "/api/auth/me", token=admin2)
    check(st==200, f"重新登录后 /me 200（新会话有效）(实际 {st})")

print("\n" + ("ALL SESSION E2E PASS ✅" if fails==0 else f"FAILED ❌ ({fails} 项不通过)"))
sys.exit(1 if fails else 0)
