"""端到端验证：服务端强制失效（JWT 吊销 + 空闲超时 + 单账号单会话）。
- MODE=logout（默认）：登录 → 调 /api/auth/logout → 同一令牌再请求应 401（吊销生效）。
- MODE=idle：容器需用 SESSION_IDLE_SECONDS=2 启动；登录 → 静置 3s → 请求应 401（空闲超时吊销）。
- MODE=activity：容器需用 SESSION_IDLE_SECONDS=3 启动；证明「操作系统时上报 /api/auth/activity
  会重置服务端空闲计时」（对照组用独立账号，避免被 admin 的重复登录互相吊销）。
- MODE=single：单账号单会话——同一账号二次登录（含不同 IP）会吊销此前所有会话，
  只有最新令牌有效。
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

def req(method, path, body=None, token=None, headers=None):
    url=BASE+path; h=dict(headers or {})
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

def scram_login(username, password, extra_headers=None):
    st, chal = req("POST", "/api/auth/login/begin", {"username": username}, headers=extra_headers)
    if st == 409:
        st, b = req("POST", "/api/auth/login", {"username": username, "password": password}, headers=extra_headers)
        return b["access_token"]
    T = sm3_hex(password.encode("utf-8") + bytes.fromhex(chal["salt"]))
    proof = sm3_hex(bytes.fromhex(T) + bytes.fromhex(chal["nonce"]))
    st, b = req("POST", "/api/auth/login/verify", {"username": username, "nonce": chal["nonce"], "proof": proof}, headers=extra_headers)
    return b["access_token"]

def create_user(admin_token, username, password):
    st, b = req("POST", "/api/admin/users", {"username": username, "password": password}, token=admin_token)
    if st not in (200, 201):
        raise RuntimeError(f"创建测试用户失败: {st} {b}")
    return b

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

elif MODE == "activity":
    # 容器需用 SESSION_IDLE_SECONDS=3 启动。
    # 证明：操作系统时上报 /api/auth/activity 会重置服务端空闲计时。
    # 对照组用「独立账号」act_ctrl（避免与 admin 的重复登录互相吊销，影响判读）。
    print("\n=== 活动上报：/api/auth/activity 重置服务端空闲计时 ===")
    ctrl = create_user(admin, "act_ctrl", "ActCtrl!2026")
    ctrl_token = scram_login("act_ctrl", "ActCtrl!2026")

    # 对照组：独立账号，从不上报活动，静置 4s（>3s）应被吊销
    time.sleep(4)
    st, _ = req("GET", "/api/auth/me", token=ctrl_token)
    check(st==401, f"对照组（独立账号，无活动）静置 4s 后 401（服务端吊销）(实际 {st})")

    # 实验组：adminA 上报活动，2s 后上报一次，再过 2s 请求应 200（计时被重置）
    adminA = scram_login("admin", "TestPass!2026")
    time.sleep(2)
    st, _ = req("POST", "/api/auth/activity", token=adminA)
    check(st==200, f"上报活动 200 (实际 {st})")
    print("  上报活动后静置 2 秒…")
    time.sleep(2)
    st, _ = req("GET", "/api/auth/me", token=adminA)
    check(st==200, f"上报后 2s 内请求 200（计时已重置）(实际 {st})")

elif MODE == "single":
    # 单账号单会话：同一账号二次登录（含不同 IP）会吊销此前所有会话，只有最新令牌有效。
    print("\n=== 单账号单会话：最新登录有效，旧登录（含其它 IP）立即失效 ===")
    # 第一次登录（不指定 IP，记录为会话 A）
    t1 = scram_login("admin", "TestPass!2026")
    st, _ = req("GET", "/api/auth/me", token=t1)
    check(st==200, f"首次登录 t1 /me 200 (实际 {st})")

    # 第二次登录（模拟来自不同 IP，记录为会话 B）——应吊销会话 A
    t2 = scram_login("admin", "TestPass!2026", extra_headers={"X-Forwarded-For": "203.0.113.9"})
    st, _ = req("GET", "/api/auth/me", token=t2)
    check(st==200, f"二次登录（其它 IP）t2 /me 200 (实际 {st})")

    # 关键断言：旧会话 A（首次登录，可能来自另一 IP）已被吊销
    st, _ = req("GET", "/api/auth/me", token=t1)
    check(st==401, f"旧登录 t1 已被吊销 401（账号单会话生效）(实际 {st})")

    # 第三次登录（无 IP，记录为会话 C）——应吊销会话 B，仅 C 有效
    t3 = scram_login("admin", "TestPass!2026")
    st, _ = req("GET", "/api/auth/me", token=t3)
    check(st==200, f"三次登录 t3 /me 200 (实际 {st})")
    st, _ = req("GET", "/api/auth/me", token=t2)
    check(st==401, f"上一轮 t2 已被新一轮登录吊销 401（仅最新有效）(实际 {st})")

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
