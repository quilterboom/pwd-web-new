"""Smoke test: deletion audit record + admin audit log view (task: 删除两步确认 + 管理员审计日志).

Run against a live container, e.g.:
    python3 smoke_audit.py http://localhost:9014

- 管理员可访问 /api/admin/audit（含 ?action=delete 过滤）
- 删除密码后，审计日志中必须出现一条 action=delete 的记录，含账号与「删除密码」说明
- 非管理员访问审计日志必须返回 403
"""
import json
import sys
import urllib.request
import urllib.error

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:9014"


def req(method, path, body=None, token=None):
    url = BASE + path
    data = None
    hdrs = {}
    if token:
        hdrs["Authorization"] = "Bearer " + token
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        hdrs["Content-Type"] = "application/json"
    r = urllib.request.Request(url, data=data, method=method, headers=hdrs)
    try:
        resp = urllib.request.urlopen(r, timeout=30)
        return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


# ---- 纯 Python SM3（与前端/服务端一致的 GM/T 0003-2012）----
import struct
_SM3_IV = [0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
            0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e]


def _rotl(x, n):
    x &= 0xffffffff
    return ((x << n) | (x >> (32 - n))) & 0xffffffff


def _p0(x):
    return x ^ _rotl(x, 9) ^ _rotl(x, 17)


def _p1(x):
    return x ^ _rotl(x, 15) ^ _rotl(x, 23)


def _ff(x, y, z, j):
    return (x ^ y ^ z) if j < 16 else ((x & y) | (x & z) | (y & z))


def _gg(x, y, z, j):
    return (x ^ y ^ z) if j < 16 else ((x & y) | ((~x) & z))


def _tj(j):
    return 0x79cc4519 if j < 16 else 0x7a879d8a


def _cf(V, B):
    W = [0] * 68
    for i in range(16):
        W[i] = struct.unpack(">I", B[i * 4:i * 4 + 4])[0]
    for i in range(16, 68):
        x = W[i - 16] ^ W[i - 9] ^ _rotl(W[i - 3], 15)
        W[i] = _p1(x) ^ _rotl(W[i - 13], 7) ^ W[i - 6]
    W1 = [W[i] ^ W[i + 4] for i in range(64)]
    A, Bb, C, D, E, F, G, H = V
    for j in range(64):
        SS1 = _rotl(_rotl(A, 12) + E + _rotl(_tj(j), j % 32), 7) & 0xffffffff
        SS2 = SS1 ^ _rotl(A, 12)
        TT1 = (_ff(A, Bb, C, j) + D + SS2 + W1[j]) & 0xffffffff
        TT2 = (_gg(E, F, G, j) + H + SS1 + W[j]) & 0xffffffff
        D = C
        C = _rotl(Bb, 9)
        Bb = A
        A = TT1
        H = G
        G = _rotl(F, 19)
        F = E
        E = _p0(TT2)
    return [V[i] ^ v for i, v in enumerate([A, Bb, C, D, E, F, G, H])]


def sm3_hex(data: bytes):
    V = _SM3_IV[:]
    bitlen = len(data) * 8
    msg = bytearray(data)
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack(">Q", bitlen)
    for i in range(0, len(msg), 64):
        V = _cf(V, msg[i:i + 64])
    return b"".join(struct.pack(">I", v) for v in V).hex()


def scram_login(username, password):
    st, b = req("POST", "/api/auth/login/begin", {"username": username})
    assert st == 200, f"begin failed {st} {b[:200]}"
    chal = json.loads(b)
    salt_b = bytes.fromhex(chal["salt"])
    T = sm3_hex(password.encode("utf-8") + salt_b)
    nonce_b = bytes.fromhex(chal["nonce"])
    proof = sm3_hex(bytes.fromhex(T) + nonce_b)
    st2, b2 = req("POST", "/api/auth/login/verify",
                    {"username": username, "nonce": chal["nonce"], "proof": proof})
    assert st2 == 200, f"verify failed {st2} {b2[:200]}"
    return json.loads(b2)["access_token"]


PASS = "TestPass!2026"
ok = True


def check(name, cond):
    global ok
    print(("  ✓ " if cond else "  ✗ ") + name)
    if not cond:
        ok = False


print("=== 1. 管理员登录 ===")
tok = scram_login("admin", PASS)
check("admin token", bool(tok))

print("\n=== 2. 取一个分组 ===")
st, b = req("GET", "/api/groups/mine", token=tok)
check("groups/mine 200", st == 200)
groups = json.loads(b)
check("存在分组", len(groups) > 0)
gid = groups[0]["id"]

print("\n=== 3. 创建一条密码 ===")
uname = "audit_del_test"
st, b = req("POST", "/api/passwords", token=tok, body={
    "username": uname,
    "secret": "topsecret-1",
    "algorithm": "symmetric",
    "entry_password": "entry-pw-2026",
    "group_id": gid,
    "notes": "", "comment": "",
})
check("create 200", st == 200)
entry_id = json.loads(b)["id"]

print("\n=== 4. 删除该密码（两步确认是前端行为；后端 DELETE 直接生效）===")
st, b = req("DELETE", f"/api/passwords/{entry_id}", token=tok)
check("delete 200", st == 200)

print("\n=== 5. 管理员审计日志：按 action=delete 过滤 ===")
st, b = req("GET", "/api/admin/audit?action=delete", token=tok)
check("audit?action=delete 200", st == 200)
rows = json.loads(b)
del_rows = [r for r in rows if r.get("username") == uname]
check("出现一条删除记录", len(del_rows) == 1)
if del_rows:
    r = del_rows[0]
    check("记录 action=delete", r["action"] == "delete")
    check("记录含账号", r["username"] == uname)
    check("记录含「删除密码」说明", "删除密码" in (r.get("comment") or ""))
    check("记录含操作人 admin", r.get("changed_by") == "admin")
    check("记录含分组名", bool(r.get("group_name")))

print("\n=== 6. 审计日志：全部（应同时含 create 与 delete）===")
st, b = req("GET", "/api/admin/audit", token=tok)
check("audit 200", st == 200)
all_rows = json.loads(b)
acts = [r["action"] for r in all_rows if r.get("username") == uname]
check("全部记录含 create", "create" in acts)
check("全部记录含 delete", "delete" in acts)

print("\n=== 7. 非管理员访问审计日志必须 403 ===")
st, b = req("POST", "/api/admin/users", token=tok, body={
    "username": "auditor_nope", "password": "NopePass!9", "is_admin": False,
    "group_ids": [gid],
})
check("创建普通用户 200", st == 200)
utok = scram_login("auditor_nope", "NopePass!9")
st, b = req("GET", "/api/admin/audit", token=utok)
check("普通用户审计日志 403", st == 403)

print("\n=== 8. 清理 ===")
# 删除普通用户
st, b = req("GET", "/api/admin/users", token=tok)
if st == 200:
    for u in json.loads(b):
        if u["username"] == "auditor_nope":
            req("DELETE", f"/api/admin/users/{u['id']}", token=tok)
            print("  已删除普通用户 auditor_nope")

print("\n" + ("ALL AUDIT SMOKE TESTS PASSED" if ok else "SOME TESTS FAILED"))
sys.exit(0 if ok else 1)
