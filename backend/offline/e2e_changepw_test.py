"""自助修改登录密码 E2E 测试（针对 pm-test2 @ localhost:9012）。

覆盖：
- 非管理员可自助修改自己的密码（SCRAM-SM3 校验当前密码）
- 修改后可用新密码登录
- 错误当前密码 → 401
- 新密码过短 → 400
- 管理员亦可自助修改自己的密码
"""
import json
import os
import struct
import urllib.request
import urllib.error

BASE = os.getenv("BASE", "http://localhost:9012")
ADMIN = "admin"
ADMIN_PW = "TestPass!2026"


# ── SM3（与前端 / 服务端一致，用于 SCRAM 计算）──
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
    A, B2, C, D, E, F, G, H = V
    for j in range(64):
        SS1 = _rotl(_rotl(A, 12) + E + _rotl(_tj(j), j % 32), 7) & 0xffffffff
        SS2 = SS1 ^ _rotl(A, 12)
        TT1 = (_ff(A, B2, C, j) + D + SS2 + W1[j]) & 0xffffffff
        TT2 = (_gg(E, F, G, j) + H + SS1 + W[j]) & 0xffffffff
        D = C
        C = _rotl(B2, 9)
        B2 = A
        A = TT1
        H = G
        G = _rotl(F, 19)
        F = E
        E = _p0(TT2)
    return [V[i] ^ v for i, v in enumerate([A, B2, C, D, E, F, G, H])]


def sm3_hex(d):
    V = _SM3_IV[:]
    bl = len(d) * 8
    m = bytearray(d)
    m.append(0x80)
    while len(m) % 64 != 56:
        m.append(0)
    m += struct.pack(">Q", bl)
    for i in range(0, len(m), 64):
        V = _cf(V, m[i:i + 64])
    return b"".join(struct.pack(">I", v) for v in V).hex()


def req(method, path, body=None, token=None):
    h = {}
    if token:
        h["Authorization"] = "Bearer " + token
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        h["Content-Type"] = "application/json"
    r = urllib.request.Request(BASE + path, data=data, method=method, headers=h)
    try:
        resp = urllib.request.urlopen(r, timeout=30)
        return resp.status, json.loads(resp.read() or b"null"), resp.headers
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"null"), e.headers


def scram_login(username, password):
    st, chal, _ = req("POST", "/api/auth/login/begin", {"username": username})
    if st == 409:
        st, b, _ = req("POST", "/api/auth/login", {"username": username, "password": password})
        return b["access_token"]
    T = sm3_hex(password.encode() + bytes.fromhex(chal["salt"]))
    proof = sm3_hex(bytes.fromhex(T) + bytes.fromhex(chal["nonce"]))
    st, b, _ = req("POST", "/api/auth/login/verify",
                   {"username": username, "nonce": chal["nonce"], "proof": proof})
    return b["access_token"]


def scram_change_pw(token, cur, new):
    st, begin, _ = req("POST", "/api/auth/change-password/begin", {}, token=token)
    assert st == 200, ("begin failed", st, begin)
    if begin.get("mode") == "scram" and begin.get("salt") and begin.get("nonce"):
        T = sm3_hex(cur.encode() + bytes.fromhex(begin["salt"]))
        proof = sm3_hex(bytes.fromhex(T) + bytes.fromhex(begin["nonce"]))
        payload = {"nonce": begin["nonce"], "proof": proof, "new_password": new}
    else:
        payload = {"current_password": cur, "new_password": new}
    return req("POST", "/api/auth/change-password/verify", payload, token=token)


def test_user_change():
    print("=== 自助修改密码 E2E ===")
    admin = scram_login(ADMIN, ADMIN_PW)

    # 1) 创建非管理员测试用户
    uname = "cp_tester"
    old_pw = "CpOld!2026"
    new_pw = "CpNew!2026"
    # 先清理可能的残留
    st, users, _ = req("GET", "/api/admin/users", token=admin)
    for u in users:
        if u["username"] == uname:
            req("DELETE", "/api/admin/users/" + str(u["id"]), token=admin)
    st, b, _ = req("POST", "/api/admin/users",
                   {"username": uname, "password": old_pw, "is_admin": False, "group_ids": []},
                   token=admin)
    assert st == 200, ("create user failed", st, b)
    print("1. 创建非管理员用户:", st, uname)

    # 2) 非管理员登录并自助改密
    tok = scram_login(uname, old_pw)
    st, b, _ = scram_change_pw(tok, old_pw, new_pw)
    assert st == 200, ("change pw failed", st, b)
    print("2. 非管理员自助改密:", st, b.get("message"))

    # 3) 用新密码可登录
    tok2 = scram_login(uname, new_pw)
    assert tok2, "新密码登录应成功"
    print("3. 新密码登录成功:", "ok")

    # 4) 错误当前密码 → 401
    st, b, _ = scram_change_pw(tok2, "Wrong!0000", "CpNew2!2026")
    assert st == 401, ("应 401", st, b)
    print("4. 错误当前密码 →", st, "(预期 401)")

    # 5) 新密码过短 → 400
    st, b, _ = scram_change_pw(tok2, new_pw, "short")
    assert st == 400, ("应 400", st, b)
    print("5. 新密码过短 →", st, "(预期 400)")

    # 6) 管理员亦可自助改密（改完还原，避免影响 dev 容器）
    st, b, _ = scram_change_pw(admin, ADMIN_PW, "TempAdmin!2026")
    assert st == 200, ("admin change failed", st, b)
    admin2 = scram_login(ADMIN, "TempAdmin!2026")
    assert admin2, "管理员新密码登录应成功"
    st, b, _ = scram_change_pw(admin2, "TempAdmin!2026", ADMIN_PW)
    assert st == 200, ("admin restore failed", st, b)
    print("6. 管理员自助改密 + 还原:", st)

    # 7) 清理
    st, users, _ = req("GET", "/api/admin/users", token=admin)
    for u in users:
        if u["username"] == uname:
            req("DELETE", "/api/admin/users/" + str(u["id"]), token=admin)
    print("7. 清理测试用户:", "ok")
    print("\nALL CHANGE-PW E2E PASS ✅")


if __name__ == "__main__":
    test_user_change()
