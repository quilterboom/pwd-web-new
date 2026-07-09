import sys, json, hashlib, urllib.request, urllib.error

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:9021"
ok = 0; fail = 0

def req(method, path, body=None, token=None):
    data = json.dumps(body).encode() if body is not None else None
    h = {"Content-Type": "application/json"}
    if token: h["Authorization"] = "Bearer " + token
    r = urllib.request.Request(BASE + path, data=data, headers=h, method=method)
    try:
        resp = urllib.request.urlopen(r, timeout=15)
        return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()

def sm3_hex(b):
    h = hashlib.new("sm3"); h.update(b); return h.hexdigest()

def login(username, password):
    st, b = req("POST", "/api/auth/login/begin", {"username": username})
    if st == 409:
        st, b = req("POST", "/api/auth/login", {"username": username, "password": password})
        return json.loads(b)["access_token"]
    ch = json.loads(b)
    T = sm3_hex(password.encode() + bytes.fromhex(ch["salt"]))
    proof = sm3_hex(bytes.fromhex(T) + bytes.fromhex(ch["nonce"]))
    st, b = req("POST", "/api/auth/login/verify",
                 {"username": username, "nonce": ch["nonce"], "proof": proof})
    return json.loads(b)["access_token"]

def check(name, cond):
    global ok, fail
    if cond: ok += 1; print(f"  [PASS] {name}")
    else: fail += 1; print(f"  [FAIL] {name}")

print("=== 登录 admin ===")
tok = login("admin", "TestPass!2026")
check("admin 登录", bool(tok))

print("=== 准备：建两个 symmetric 条目（不同解密密码）===")
st, b = req("GET", "/api/admin/groups", token=tok)
g1 = json.loads(b)[0]["id"]
def add_pw(username, ep):
    st, b = req("POST", "/api/passwords",
        {"title": username, "username": username, "secret": "s3", "algorithm": "symmetric",
         "group_id": g1, "entry_password": ep, "comment": "新增密码"}, token=tok)
    return json.loads(b)["id"] if st == 200 else None
id1 = add_pw("exp_a", "pwAAAA1111")
id2 = add_pw("exp_b", "pwBBBB2222")
check("建 exp_a", id1 is not None)
check("建 exp_b", id2 is not None)

print("=== 问题1：解密失败则禁止导出并提示 ===")
# 两个条目用同一错误密码 → 两条都解密失败 → 应 400 拒绝
st, b = req("POST", "/api/passwords/export",
    {"ids": [id1, id2], "passwords": {str(id1): "WRONG", str(id2): "WRONG"},
     "format": "json", "plaintext": True}, token=tok)
check("全错密码导出 = 400", st == 400)
check("400 文案含『无法导出明文』", "无法导出明文" in b)
check("400 文案含失败账号 exp_a", "exp_a" in b)

# 其中一个对、一个错 → 只要有失败就整体拒绝
st, b = req("POST", "/api/passwords/export",
    {"ids": [id1, id2], "passwords": {str(id1): "pwAAAA1111", str(id2): "WRONG"},
     "format": "json", "plaintext": True}, token=tok)
check("部分错 → 400 拒绝", st == 400)

# 全部正确 → 200 正常导出
st, b = req("POST", "/api/passwords/export",
    {"ids": [id1, id2], "passwords": {str(id1): "pwAAAA1111", str(id2): "pwBBBB2222"},
     "format": "json", "plaintext": True}, token=tok)
check("全对 → 200 导出", st == 200)
if st == 200:
    payload = json.loads(b)
    check("导出含 2 条明文", payload.get("count") == 2)

# CSV 同理：全错应 400
st, b = req("POST", "/api/passwords/export",
    {"ids": [id1, id2], "passwords": {str(id1): "WRONG", str(id2): "WRONG"},
     "format": "csv", "plaintext": True}, token=tok)
check("CSV 全错 → 400", st == 400)

print(f"\n导出解密失败拦截：{ok} 通过 / {fail} 失败")
sys.exit(1 if fail else 0)
