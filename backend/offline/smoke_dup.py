import sys, json, hashlib, urllib.request, urllib.error

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:9019"
ok = 0
fail = 0

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
    if cond:
        ok += 1; print(f"  [PASS] {name}")
    else:
        fail += 1; print(f"  [FAIL] {name}")

print("=== 登录 admin ===")
tok = login("admin", "TestPass!2026")
check("admin 登录成功", bool(tok))

print("=== 准备分组 ===")
st, b = req("GET", "/api/admin/groups", token=tok)
groups = json.loads(b)
g1 = groups[0]["id"]
# 确保有第二个分组用于跨分组校验
g2 = None
for g in groups:
    if g["name"] == "smoke-dup-g2":
        g2 = g["id"]
if g2 is None:
    st, b = req("POST", "/api/admin/groups", {"name": "smoke-dup-g2", "desc": "dup test"}, token=tok)
    g2 = json.loads(b)["id"]
check("存在第二个分组(g2)", g2 is not None)

print("=== 问题4：重复新增拦截 ===")
# 1) 首次新增 (dupuser / symmetric / g1) → 200
st, b = req("POST", "/api/passwords",
    {"title": "dup", "username": "dupuser", "secret": "s3", "algorithm": "symmetric",
     "group_id": g1, "entry_password": "ep123456", "comment": "新增密码"}, token=tok)
check("首次新增 dupuser/symmetric/g1 = 200", st == 200)

# 2) 完全相同 (dupuser / symmetric / g1) → 409 + 明确文案
st, b = req("POST", "/api/passwords",
    {"title": "dup2", "username": "dupuser", "secret": "s3", "algorithm": "symmetric",
     "group_id": g1, "entry_password": "ep123456", "comment": "新增密码"}, token=tok)
check("重复 dupuser/symmetric/g1 = 409", st == 409)
check("409 文案含『请勿重复新增』", "请勿重复新增" in b)

# 3) 同名不同算法 (dupuser / gpg / g1) → 200（不误杀）
st, b = req("POST", "/api/passwords",
    {"title": "dupg", "username": "dupuser", "secret": "s3", "algorithm": "gpg",
     "group_id": g1, "entry_password": "ep123456", "comment": "新增密码"}, token=tok)
check("同名不同算法 dupuser/gpg/g1 = 200", st == 200)

# 4) 同算法不同名 (dupuser2 / symmetric / g1) → 200（不误杀）
st, b = req("POST", "/api/passwords",
    {"title": "dup3", "username": "dupuser2", "secret": "s3", "algorithm": "symmetric",
     "group_id": g1, "entry_password": "ep123456", "comment": "新增密码"}, token=tok)
check("同算法不同名 dupuser2/symmetric/g1 = 200", st == 200)

# 5) 同名同算法跨分组 (dupuser / symmetric / g2) → 200（不同租户不误杀）
st, b = req("POST", "/api/passwords",
    {"title": "dup4", "username": "dupuser", "secret": "s3", "algorithm": "symmetric",
     "group_id": g2, "entry_password": "ep123456", "comment": "新增密码"}, token=tok)
check("跨分组 dupuser/symmetric/g2 = 200", st == 200)

# 6) 大小写不敏感：DUPUSER / symmetric / g1 → 409
st, b = req("POST", "/api/passwords",
    {"title": "dup5", "username": "DUPUSER", "secret": "s3", "algorithm": "symmetric",
     "group_id": g1, "entry_password": "ep123456", "comment": "新增密码"}, token=tok)
check("大小写不敏感 DUPUSER/symmetric/g1 = 409", st == 409)

print(f"\n重复新增校验：{ok} 通过 / {fail} 失败")
sys.exit(1 if fail else 0)
