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

print("=== 重复新增拦截（按「密码文件名称 + 加密方式」判重）===")
# 1) 首次新增 (title=dup / symmetric / g1) → 200
st, b = req("POST", "/api/passwords",
    {"title": "dup", "username": "dupuser", "secret": "s3", "algorithm": "symmetric",
     "group_id": g1, "entry_password": "ep123456", "comment": "新增密码"}, token=tok)
check("首次新增 title=dup/symmetric/g1 = 200", st == 200)

# 2) 相同「密码文件名称 + 加密方式」但账号不同 (title=dup / dupuser2 / symmetric / g1) → 409
#    证明判重依据是密码文件名称而非账号
st, b = req("POST", "/api/passwords",
    {"title": "dup", "username": "dupuser2", "secret": "s3", "algorithm": "symmetric",
     "group_id": g1, "entry_password": "ep123456", "comment": "新增密码"}, token=tok)
check("重复 title=dup/symmetric/g1（不同账号）= 409", st == 409)
check("409 文案含『请勿重复新增』", "请勿重复新增" in b)
check("409 文案含『密码文件名称』", "密码文件名称" in b)

# 3) 同名不同算法 (title=dup / gpg / g1) → 200（加密方式不同不误杀）
st, b = req("POST", "/api/passwords",
    {"title": "dup", "username": "dupuser3", "secret": "s3", "algorithm": "gpg",
     "group_id": g1, "entry_password": "ep123456", "comment": "新增密码"}, token=tok)
check("同名不同算法 title=dup/gpg/g1 = 200", st == 200)

# 4) 同算法不同名 (title=dup3 / symmetric / g1) → 200（不误杀）
st, b = req("POST", "/api/passwords",
    {"title": "dup3", "username": "dupuser", "secret": "s3", "algorithm": "symmetric",
     "group_id": g1, "entry_password": "ep123456", "comment": "新增密码"}, token=tok)
check("同算法不同名 title=dup3/symmetric/g1 = 200", st == 200)

# 5) 同名同算法跨分组 (title=dup / symmetric / g2) → 200（不同分组不误杀）
st, b = req("POST", "/api/passwords",
    {"title": "dup", "username": "dupuser", "secret": "s3", "algorithm": "symmetric",
     "group_id": g2, "entry_password": "ep123456", "comment": "新增密码"}, token=tok)
check("跨分组 title=dup/symmetric/g2 = 200", st == 200)

# 6) 密码文件名称大小写不敏感：title=DUP / symmetric / g1 → 409
st, b = req("POST", "/api/passwords",
    {"title": "DUP", "username": "dupuser4", "secret": "s3", "algorithm": "symmetric",
     "group_id": g1, "entry_password": "ep123456", "comment": "新增密码"}, token=tok)
check("大小写不敏感 title=DUP/symmetric/g1 = 409", st == 409)

print("=== 编辑去重（改名成已存在项应被拦截）===")
# 编辑源：新增 title=edit-src / symmetric / g1 → 200
st, b = req("POST", "/api/passwords",
    {"title": "edit-src", "username": "editsrc", "secret": "s3", "algorithm": "symmetric",
     "group_id": g1, "entry_password": "ep123456", "comment": "编辑源"}, token=tok)
check("编辑源新增 title=edit-src/symmetric/g1 = 200", st == 200)
src_id = json.loads(b)["id"]
# 改名成已存在的 title=dup（同分组同算法，排除自身）→ 409
st, b = req("PUT", f"/api/passwords/{src_id}",
    {"title": "dup", "entry_password": "ep123456"}, token=tok)
check("编辑改名成已存在 title=dup/symmetric/g1 = 409", st == 409)
check("409 文案含『请勿重复』", "请勿重复" in b)
# 改名成不存在的名称 → 200（不误杀）
st, b = req("PUT", f"/api/passwords/{src_id}",
    {"title": "edit-new", "entry_password": "ep123456"}, token=tok)
check("编辑改名成新名称 edit-new = 200", st == 200)

print(f"\n重复新增/编辑校验：{ok} 通过 / {fail} 失败")
sys.exit(1 if fail else 0)
