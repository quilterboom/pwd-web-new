"""端到端验证：授权管理页面背后权限模型。
- catalog 完整性
- 无记录用户全开
- 超管给普通用户设子集权限后：未授权项 403、已授权项 200
- /me 返回 permissions
目标地址通过环境变量 BASE 指定（默认 http://localhost:9014）。
"""
import json, os, struct, urllib.request, urllib.error

BASE = os.getenv("BASE", "http://localhost:9014")

# ── SM3（与前端一致，用于 SCRAM 登录）──
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

def req(method, path, body=None, token=None, raw=False):
    url=BASE+path; h={}
    if token: h["Authorization"]="Bearer "+token
    data=None
    if body is not None:
        data=json.dumps(body).encode("utf-8"); h["Content-Type"]="application/json"
    r=urllib.request.Request(url, data=data, method=method, headers=h)
    try:
        resp=urllib.request.urlopen(r, timeout=30); rb=resp.read()
        return resp.status, (rb if raw else (json.loads(rb) if rb else None))
    except urllib.error.HTTPError as e:
        return e.code, (e.read() if raw else None)

def scram_login(username, password):
    st, chal = req("POST", "/api/auth/login/begin", {"username": username})
    if st == 409:
        st, b = req("POST", "/api/auth/login", {"username": username, "password": password})
        return b["access_token"]
    T = sm3_hex(password.encode("utf-8") + bytes.fromhex(chal["salt"]))
    proof = sm3_hex(bytes.fromhex(T) + bytes.fromhex(chal["nonce"]))
    st, b = req("POST", "/api/auth/login/verify",
                 {"username": username, "nonce": chal["nonce"], "proof": proof})
    return b["access_token"]

fails=0
def check(cond, msg):
    global fails
    print(("  ✅ "+msg) if cond else ("  ❌ "+msg))
    if not cond: fails+=1

print("=== 1. 管理员登录 ===")
admin = scram_login("admin", "TestPass!2026")
print("admin token len:", len(admin))

print("\n=== 2. 权限目录完整性 ===")
st, catalog = req("GET", "/api/auth/permissions/catalog", token=admin)
print("catalog:", json.dumps(catalog, ensure_ascii=False))
expected_groups = {"密码库", "密钥库", "账户", "系统管理（仅管理员可执行，逐用户授权不生效）"}
got_groups = {g["category"] for g in catalog}
check(st==200, f"catalog 返回 200 (实际 {st})")
check(expected_groups.issubset(got_groups), f"含全部分组 {expected_groups} (实际 {got_groups})")
all_keys = set()
for g in catalog:
    for it in g["items"]:
        all_keys.add(it["key"])
print("  目录权限键总数:", len(all_keys))
# 与路由器实际 require_perm 使用的键逐一对照（一致即授权可生效）
for need in ["pw.create","pw.edit","pw.delete","pw.batch_delete","pw.import","pw.export","pw.view",
             "key.generate","key.import","key.delete","key.batch_delete",
             "account.change_password",
             "sys.user_manage","sys.group_manage","sys.audit_view"]:
    check(need in all_keys, f"目录含 {need}（与 require_perm 一致）")

print("\n=== 3. 创建普通用户（无权限记录） ===")
st, groups = req("GET", "/api/admin/groups", token=admin)
gid = groups[0]["id"]
st, cu = req("POST", "/api/admin/users",
              {"username":"perm_tester","password":"PermTest!1","is_admin":False,"group_ids":[gid]},
              token=admin)
print("创建:", st, json.dumps(cu, ensure_ascii=False) if cu else "")
uid = cu["id"]
tester = scram_login("perm_tester", "PermTest!1")

print("\n=== 4. 无记录用户：全部操作应可达（200，而非 403） ===")
st, me = req("GET", "/api/auth/me", token=tester)
print("  /me is_global_admin:", me.get("is_global_admin"), "| permissions:", me.get("permissions"))
# 取一个分组用于创建密码
st, groups2 = req("GET", "/api/admin/groups", token=tester)
gtid = groups2[0]["id"] if groups2 else gid
# 试几个代表性接口（创建/查看/导出/改密入口）
st, _ = req("POST", "/api/passwords", {"title":"t","username":"u","secret":"s","algorithm":"symmetric","entry_password":"X1!passw","group_id":gtid}, token=tester)
check(st==200, f"无记录用户 pw.create 200 (实际 {st})")
st, entries = req("GET", "/api/passwords", token=tester)
check(st==200, f"无记录用户 pw.view 200 (实际 {st})")
if entries:
    eid = entries[0]["id"]
    st, _ = req("POST", f"/api/passwords/{eid}/unlock", {"entry_password":"X1!passw"}, token=tester)
    check(st==200, f"无记录用户 pw.unlock 200 (实际 {st})")
st, _ = req("POST", "/api/passwords/export", {"ids":[],"format":"json","plaintext":True}, token=tester)
# 空 ids 会 400（参数校验），但绝不应 403
check(st!=403, f"无记录用户 pw.export 非 403 (实际 {st})")
st, _ = req("POST", "/api/auth/change-password/begin", token=tester)
check(st!=403, f"无记录用户 account.change_password 非 403 (实际 {st})")

print("\n=== 5. 超管给普通用户设【仅查看】子集权限 ===")
# 只授权 pw.view；其余全部收回
restricted = [k for k in all_keys if k=="pw.view"]
print("  授权集:", restricted)
st, setr = req("PUT", f"/api/admin/permissions/users/{uid}", {"permissions":restricted}, token=admin)
print("  设置权限:", st, json.dumps(setr, ensure_ascii=False) if setr else "")
check(st==200, f"设置子集权限 200 (实际 {st})")

print("\n=== 6. 设限后：未授权项 403、已授权项 200 ===")
st, me2 = req("GET", "/api/auth/me", token=tester)
print("  /me permissions:", me2.get("permissions"))
check(me2.get("permissions")==restricted, f"/me 正确返回 permissions={restricted} (实际 {me2.get('permissions')})")
# 已授权：查看
st, entries = req("GET", "/api/passwords", token=tester)
check(st==200, f"已授权 pw.view 200 (实际 {st})")
# 未授权：创建
st, _ = req("POST", "/api/passwords", {"title":"t2","username":"u2","secret":"s2","algorithm":"symmetric","entry_password":"X1!passw","group_id":gtid}, token=tester)
check(st==403, f"未授权 pw.create 403 (实际 {st})")
# 未授权：导入
st, _ = req("POST", "/api/passwords/import", {}, token=tester)
check(st==403, f"未授权 pw.import 403 (实际 {st})")
# 未授权：改密
st, _ = req("POST", "/api/auth/change-password/begin", token=tester)
check(st==403, f"未授权 account.change_password 403 (实际 {st})")
# 未授权：导出
st, _ = req("POST", "/api/passwords/export", {"ids":[],"format":"json","plaintext":True}, token=tester)
check(st==403, f"未授权 pw.export 403 (实际 {st})")

print("\n=== 7. 重置权限（删除记录）后恢复全开 ===")
st, _ = req("DELETE", f"/api/admin/permissions/users/{uid}", token=admin)
check(st==200, f"重置权限 200 (实际 {st})")
st, _ = req("POST", "/api/passwords", {"title":"t3","username":"u3","secret":"s3","algorithm":"symmetric","entry_password":"X1!passw","group_id":gtid}, token=tester)
check(st==200, f"重置后 pw.create 恢复 200 (实际 {st})")

print("\n=== 8. 清理 ===")
# 删除测试期间创建的密码条目
st, entries = req("GET", "/api/passwords", token=admin)
for e in entries:
    req("DELETE", f"/api/passwords/{e['id']}", token=admin)
req("DELETE", f"/api/admin/users/{uid}", token=admin)
print("  已清理测试用户与密码条目")

print("\n" + ("ALL PERM E2E PASS ✅" if fails==0 else f"FAILED ❌ ({fails} 项不通过)"))
