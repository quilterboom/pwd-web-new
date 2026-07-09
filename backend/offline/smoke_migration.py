#!/usr/bin/env python3
"""回归测试：离线镜像的「启动自动迁移」必须保证旧库（缺列）也能正常服务。

重点覆盖用户上报的两个 500/锁定类问题：
  1) GET /api/passwords 在部署库缺少 passwords.deleted 等列时不再 500
     （db._migrate_columns 现在通用地补齐所有缺失模型列）。
  2) 删除记录写入 History（action=delete）且管理员审计日志可查。

用法：
  python3 smoke_migration.py [BASE_URL]        # 默认 http://localhost:9010
需在运行中的容器里执行（镜像自带 SM3 / GPG / SM2 依赖）。
管理员账号：环境变量 ADMIN_PASSWORD 指定，默认 admin123。
"""
import sys, json, hashlib, urllib.request, urllib.error

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:9010"
ADMIN_PW = "TestPass!2026"


def req(method, path, body=None, token=None):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    r = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    try:
        resp = urllib.request.urlopen(r, timeout=20)
        return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def sm3_hex(b: bytes) -> str:
    h = hashlib.new("sm3")
    h.update(b)
    return h.hexdigest()


def login(username, password):
    st, b = req("POST", "/api/auth/login/begin", {"username": username})
    if st == 409:
        # 旧账号尚未迁移 → 明文 /login 一次性迁移（前端 doLogin 同款回退）
        st, b = req("POST", "/api/auth/login", {"username": username, "password": password})
        assert st == 200, f"迁移登录失败 {st} {b}"
        return json.loads(b)["access_token"]
    ch = json.loads(b)
    T = sm3_hex(password.encode() + bytes.fromhex(ch["salt"]))
    proof = sm3_hex(bytes.fromhex(T) + bytes.fromhex(ch["nonce"]))
    st, b = req("POST", "/api/auth/login/verify",
                {"username": username, "nonce": ch["nonce"], "proof": proof})
    assert st == 200, f"登录失败 {st} {b}"
    return json.loads(b)["access_token"]


passed = 0
failed = 0


def check(name, cond, extra=""):
    global passed, failed
    if cond:
        passed += 1
        print(f"  [PASS] {name}")
    else:
        failed += 1
        print(f"  [FAIL] {name} {extra}")


print("=== 1. 管理员登录 ===")
tok = login("admin", ADMIN_PW)
check("admin 登录拿到 token", bool(tok))

print("=== 2. GET /api/passwords 必须 200（回归：旧库缺列曾导致 500）===")
st, b = req("GET", "/api/passwords", token=tok)
check("GET /api/passwords == 200", st == 200, f"实际 {st}: {b[:160]}")
rows = json.loads(b) if st == 200 else []
check("返回的是数组", isinstance(rows, list))

print("=== 3. 新建分组 + 密码，确认能落库并被列出 ===")
st, b = req("POST", "/api/admin/groups", {"name": "迁移测试组"}, token=tok)
gid = json.loads(b)["id"] if st == 200 else 1
st, b = req("POST", "/api/passwords", {
    "title": "迁移回归账号", "username": "muser", "secret": "s3cr3t",
    "entry_password": "epw", "algorithm": "symmetric", "group_id": gid,
    "comment": "新增密码",
}, token=tok)
check("创建密码 == 200", st == 200, f"实际 {st} {b[:120]}")
st, b = req("GET", "/api/passwords", token=tok)
rows = json.loads(b) if st == 200 else []
check("列表包含新建账号", any(r.get("username") == "muser" for r in rows), f"rows={rows}")

print("=== 4. 删除该密码，审计日志应出现 action=delete 记录 ===")
pid = next((r["id"] for r in rows if r.get("username") == "muser"), None)
st, b = req("DELETE", f"/api/passwords/{pid}", token=tok)
check("删除密码 == 200", st == 200, f"实际 {st} {b[:120]}")
st, b = req("GET", "/api/admin/audit?action=delete", token=tok)
check("审计日志(delete) == 200", st == 200, f"实际 {st} {b[:160]}")
aud = json.loads(b) if st == 200 else []
check("删除记录存在且含账号说明",
      any(a.get("username") == "muser" and "删除密码" in (a.get("comment") or "") for a in aud),
      f"aud={aud}")

print("=== 5. 非管理员不能看审计日志（权限）===")
st, b = req("POST", "/api/admin/users", {
    "username": "viewer", "password": "ViewPass!2026", "is_admin": False, "group_ids": [gid]
}, token=tok)
check("创建普通用户 == 200", st == 200, f"实际 {st} {b[:120]}")
vtok = login("viewer", "ViewPass!2026")
st, b = req("GET", "/api/admin/audit", token=vtok)
check("普通用户访问审计日志 == 403", st == 403, f"实际 {st} {b[:120]}")

print(f"\n=== 结果：{passed} 通过, {failed} 失败 ===")
sys.exit(1 if failed else 0)
