"""验证 2026-07-08 新增：修改记录字段名汉化。

1. 创建条目 → 修改「账号 + 密码明文 + 解密密码」 → 查询 history
2. history.comment 应直接是中文标签，且不含英文字段名残留
"""
import json
import urllib.request
import urllib.error

BASE = "http://localhost:9012"
ADMIN = "admin"
ADMIN_PW = "TestPass!2026"

passed = 0
failed = 0


def check(name, cond, extra=""):
    global passed, failed
    if cond:
        passed += 1
        print(f"  PASS  {name}")
    else:
        failed += 1
        print(f"  FAIL  {name}  {extra}")


def req(method, path, token=None, body=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(r) as resp:
            raw = resp.read().decode()
            try: return resp.status, json.loads(raw) if raw else None
            except: return resp.status, raw
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try: return e.code, json.loads(raw) if raw else None
        except: return e.code, raw


# 登录
status, data = req("POST", "/api/auth/login", body={"username": ADMIN, "password": ADMIN_PW})
check("登录 200", status == 200 and data)
token = data["access_token"]

# 取分组
status, me = req("GET", "/api/auth/me", token=token)
gid = me["groups"][0]["id"]
print(f"  [info] admin in group_id={gid}")

# 创建条目
status, created = req("POST", "/api/passwords", token=token, body={
    "username": "alice@历史测试",
    "secret": "原始明文-001",
    "group_id": gid,
    "entry_password": "oldPwd!1",
    "comment": "首次创建"
})
check("创建条目", status == 200 and created)
pid = created["id"]

# 修改：账号 + 密码明文 + 解密密码 → comment 留空让后端自动生成
status, upd = req("PUT", f"/api/passwords/{pid}", token=token, body={
    "username": "alice@历史测试-renamed",
    "secret": "新明文-002",
    "entry_password": "oldPwd!1",
    "new_entry_password": "newPwd!2",
})
check("修改条目", status == 200 and upd)

# 再改一次：备注 + 算法切换（仍走 symmetric），触发纯字段变更
status, me2 = req("GET", "/api/auth/me", token=token)  # 避免后续 401（无关）
status, upd2 = req("PUT", f"/api/passwords/{pid}", token=token, body={
    "notes": "加备注",
    "entry_password": "newPwd!2",
    "comment": "本轮我手动写了说明",
})
check("再次修改", status == 200 and upd2)

# 拉 history
status, rows = req("GET", f"/api/passwords/{pid}/history", token=token)
check("拉 history", status == 200 and isinstance(rows, list) and len(rows) >= 3)
print(f"  [info] history rows = {len(rows)}")
for r in rows:
    print(f"    - [{r['action']}] {r['changed_at'][:19]} comment={r['comment']!r}")

# 断言：comment 字段里不应出现英文字段名（title/username/notes/secret/entry_password/algorithm/orgkey_id）
ENGLISH_FIELDS = ("title", "username", "notes", "secret", "entry_password", "algorithm", "orgkey_id")
english_leak = []
for r in rows:
    c = r.get("comment", "")
    for ef in ENGLISH_FIELDS:
        # 只看中文描述里夹的英文；首尾允许（如 comment="删除密码"）单个英文单词作为独立字段
        # 更严格：查 "修改了 X,..." 中的 X、或 ",X" 形式
        for tok in (f"{ef},", f",{ef}", f"修改了 {ef}", f", {ef}", f"{ef} "):
            if tok in c:
                english_leak.append((r["action"], c, tok))
check("无英文字段名残留", not english_leak, str(english_leak))

# 断言：至少有 1 条 comment 含「修改了」+ 中文
mod_zh = [r["comment"] for r in rows if r["action"] == "update" and r["comment"].startswith("修改了") and any('\u4e00' <= ch <= '\u9fff' for ch in r["comment"])]
check("修改 comment 为中文描述", bool(mod_zh), mod_zh)

# 断言：用户手动写的 comment 应原样保留（不被改写）
manual_kept = any(r["comment"] == "本轮我手动写了说明" for r in rows)
check("用户手动 comment 原样保留", manual_kept)

print(f"\n结果: {passed} 通过, {failed} 失败")
exit(0 if failed == 0 else 1)
