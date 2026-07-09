"""端到端验证：删除密钥（OrgKey）与删除密码一致——后端生成审计记录。
在容器内运行：docker exec <c> python3 /tmp/smoke_keydelete.py http://localhost:9010
"""
import sys, json, urllib.request, urllib.error

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:9010"
fails = 0
def check(cond, msg):
    global fails
    print(("  ✅ " if cond else "  ❌ ") + msg)
    if not cond: fails += 1

def call(method, path, token=None, body=None):
    headers = {"Content-Type": "application/json"}
    if token: headers["Authorization"] = "Bearer " + token
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    try:
        resp = urllib.request.urlopen(r, timeout=30)
        return resp.status, json.loads(resp.read().decode() or "null")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or "null")

print("[1] 登录 admin")
st, d = call("POST", "/api/auth/login", body={"username": "admin", "password": "TestPass!2026"})
check(st == 200, f"登录 200 (got {st})")
token = d.get("access_token")

print("[2] 获取分组")
st, d = call("GET", "/api/groups/mine", token=token)
check(st == 200 and isinstance(d, list) and d, "groups/mine 返回分组")
gid = d[0]["id"]

print("[3] 生成 SM2 OrgKey（带唯一名）")
name = "待删密钥-" + str(abs(hash("smoke_keydelete")) % 100000)
st, d = call("POST", "/api/orgkeys/generate", token=token,
             body={"name": name, "algorithm": "sm2", "group_id": gid})
check(st == 200, f"生成 SM2 OrgKey 200 (got {st}: {d})")
kid = d.get("id")

print("[4] 删除该密钥（后端应写入审计记录）")
st, d = call("DELETE", f"/api/orgkeys/{kid}", token=token)
check(st == 200 and d.get("ok") is True, f"删除密钥 200 (got {st}: {d})")

print("[5] 审计日志应出现『删除密钥』记录且含密钥名")
st, d = call("GET", "/api/admin/audit?action=delete", token=token)
check(st == 200 and isinstance(d, list), f"审计日志 200 (got {st})")
hit = [r for r in d if r.get("comment", "").startswith("删除密钥") and r.get("title") == name]
check(bool(hit), f"审计含『删除密钥（名称：{name}）』记录 (命中 {len(hit)})")
if hit:
    print("     审计记录:", json.dumps(hit[0], ensure_ascii=False))

print("\n结果:", "全部通过 ✅" if fails == 0 else f"{fails} 项失败 ❌")
sys.exit(1 if fails else 0)
