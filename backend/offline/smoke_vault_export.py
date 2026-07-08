"""验证 2026-07-08 五项改动中的后端接口：
1) 文件保险箱接口已移除（GET /api/files -> 404）
2) 查看受「解密密码」保护的条目必须用 POST /api/passwords/{id}/unlock（密码不在 URL）
3) 正确密码 -> 明文；错误密码 -> 401
4) 批量导出：加密备份（含密文、无明文）/ 明文导出（需各条目密码）
5) 旧式无密码条目 GET /{id} 仍可直接查看
"""
import json
import urllib.request
import urllib.error

BASE = "http://localhost:9010"
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
    url = BASE + path
    data = None
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    if body is not None:
        if isinstance(body, (dict, list)):
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        else:
            data = body
    r = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(r) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def login():
    st, body = req("POST", "/api/auth/login", body={"username": ADMIN, "password": ADMIN_PW})
    assert st == 200, f"login {st}"
    return json.loads(body)["access_token"]


def get_admin_id(token):
    st, body = req("GET", "/api/admin/users", token=token)
    users = json.loads(body)
    return next(u["id"] for u in users if u["username"] == ADMIN)


def ensure_group(token, name):
    st, body = req("GET", "/api/admin/groups", token=token)
    for g in json.loads(body):
        if g["name"] == name:
            return g["id"]
    st, body = req("POST", "/api/admin/groups", token=token,
                    body={"name": name, "description": "", "member_ids": []})
    assert st == 200, f"create group {st}"
    return json.loads(body)["id"]


def main():
    token = login()
    admin_id = get_admin_id(token)
    gid = ensure_group(token, "smoke_vault")
    print(f"[*] admin_id={admin_id} group_id={gid}")

    # 1) 文件保险箱接口已移除
    st, _ = req("GET", "/api/files", token=token)
    check("文件保险箱接口已移除 GET /api/files -> 404", st == 404, f"got {st}")

    # 建两条对称条目（不同解密密码）
    pw_a, pw_b = "PassA!2026", "PassB!2026"
    st, body = req("POST", "/api/passwords", token=token, body={
        "username": "acct_a", "secret": "secret-A", "notes": "", "comment": "",
        "group_id": gid, "algorithm": "symmetric", "entry_password": pw_a,
    })
    check("新增条目A", st == 200, f"got {st} {body}")
    id_a = json.loads(body)["id"]

    st, body = req("POST", "/api/passwords", token=token, body={
        "username": "acct_b", "secret": "secret-B", "notes": "", "comment": "",
        "group_id": gid, "algorithm": "symmetric", "entry_password": pw_b,
    })
    check("新增条目B", st == 200, f"got {st} {body}")
    id_b = json.loads(body)["id"]

    # 2) 受密码保护条目：GET /{id} 应被拒并提示用 unlock
    st, body = req("GET", f"/api/passwords/{id_a}", token=token)
    check("GET /{id}(受密码保护) 不在 URL 传密码 -> 4xx", st in (400, 401), f"got {st} {body}")

    # 3) POST /unlock 正确密码 -> 明文
    st, body = req("POST", f"/api/passwords/{id_a}/unlock", token=token,
                   body={"entry_password": pw_a})
    ok = st == 200 and json.loads(body).get("secret") == "secret-A"
    check("POST /unlock 正确密码 -> 明文", ok, f"got {st} {body}")

    # 3b) POST /unlock 错误密码 -> 401
    st, _ = req("POST", f"/api/passwords/{id_a}/unlock", token=token,
                body={"entry_password": "wrong"})
    check("POST /unlock 错误密码 -> 401", st == 401, f"got {st}")

    # 4) 批量导出：加密备份（含密文、无明文）
    st, body = req("POST", "/api/passwords/export", token=token, body={
        "ids": [id_a, id_b], "passwords": {}, "format": "json", "plaintext": False,
    })
    export_ok = st == 200
    if export_ok:
        payload = json.loads(body)
        rows = payload.get("entries", [])
        has_cipher = all(("ciphertext" in r) for r in rows) and len(rows) == 2
        no_plain = all(("secret" not in r) for r in rows)
        export_ok = has_cipher and no_plain
    check("批量导出 加密备份(含密文/无明文)", export_ok, f"got {st} {body[:200]}")

    # 4b) 明文导出（提供各条目密码）
    st, body = req("POST", "/api/passwords/export", token=token, body={
        "ids": [id_a, id_b], "passwords": {str(id_a): pw_a, str(id_b): pw_b},
        "format": "json", "plaintext": True,
    })
    plain_ok = st == 200
    if plain_ok:
        rows = json.loads(body).get("entries", [])
        plain_ok = {r["id"]: r.get("secret") for r in rows} == {id_a: "secret-A", id_b: "secret-B"}
    check("批量导出 明文(密码正确)", plain_ok, f"got {st} {body[:200]}")

    # 4c) 明文导出但密码错误 -> 该条 secret 为 null
    st, body = req("POST", "/api/passwords/export", token=token, body={
        "ids": [id_a], "passwords": {str(id_a): "bad"}, "format": "json", "plaintext": True,
    })
    bad_ok = st == 200 and json.loads(body)["entries"][0].get("secret") is None
    check("批量导出 明文(密码错误 -> null)", bad_ok, f"got {st} {body[:200]}")

    # 5) 新设计：gpg/sm2 也必须填「解密密码」（需求 2/3）。缺解密密码创建 gpg 应被拒。
    st, body = req("POST", "/api/passwords", token=token, body={
        "username": "no_pw_gpg", "secret": "x", "notes": "", "comment": "",
        "group_id": gid, "algorithm": "gpg",
    })
    check("gpg 缺解密密码 -> 400（强制要求解密密码）", st == 400, f"got {st} {body}")

    # 5b) gpg 带解密密码 -> 创建成功，且受密码保护（GET 被拒，需 unlock）
    st, body = req("POST", "/api/passwords", token=token, body={
        "username": "gpg_c", "secret": "secret-C", "notes": "", "comment": "",
        "group_id": gid, "algorithm": "gpg", "entry_password": "GpgPw!2026",
    })
    check("新增 gpg 条目(带解密密码)", st == 200, f"got {st} {body}")
    if st == 200:
        id_c = json.loads(body)["id"]
        st, _ = req("GET", f"/api/passwords/{id_c}", token=token)
        check("gpg 条目 GET /{id} 受保护 -> 4xx", st in (400, 401), f"got {st}")
        st, body = req("POST", f"/api/passwords/{id_c}/unlock", token=token,
                       body={"entry_password": "GpgPw!2026"})
        check("gpg 条目 POST /unlock 正确密码 -> 明文", st == 200 and json.loads(body).get("secret") == "secret-C",
              f"got {st} {body[:200]}")

    print(f"\n结果: {passed} 通过, {failed} 失败")
    raise SystemExit(1 if failed else 0)


if __name__ == "__main__":
    main()
