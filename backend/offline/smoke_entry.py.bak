import json, urllib.request, urllib.error, sys, time

BASE = "http://127.0.0.1:9010"
ADMIN = "admin"
ADMIN_PW = "TestPass!2026"

def req(method, path, token=None, data=None):
    url = BASE + path
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    body = json.dumps(data).encode() if data is not None else None
    r = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
    except Exception as e:
        return -1, str(e)

passed = 0
failed = 0
def check(name, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("PASS:", name)
    else:
        failed += 1
        print("FAIL:", name, "|", detail)

def unlock(tok, pid, pw):
    """POST /unlock（密码在请求体，不在 URL）解密查看。"""
    return req("POST", f"/api/passwords/{pid}/unlock", token=tok, data={"entry_password": pw})

# 1. login
st, body = req("POST", "/api/auth/login", data={"username": ADMIN, "password": ADMIN_PW})
check("login 200", st == 200, f"status={st} body={body}")
if st != 200:
    print("RESULT: passed=%d failed=%d" % (passed, failed))
    sys.exit(1)
tok = json.loads(body)["access_token"]

# 2. /me admin
st, body = req("GET", "/api/auth/me", token=tok)
check("me is_admin", st == 200 and json.loads(body).get("is_admin") is True, f"body={body}")

# 3. create group (幂等：已存在则复用)
st, body = req("POST", "/api/admin/groups", token=tok, data={"name": "smoke-group", "description": "smoke"})
if st == 409:
    st, body = req("GET", "/api/admin/groups", token=tok)
    existing = next((g for g in json.loads(body) if g["name"] == "smoke-group"), None)
    st = 200 if existing else st
    body = json.dumps(existing) if existing else body
check("create group", st == 200, f"status={st} body={body}")
gid = json.loads(body)["id"]

# 4. create entry (symmetric / entry scheme)
st, body = req("POST", "/api/passwords", token=tok, data={
    "username": "alice", "secret": "SUPER-SECRET-123", "group_id": gid,
    "algorithm": "symmetric", "entry_password": "entry-pw-1", "comment": "smoke create"
})
check("create entry symmetric", st == 200, f"status={st} body={body}")
pid = json.loads(body)["id"]

# 5. get without entry_password -> 400
st, _ = req("GET", f"/api/passwords/{pid}", token=tok)
check("get without entry_password -> 400", st == 400, f"status={st}")

# 6. get wrong entry_password -> 401
st, _ = unlock(tok, pid, "WRONG")
check("get wrong entry_password -> 401", st == 401, f"status={st}")

# 7. get correct entry_password -> secret
st, body = unlock(tok, pid, "entry-pw-1")
check("get correct entry_password -> secret", st == 200 and json.loads(body).get("secret") == "SUPER-SECRET-123", f"status={st} body={body}")

# 8. update entry with new entry_password
st, body = req("PUT", f"/api/passwords/{pid}", token=tok, data={
    "secret": "NEW-SECRET-456", "entry_password": "entry-pw-1", "new_entry_password": "entry-pw-2", "comment": "smoke update"
})
check("update entry", st == 200, f"status={st} body={body}")

# 9. old password fails, new works
st, _ = unlock(tok, pid, "entry-pw-1")
check("old entry_password now fails -> 401", st == 401, f"status={st}")
st, body = unlock(tok, pid, "entry-pw-2")
check("new entry_password decrypts", st == 200 and json.loads(body).get("secret") == "NEW-SECRET-456", f"status={st} body={body}")

# 10. history >= 2
st, body = req("GET", f"/api/passwords/{pid}/history", token=tok)
check("history >= 2", st == 200 and len(json.loads(body)) >= 2, f"status={st} body={body}")

# 11. keys status
st, body = req("GET", "/api/keys/status", token=tok)
check("keys status dict", st == 200 and isinstance(json.loads(body), dict), f"status={st} body={body}")

# 12. generate OrgKey (gpg)
st, body = req("POST", "/api/orgkeys/generate", token=tok, data={
    "name": "smoke-orgkey", "algorithm": "gpg", "group_id": gid, "comment": "smoke"
})
check("generate OrgKey gpg", st == 200, f"status={st} body={body}")
kid = json.loads(body).get("id") if st == 200 else None

# 13. list orgkeys includes it
if kid is not None:
    st, body = req("GET", "/api/orgkeys", token=tok)
    check("orgkey listed", st == 200 and any(k.get("id") == kid for k in json.loads(body)), f"status={st} body={body}")

    # 14. legacy(hybrid) gpg entry using orgkey + 解密密码, decrypt via private + 解密密码
    st, body = req("POST", "/api/passwords", token=tok, data={
        "username": "bob", "secret": "LEGACY-SECRET", "group_id": gid,
        "algorithm": "gpg", "orgkey_id": kid, "entry_password": "bob-pw", "comment": "smoke legacy"
    })
    check("create legacy gpg entry with orgkey + 解密密码", st == 200, f"status={st} body={body}")
    if st == 200:
        lid = json.loads(body)["id"]
        st, body = unlock(tok, lid, "bob-pw")
        check("decrypt legacy gpg entry via orgkey private + 解密密码", st == 200 and json.loads(body).get("secret") == "LEGACY-SECRET", f"status={st} body={body}")
        st, _ = req("GET", f"/api/passwords/{lid}", token=tok)
        check("legacy gpg entry 缺解密密码被拒", st in (400, 401), f"status={st}")

# 15. unauthorized (no token) -> 401
st, _ = req("GET", "/api/passwords")
check("no token -> 401", st == 401, f"status={st}")

print("RESULT: passed=%d failed=%d" % (passed, failed))
sys.exit(1 if failed else 0)
