import sys, requests, json

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:9015"
ADMIN_U, ADMIN_P = "admin", "TestPass!2026"

def auth(u, p):
    r = requests.post(f"{BASE}/api/auth/login", json={"username": u, "password": p}, timeout=30)
    assert r.status_code == 200, (u, r.status_code, r.text)
    return r.json()["access_token"]

def H(t): return {"Authorization": "Bearer " + t}

def ck(name, cond):
    print(("PASS" if cond else "FAIL"), "-", name)
    if not cond:
        global FAILED; FAILED = True

FAILED = False
ta = auth(ADMIN_U, ADMIN_P)
me = requests.get(f"{BASE}/api/auth/me", headers=H(ta), timeout=30).json()
ck("admin is_global_admin", me["is_global_admin"] is True)

# create groups A, B
ga = requests.post(f"{BASE}/api/admin/groups", headers=H(ta), json={"name": "E2E_A", "description": "", "member_ids": []}, timeout=30).json()
gb = requests.post(f"{BASE}/api/admin/groups", headers=H(ta), json={"name": "E2E_B", "description": "", "member_ids": []}, timeout=30).json()
gidA, gidB = ga["id"], gb["id"]

# normal user member of both
requests.post(f"{BASE}/api/admin/users", headers=H(ta), json={"username": "e2euser", "password": "User@12345", "is_admin": False, "group_ids": [gidA, gidB]}, timeout=30)

# scoped admin over A
r = requests.post(f"{BASE}/api/admin/users", headers=H(ta), json={"username": "e2eadmin", "password": "Adm@12345", "is_admin": True, "admin_group_ids": [gidA]}, timeout=30)
ck("create scoped admin ok", r.status_code == 200)
ts = auth("e2eadmin", "Adm@12345")
me = requests.get(f"{BASE}/api/auth/me", headers=H(ts), timeout=30).json()
ck("scoped admin is_global_admin false", me["is_global_admin"] is False)
ck("scoped admin groups only A", {g["name"] for g in me["groups"]} == {"E2E_A"})

grp = requests.get(f"{BASE}/api/admin/groups", headers=H(ts), timeout=30).json()
ck("scoped admin group list only A", {g["name"] for g in grp} == {"E2E_A"})

usr = requests.get(f"{BASE}/api/admin/users", headers=H(ts), timeout=30).json()
ck("scoped admin users sees e2euser (shares A)", "e2euser" in {u["username"] for u in usr})
ck("scoped admin users excludes itself? includes self", "e2eadmin" in {u["username"] for u in usr})

# scoped admin cannot create admin
r = requests.post(f"{BASE}/api/admin/users", headers=H(ts), json={"username": "evil", "password": "Evil@123", "is_admin": True}, timeout=30)
ck("scoped admin create admin -> 403", r.status_code == 403)

# scoped admin cannot delete group B
r = requests.delete(f"{BASE}/api/admin/groups/{gidB}", headers=H(ts), timeout=30)
ck("scoped admin delete B -> 403", r.status_code == 403)

# group edit returns members (so frontend member list populates)
r = requests.put(f"{BASE}/api/admin/groups/{gidA}", headers=H(ta), json={"member_ids": [next(u["id"] for u in requests.get(f"{BASE}/api/admin/users", headers=H(ta), timeout=30).json() if u["username"] == "e2euser")]}, timeout=30)
ck("admin added e2euser to group A", r.status_code == 200)
g = requests.get(f"{BASE}/api/admin/groups", headers=H(ta), timeout=30).json()
ga_obj = next(x for x in g if x["name"] == "E2E_A")
ck("group A now has 1 member", ga_obj["member_count"] == 1 and ga_obj["members"][0]["username"] == "e2euser")

# scoped admin sees that member in edit payload too
g2 = requests.get(f"{BASE}/api/admin/groups", headers=H(ts), timeout=30).json()
ga2 = next(x for x in g2 if x["name"] == "E2E_A")
ck("scoped admin group A shows member e2euser", any(m["username"] == "e2euser" for m in ga2["members"]))

# cleanup
requests.delete(f"{BASE}/api/admin/groups/{gidA}", headers=H(ta), timeout=30)
requests.delete(f"{BASE}/api/admin/groups/{gidB}", headers=H(ta), timeout=30)

print("\nRESULT:", "ALL PASSED" if not FAILED else "SOME FAILED")
sys.exit(1 if FAILED else 0)
