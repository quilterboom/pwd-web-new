import sys, requests

BASE = "http://localhost:9016"
ADMIN_U, ADMIN_P = "admin", "TestPass!2026"

def auth(u, p):
    r = requests.post(f"{BASE}/api/auth/login", json={"username": u, "password": p}, timeout=30)
    assert r.status_code == 200, (u, r.status_code, r.text)
    return r.json()["access_token"]

def H(t): return {"Authorization": "Bearer " + t}
def ck(name, cond):
    print(("PASS" if cond else "FAIL"), "-", name)
    if not cond: global FAILED; FAILED = True
FAILED = False

ta = auth(ADMIN_U, ADMIN_P)
ga = requests.post(f"{BASE}/api/admin/groups", headers=H(ta), json={"name": "MG_A", "description": "", "member_ids": []}, timeout=30).json()
gb = requests.post(f"{BASE}/api/admin/groups", headers=H(ta), json={"name": "MG_B", "description": "", "member_ids": []}, timeout=30).json()
gidA, gidB = ga["id"], gb["id"]

# merged model: create scoped admin with group_ids=[A] and admin_group_ids=[A]
r = requests.post(f"{BASE}/api/admin/users", headers=H(ta), json={
    "username": "mgr", "password": "Mgr@1234", "is_admin": True,
    "group_ids": [gidA], "admin_group_ids": [gidA]}, timeout=30)
ck("create merged scoped admin ok", r.status_code == 200)

# super admin: no groups at all
r = requests.post(f"{BASE}/api/admin/users", headers=H(ta), json={
    "username": "sup", "password": "Sup@1234", "is_admin": True,
    "group_ids": [], "admin_group_ids": []}, timeout=30)
ck("create super admin ok", r.status_code == 200)
ts = auth("sup", "Sup@1234")
me = requests.get(f"{BASE}/api/auth/me", headers=H(ts), timeout=30).json()
ck("super admin is_global_admin", me["is_global_admin"] is True)
ck("super admin sees MG_A & MG_B (default group also present)", {"MG_A", "MG_B"} <= {g["name"] for g in me["groups"]})

# scoped admin login -> only A
tm = auth("mgr", "Mgr@1234")
me = requests.get(f"{BASE}/api/auth/me", headers=H(tm), timeout=30).json()
ck("scoped admin is_global_admin false", me["is_global_admin"] is False)
ck("scoped admin groups only A", {g["name"] for g in me["groups"]} == {"MG_A"})

# verify membership: mgr is a member of A (single selector sets both)
grps = requests.get(f"{BASE}/api/admin/groups", headers=H(ta), timeout=30).json()
aobj = next(x for x in grps if x["name"] == "MG_A")
ck("mgr is member of A", "mgr" in {m["username"] for m in aobj["members"]})

# edit: change scoped admin to manage A+B via merged selector (group_ids both)
uid = next(u["id"] for u in requests.get(f"{BASE}/api/admin/users", headers=H(ta), timeout=30).json() if u["username"] == "mgr")
r = requests.put(f"{BASE}/api/admin/users/{uid}", headers=H(ta), json={
    "group_ids": [gidA, gidB], "admin_group_ids": [gidA, gidB]}, timeout=30)
ck("edit scoped admin to A+B ok", r.status_code == 200)
tm2 = auth("mgr", "Mgr@1234")
me = requests.get(f"{BASE}/api/auth/me", headers=H(tm2), timeout=30).json()
ck("scoped admin now sees A+B", {g["name"] for g in me["groups"]} == {"MG_A", "MG_B"})

# cleanup
requests.delete(f"{BASE}/api/admin/groups/{gidA}", headers=H(ta), timeout=30)
requests.delete(f"{BASE}/api/admin/groups/{gidB}", headers=H(ta), timeout=30)

print("\nRESULT:", "ALL PASSED" if not FAILED else "SOME FAILED")
sys.exit(1 if FAILED else 0)
