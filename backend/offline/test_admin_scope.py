import os, tempfile, secrets
os.environ["DATABASE_URL"] = "sqlite:///" + tempfile.mktemp(suffix=".db")
os.environ["ADMIN_USERNAME"] = "admin"
os.environ["ADMIN_PASSWORD"] = "Admin@123456"
os.environ["DEFAULT_GROUP_NAME"] = "默认分组"
os.environ["SECRET_KEY"] = "test-secret"

from app.db import Base, SessionLocal, engine
from app import models
Base.metadata.create_all(bind=engine)

from fastapi import FastAPI
from app.routers import admin, auth
app = FastAPI()
app.include_router(auth.router)
app.include_router(admin.mine_router)
app.include_router(admin.users_router)
app.include_router(admin.groups_router)
app.include_router(admin.audit_router)

from fastapi.testclient import TestClient
client = TestClient(app)

from app.security import hash_password

db = SessionLocal()
admin = models.User(username="admin", hashed_password=hash_password("Admin@123456"), is_admin=True)
db.add(admin)
for n in ["A", "B", "C"]:
    db.add(models.Group(name=n))
db.commit()
gA = db.query(models.Group).filter_by(name="A").first().id
gB = db.query(models.Group).filter_by(name="B").first().id
gC = db.query(models.Group).filter_by(name="C").first().id

# scoped admin over group A
scoped = models.User(username="scoped", hashed_password=hash_password("Scoped@123"), is_admin=True)
db.add(scoped); db.commit(); db.refresh(scoped)
db.execute(models.user_admin_groups.insert().values(user_id=scoped.id, group_id=gA))

# alice member of A and B
alice = models.User(username="alice", hashed_password=hash_password("Alice@123"), is_admin=False)
db.add(alice); db.commit(); db.refresh(alice)
db.execute(models.user_groups.insert().values(user_id=alice.id, group_id=gA))
db.execute(models.user_groups.insert().values(user_id=alice.id, group_id=gB))

# bob member of B only
bob = models.User(username="bob", hashed_password=hash_password("Bob@123"), is_admin=False)
db.add(bob); db.commit(); db.refresh(bob)
db.execute(models.user_groups.insert().values(user_id=bob.id, group_id=gB))
db.commit(); db.close()

def token(username, password):
    r = client.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, (username, r.status_code, r.text)
    return r.json()["access_token"]

def auth_h(token):
    return {"Authorization": "Bearer " + token}

def check(name, cond):
    print(("PASS" if cond else "FAIL"), "-", name)
    if not cond:
        global FAILED
        FAILED = True

FAILED = False

# ---- global admin ----
ta = token("admin", "Admin@123456")
me = client.get("/api/auth/me", headers=auth_h(ta)).json()
check("global admin is_global_admin true", me["is_global_admin"] is True)
grp = client.get("/api/admin/groups", headers=auth_h(ta)).json()
check("global admin sees all 3 groups", {g["name"] for g in grp} == {"A", "B", "C"})
usr = client.get("/api/admin/users", headers=auth_h(ta)).json()
check("global admin sees all 4 users", {u["username"] for u in usr} == {"admin", "scoped", "alice", "bob"})

# ---- scoped admin ----
ts = token("scoped", "Scoped@123")
me = client.get("/api/auth/me", headers=auth_h(ts)).json()
check("scoped admin is_global_admin false", me["is_global_admin"] is False)
check("scoped admin groups only A", {g["name"] for g in me["groups"]} == {"A"})
mine = client.get("/api/groups/mine", headers=auth_h(ts)).json()
check("scoped /groups/mine only A", {g["name"] for g in mine} == {"A"})
grp = client.get("/api/admin/groups", headers=auth_h(ts)).json()
check("scoped admin groups list only A", {g["name"] for g in grp} == {"A"})
usr = client.get("/api/admin/users", headers=auth_h(ts)).json()
check("scoped admin sees only scoped+alice", {u["username"] for u in usr} == {"scoped", "alice"})

# scoped admin cannot create admin
r = client.post("/api/admin/users", headers=auth_h(ts),
                json={"username": "evil", "password": "Evil@123", "is_admin": True})
check("scoped admin creating admin -> 403", r.status_code == 403)

# scoped admin cannot modify global admin
ga = [u for u in client.get("/api/admin/users", headers=auth_h(ta)).json() if u["username"] == "admin"][0]
r = client.put(f"/api/admin/users/{ga['id']}", headers=auth_h(ts), json={"is_admin": False})
check("scoped admin editing global admin -> 403", r.status_code == 403)

# scoped admin cannot manage group B
r = client.delete(f"/api/admin/groups/{gB}", headers=auth_h(ts))
check("scoped admin delete group B -> 403", r.status_code == 403)

# scoped admin creates a group -> auto added to scope
r = client.post("/api/admin/groups", headers=auth_h(ts),
                json={"name": "D", "description": "", "member_ids": []})
check("scoped admin create group D ok", r.status_code == 200)
grp = client.get("/api/admin/groups", headers=auth_h(ts)).json()
check("scoped admin now sees A and D", {g["name"] for g in grp} == {"A", "D"})

# ---- global admin creates a scoped admin via API (admin_group_ids) ----
r = client.post("/api/admin/users", headers=auth_h(ta),
                json={"username": "subadmin", "password": "Sub@12345", "is_admin": True, "admin_group_ids": [gB]})
check("global admin creates scoped admin subadmin", r.status_code == 200)
u = [x for x in client.get("/api/admin/users", headers=auth_h(ta)).json() if x["username"] == "subadmin"][0]
check("subadmin admin_groups = [B]", {g["name"] for g in u["admin_groups"]} == {"B"})
check("subadmin is_admin true", u["is_admin"] is True)

# subadmin login -> sees only B (plus member groups if any)
tsub = token("subadmin", "Sub@12345")
me = client.get("/api/auth/me", headers=auth_h(tsub)).json()
check("subadmin groups only B", {g["name"] for g in me["groups"]} == {"B"})

# ---- update: clear admin_group_ids makes global; set empty admin for non-admin clears ----
r = client.put(f"/api/admin/users/{u['id']}", headers=auth_h(ta),
               json={"admin_group_ids": []})
check("clear admin_group_ids -> still admin (global)", r.status_code == 200)
u2 = [x for x in client.get("/api/admin/users", headers=auth_h(ta)).json() if x["username"] == "subadmin"][0]
check("subadmin now global admin", u2["is_global_admin"] if "is_global_admin" in u2 else (u2["admin_groups"] == []) )

print("\nRESULT:", "ALL PASSED" if not FAILED else "SOME FAILED")
