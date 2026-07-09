"""端到端验证：rebuilt 镜像中导入外部密钥（含子密钥/受口令保护）的行为。
在容器内运行：docker exec keymoke python3 /tmp/smoke_keyimport.py
"""
import sys, json, types, urllib.request, urllib.error

if "imghdr" not in sys.modules:
    m = types.ModuleType("imghdr"); m.what = lambda f, h=None: None
    sys.modules["imghdr"] = m
import pgpy
from pgpy.constants import KeyFlags, PubKeyAlgorithm, SymmetricKeyAlgorithm, HashAlgorithm

BASE = "http://localhost:9010"
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


def unlock(tok, pid, pw):
    """POST /unlock（密码在请求体，不在 URL）解密查看。"""
    return call("POST", f"/api/passwords/{pid}/unlock", token=tok, body={"entry_password": pw})

print("[2] 获取分组")
st, d = call("GET", "/api/groups/mine", token=token)
check(st == 200 and isinstance(d, list) and d, f"groups/mine 返回分组 (got {st})")
gid = d[0]["id"]

def gen_key(protect=None):
    k = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
    k.add_uid(pgpy.PGPUID.new("t", email="t@t"), usage={KeyFlags.Certify, KeyFlags.Sign},
              hashes=[HashAlgorithm.SHA256], ciphers=[SymmetricKeyAlgorithm.AES256])
    sub = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
    k.add_subkey(sub, usage={KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage})
    if protect:
        k.protect(protect, SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)
        for sk in k.subkeys.values():
            sk.protect(protect, SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)
    return str(k.pubkey), str(k)

print("[3] 生成未受保护(含子密钥)的外部密钥并导入 -> 期望 200")
pub, priv = gen_key()
st, d = call("POST", "/api/orgkeys/import", token=token,
             body={"name": "外部子密钥密钥", "algorithm": "gpg", "group_id": gid,
                   "public_key": pub, "private_key": priv})
check(st == 200, f"导入未受保护密钥 200 (got {st}: {d})")
check(d.get("has_private") is True, "返回 has_private=True")
imported_id = d.get("id")

print("[4] 端到端：用该导入密钥创建密码条目并读回")
st, d = call("POST", "/api/passwords", token=token,
             body={"title": "e2e", "algorithm": "gpg", "group_id": gid,
                   "orgkey_id": imported_id, "entry_password": "ep123",
                   "secret": "端到端-中文-secret"})
check(st == 200, f"创建条目 200 (got {st}: {d})")
pid = d.get("id")
st, d = unlock(token, pid, "ep123")
check(st == 200 and d.get("secret") == "端到端-中文-secret", f"用正确解密密码读回明文匹配 (got {st}: {d.get('secret')!r})")
st, d = unlock(token, pid, "wrong")
check(st == 401, f"错误解密密码被拒 401 (got {st})")

print("[5] 生成受口令保护的外部密钥并导入 -> 期望 400 清晰提示")
pub2, priv2 = gen_key(protect="pw123")
st, d = call("POST", "/api/orgkeys/import", token=token,
             body={"name": "受保护密钥", "algorithm": "gpg", "group_id": gid,
                   "public_key": pub2, "private_key": priv2})
check(st == 400, f"导入受保护密钥 400 (got {st})")
detail = (d.get("detail") or "") if isinstance(d, dict) else ""
check("受口令保护" in detail, f"错误提示含'受口令保护' (detail={detail!r})")

print("[6] 生成 SM2 OrgKey 并创建条目 -> 此前会因 passphrase 形参报错 500")
st, d = call("POST", "/api/orgkeys/generate", token=token,
             body={"name": "SM2回归密钥", "algorithm": "sm2", "group_id": gid})
check(st == 200, f"生成 SM2 OrgKey 200 (got {st}: {d})")
sm2_id = d.get("id")

st, d = call("POST", "/api/passwords", token=token,
             body={"title": "sm2-e2e", "algorithm": "sm2", "group_id": gid,
                   "orgkey_id": sm2_id, "entry_password": "ep123",
                   "secret": "SM2-中文-secret"})
check(st == 200, f"用 SM2 OrgKey 创建条目 200 (got {st}: {d})")
pid2 = d.get("id")
st, d = unlock(token, pid2, "ep123")
check(st == 200 and d.get("secret") == "SM2-中文-secret", f"SM2 OrgKey 解密读回明文匹配 (got {st}: {d.get('secret')!r})")

print("[7] 导入受口令 GPG 密钥时传入正确口令 -> 期望 200（验证 passphrase 形参对 GPG 仍生效）")
st, d = call("POST", "/api/orgkeys/import", token=token,
             body={"name": "受保护密钥(带口令)", "algorithm": "gpg", "group_id": gid,
                   "public_key": pub2, "private_key": priv2, "private_passphrase": "pw123"})
check(st == 200, f"带正确口令导入受保护 GPG 密钥 200 (got {st}: {d})")

print("\n结果:", "全部通过 ✅" if fails == 0 else f"{fails} 项失败 ❌")
sys.exit(1 if fails else 0)
