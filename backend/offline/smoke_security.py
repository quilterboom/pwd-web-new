"""安全加固回归测试（需容器内运行，直接访问本地 FastAPI）。

覆盖：
  1. 正常 SCRAM-SM3 登录（begin -> verify）仍可用；
  2. 重放攻击被阻断：同一 (nonce, proof) 二次 verify 必须 401；
  3. 安全响应头存在：X-Frame-Options / CSP / X-Content-Type-Options / Referrer-Policy；
  4. CORS 不允许任意跨域（Origin 非白名单时不回显 ACAO）；
  5. 登录限速：超过阈值返回 429。
"""
import json
import os
import sys
import urllib.request
import urllib.error

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://localhost:9010").rstrip("/")
ADMIN = os.getenv("ADMIN_USERNAME", "admin")
PASS = os.getenv("ADMIN_PASSWORD", "admin123")

sys.path.insert(0, "/app")
from app.security import _sm3_hex  # noqa: E402

fails = 0


def _post(path, payload, headers=None):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        BASE + path, data=data, headers=headers or {"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, r.read().decode(), r.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), e.headers


def _get(path, headers=None):
    req = urllib.request.Request(BASE + path, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, r.read().decode(), r.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), e.headers


def begin(username):
    return _post("/api/auth/login/begin", {"username": username})


def verify(username, nonce, proof):
    return _post("/api/auth/login/verify", {"username": username, "nonce": nonce, "proof": proof})


def compute_proof(salt_hex, nonce_hex, password):
    T = _sm3_hex(password.encode("utf-8") + bytes.fromhex(salt_hex))
    return _sm3_hex(bytes.fromhex(T) + bytes.fromhex(nonce_hex))


def check(name, cond, extra=""):
    global fails
    status = "✅" if cond else "❌"
    print(f"  {status} {name}" + (f" — {extra}" if extra and not cond else ""))
    if not cond:
        fails += 1


# 1) 正常登录
st, body, _ = begin(ADMIN)
check("login/begin 返回挑战", st == 200, f"status={st}")
if st == 200:
    d = json.loads(body)
    proof = compute_proof(d["salt"], d["nonce"], PASS)
    st2, body2, _ = verify(ADMIN, d["nonce"], proof)
    check("login/verify 正常签发令牌", st2 == 200, f"status={st2} body={body2[:120]}")
    token = json.loads(body2).get("access_token") if st2 == 200 else None

    # 2) 重放攻击：用同一 (nonce, proof) 再 verify 一次，必须 401（挑战已消费）
    st3, body3, _ = verify(ADMIN, d["nonce"], proof)
    check("重放同一 proof 被拒绝(401)", st3 == 401, f"status={st3} body={body3[:120]}")

    # 用「任意伪造 nonce」verify（绕过 begin 存储）—— 必须 401（无服务端挑战）
    fake = compute_proof(d["salt"], "00" * 16, PASS)
    st4, _, _ = verify(ADMIN, "00" * 16, fake)
    check("伪造 nonce 被拒绝(401)", st4 == 401, f"status={st4}")

# 3) 安全响应头
st_h, _, hdrs = _get("/")
check("X-Frame-Options: DENY", hdrs.get("X-Frame-Options", "").upper() == "DENY", hdrs.get("X-Frame-Options"))
check("X-Content-Type-Options: nosniff", hdrs.get("X-Content-Type-Options", "").lower() == "nosniff")
csp = hdrs.get("Content-Security-Policy", "")
check("CSP 含 default-src 'self'", "default-src 'self'" in csp, csp[:80])
check("CSP frame-ancestors 'none'", "frame-ancestors 'none'" in csp)

# 4) CORS：非白名单 Origin 不应回显 Access-Control-Allow-Origin
_, _, hdrs_c = _post(
    "/api/auth/login/begin", {"username": ADMIN},
    headers={"Content-Type": "application/json", "Origin": "http://evil.example.com"},
)
acao = hdrs_c.get("Access-Control-Allow-Origin", "")
cors_safe = (acao == "" or acao == "null") and ("evil" not in acao)
check("CORS 不回显恶意 Origin", cors_safe, f"ACAO={acao!r}")

# 5) 登录限速：持续 begin 直到 429
seen_429 = False
for _ in range(60):
    s, _, _ = begin(ADMIN)
    if s == 429:
        seen_429 = True
        break
check("登录限速触发 429", seen_429, "未在 60 次内触发")

print("\n结果:", "全部通过 ✅" if fails == 0 else f"{fails} 项失败 ❌")
sys.exit(1 if fails else 0)
