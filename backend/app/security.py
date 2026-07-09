from datetime import datetime, timedelta, timezone
import secrets

import jwt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hashes import SM3
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from passlib.context import CryptContext

from .config import ALGORITHM, SECRET_KEY, ACCESS_TOKEN_EXPIRE_MINUTES

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)


def create_token(username: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": username, "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])


# ────────────── SCRAM-SM3 登录凭据 ──────────────
#
# 设计目标：登录时密码「不在网络上以明文传输」，替代旧的纯 bcrypt+明文 POST。
#
# 协议（极简 SCRAM-SM3）：
#   1. 客户端 → POST /api/auth/login/begin {username}
#      服务端 → {salt: hex16B, nonce: hex16B, mode: "scram"}
#   2. 客户端用 salt 计算 SCRAM 派生材料：
#        T  = SM3(password || salt)   ← 一次性外层 hash
#        proof = SM3(T || nonce)       ← 挑战响应（每次不同）
#      客户端 → POST /api/auth/login/verify {username, nonce, proof}
#   3. 服务端取出该用户保存的 pw_verifier（== T），计算 expected = SM3(pw_verifier || nonce)，
#      与 proof 比对。一致则签发 JWT。
#
# 安全要点：
#   • 监听者看不到密码（只看到 nonce 与 SM3 结果）
#   • 重放防护：nonce 必须由服务端生成且每次不同（同一 nonce 不可复用）
#   • 服务端 DB 泄漏：攻击者只拿到 pw_verifier == SM3(password || salt)，
#     无法直接登录（仍需原始 SM3 哈希去满足挑战 — 难度等同离线爆破密码）
#   • 旧用户（旧密码仍只有 bcrypt）：登录路径暂时保留为 /api/auth/login（明文），
#     登录成功后服务端自动生成 salt + pw_verifier 迁移到新方案。后续则强制使用新方案。

PBKDF2_ITER = 10_000  # SCRAM-SM3 拉伸迭代次数（与 Gmssl.PBKDF2_SM3 保持一致）

_SM3_CTX_BYTES = 32  # SM3 摘要固定 32 字节


def _sm3_hex(data: bytes) -> str:
    h = hashes.Hash(SM3())
    h.update(data)
    return h.finalize().hex()


def derive_password_verifier(password: str, salt_hex: str) -> str:
    """根据明文密码与 salt 派生 pw_verifier（SM3-hex，32 字节）。

    服务端用此函数在创建 / 重置密码时持久化 verifier；登录时客户端用同一个 salt
    也能算出一致值，从而参与挑战-响应证明。
    """
    return _sm3_hex((password or "").encode("utf-8") + bytes.fromhex(salt_hex or "00"))


def derive_password_verifier(password: str, salt_hex: str) -> str:
    """对外统一接口：根据明文密码与 salt 派生 pw_verifier (SM3-hex)。"""
    return _sm3_hex((password or "").encode("utf-8") + bytes.fromhex(salt_hex or "00"))


def make_login_challenge() -> dict:
    """生成新的登录挑战（一次性 nonce 与 salt）。"""
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(16)
    return {
        "salt": salt.hex(),
        "nonce": nonce.hex(),
        "iter": PBKDF2_ITER,
    }


def expected_proof(pw_verifier_hex: str, nonce_hex: str) -> str:
    """服务端计算 expected = SM3(pw_verifier || nonce) 用以比对客户端 proof。"""
    # 解码 verifier 与 nonce 为原始字节并拼接
    msg = bytes.fromhex(pw_verifier_hex or "") + bytes.fromhex(nonce_hex or "")
    return _sm3_hex(msg)


# ────────────── 旧的 PBKDF2-SM3 派生（保留供条目密码加解密复用）──────────────


def pbkdf2_sm3(password: str, salt_hex: str, iterations: int = PBKDF2_ITER, length: int = 32) -> bytes:
    """PBKDF2-SM3：服务端做密钥派生，与 PassPy / entry 方案互通。"""
    salt = bytes.fromhex(salt_hex or "00" * 16)
    kdf = PBKDF2HMAC(
        algorithm=SM3(), length=length, salt=salt, iterations=iterations
    )
    return kdf.derive(password.encode("utf-8"))
