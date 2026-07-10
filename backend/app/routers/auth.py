from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

import os
import secrets
import time

from ..core.deps import get_current_user, get_user_groups
from ..db import get_db
from ..models import User
from ..security import (
    consume_login_challenge,
    create_token,
    derive_password_verifier,
    expected_proof,
    hash_password,
    make_login_challenge,
    store_login_challenge,
    verify_password,
)

# ── 登录限速（内存固定窗口；单进程部署足够）──
# 针对三个登录入口（begin / verify / 旧 login）统一限速，遏制在线爆破与重放探测。
_LOGIN_LIMIT = int(os.getenv("LOGIN_RATE_LIMIT", "20"))   # 每个窗口最多尝试次数
_LOGIN_WINDOW = int(os.getenv("LOGIN_RATE_WINDOW", "60"))  # 窗口秒数
_login_hits: dict[str, list[float]] = {}


def _login_rate_limit(request: Request) -> None:
    client = request.client.host if request.client else "unknown"
    now = time.time()
    hits = _login_hits.setdefault(client, [])
    # 仅保留窗口内的记录
    _login_hits[client] = [t for t in hits if now - t < _LOGIN_WINDOW]
    if len(_login_hits[client]) >= _LOGIN_LIMIT:
        raise HTTPException(
            status_code=429,
            detail="登录尝试过于频繁，请稍后再试",
        )
    _login_hits[client].append(now)

router = APIRouter(prefix="/api/auth", tags=["auth"])


# ────────── 旧的「纯明文」登录（兼容路径，登录成功后自动迁移到 SCRAM-SM3） ──────────

class LoginRequest(BaseModel):
    username: str
    password: str


@router.post("/login")
def login(req: LoginRequest, request: Request, db: Session = Depends(get_db)):
    """旧版登录入口：明文密码。

    仅当用户尚未迁移（pw_verifier 为空）时启用此路径。登录成功后服务端自动为该用户生成
    salt 并写入 pw_verifier（基于本次明文密码一次性迁移）。下一次登录必须改用
    /login/begin + /login/verify 走 SCRAM-SM3 协议。
    """
    _login_rate_limit(request)
    user = db.query(User).filter_by(username=req.username).first()
    if user is None or not verify_password(req.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="用户名或密码错误")

    # 自动迁移到 SCRAM-SM3 凭据
    if not user.pw_verifier:
        salt = secrets.token_bytes(16).hex()
        user.pw_salt = salt
        user.pw_verifier = derive_password_verifier(req.password, salt)
        db.commit()

    token = create_token(user.username)
    return {"access_token": token, "token_type": "bearer"}


# ────────── 新版「SCRAM-SM3 挑战-响应」登录（推荐路径，密码不在网络上明文传输）──────────

class LoginBeginRequest(BaseModel):
    username: str


class LoginVerifyRequest(BaseModel):
    username: str
    nonce: str
    proof: str


@router.post("/login/begin")
def login_begin(req: LoginBeginRequest, request: Request, db: Session = Depends(get_db)):
    _login_rate_limit(request)
    user = db.query(User).filter_by(username=req.username).first()
    if user is None:
        # 用户名是否存在不应直接暴露（统一返回 401）
        raise HTTPException(status_code=401, detail="用户名或密码错误")
    if not user.pw_verifier:
        # 用户尚未迁移到 SCRAM-SM3，提示调用 /login（旧路径）一次性迁移
        raise HTTPException(
            status_code=409,
            detail="账户尚未启用加密登录，请使用旧登录入口一次完成迁移；或联系管理员重置密码。",
        )
    # 关键：返回「用户库内存储的 salt」，不是新的随机 salt——客户端必须用它才能算出与服务端相同的 verifier
    chal = make_login_challenge()
    # 服务端保存该一次性挑战（与用户名绑定，verify 时消费，防重放）
    store_login_challenge(user.username, chal["nonce"])
    return {
        "username": user.username,
        "salt": user.pw_salt,                 # 持久化的盐（与服务端 verifier 一一对应）
        "nonce": chal["nonce"],               # 一次性的挑战随机数（防重放）
        "iter": chal["iter"],                 # 拉伸迭代次数（与 PBKDF2-SM3 保持一致即可）
        "mode": "scram",
    }


@router.post("/login/verify")
def login_verify(req: LoginVerifyRequest, request: Request, db: Session = Depends(get_db)):
    _login_rate_limit(request)
    user = db.query(User).filter_by(username=req.username).first()
    if user is None or not user.pw_verifier:
        raise HTTPException(status_code=401, detail="用户名或密码错误")
    # 必须使用服务端此前下发的「未过期且未消费」挑战 nonce，否则视为重放/过期
    if not consume_login_challenge(user.username, req.nonce):
        raise HTTPException(
            status_code=401,
            detail="登录挑战已失效或重复使用，请重新发起登录",
        )
    expected = expected_proof(user.pw_verifier, req.nonce)
    # constant-time 比较，避免 timing leak
    if not secrets.compare_digest(expected.lower(), (req.proof or "").lower()):
        raise HTTPException(status_code=401, detail="用户名或密码错误")
    token = create_token(user.username)
    return {"access_token": token, "token_type": "bearer"}


@router.get("/me")
def me(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    groups = [{"id": g.id, "name": g.name} for g in get_user_groups(db, user)]
    return {"username": user.username, "is_admin": bool(user.is_admin), "groups": groups}


# ────────── 自助修改登录密码（所有登录用户可用）──────────
#
# 复用 SCRAM-SM3 挑战-响应校验「当前密码」（零明文），校验通过后再写入新密码。
# 同时更新 pw_salt / pw_verifier（SCRAM 凭据）与 hashed_password（bcrypt 旧路径兼容），
# 确保两种登录方式都指向新密码。legacy 用户（pw_verifier 为空）可用 current_password 明文兜底校验。

class ChangePasswordVerifyRequest(BaseModel):
    nonce: str = ""
    proof: str = ""                 # SCRAM-SM3 证明（优先）
    current_password: str = ""      # legacy 兜底：仅当 pw_verifier 为空时可用
    new_password: str


@router.post("/change-password/begin")
def change_password_begin(
    user: User = Depends(get_current_user),
    request: Request = None,
    db: Session = Depends(get_db),
):
    """下发一次性挑战（salt + nonce），供前端用「当前密码」计算 SCRAM 证明。"""
    if request is not None:
        _login_rate_limit(request)
    if not user.pw_verifier:
        # 尚未启用 SCRAM：返回特殊标记，前端可引导用 current_password 明文路径
        return {"username": user.username, "salt": "", "nonce": "", "iter": 0, "mode": "legacy"}
    chal = make_login_challenge()
    store_login_challenge(user.username, chal["nonce"])
    return {
        "username": user.username,
        "salt": user.pw_salt,
        "nonce": chal["nonce"],
        "iter": chal["iter"],
        "mode": "scram",
    }


@router.post("/change-password/verify")
def change_password_verify(
    req: ChangePasswordVerifyRequest,
    user: User = Depends(get_current_user),
    request: Request = None,
    db: Session = Depends(get_db),
):
    """校验「当前密码」后写入新密码。本端点基于已登录身份，仅能修改自己的密码。"""
    if request is not None:
        _login_rate_limit(request)

    npw = req.new_password or ""
    if len(npw) < 8:
        raise HTTPException(status_code=400, detail="新密码长度至少为 8 位")
    if npw == (req.current_password or ""):
        raise HTTPException(status_code=400, detail="新密码不能与当前密码相同")

    # 1) 校验当前密码身份
    authed = False
    if req.proof and user.pw_verifier:
        if not consume_login_challenge(user.username, req.nonce):
            raise HTTPException(status_code=401, detail="验证挑战已失效，请重试")
        expected = expected_proof(user.pw_verifier, req.nonce)
        authed = secrets.compare_digest(expected.lower(), (req.proof or "").lower())
    elif req.current_password:
        # legacy 兜底：直接比对 bcrypt 哈希
        authed = verify_password(req.current_password, user.hashed_password)

    if not authed:
        raise HTTPException(status_code=401, detail="当前密码错误")

    # 2) 写入新密码（SCRAM 凭据 + bcrypt 哈希同步更新）
    new_salt = secrets.token_bytes(16).hex()
    user.pw_salt = new_salt
    user.pw_verifier = derive_password_verifier(npw, new_salt)
    user.hashed_password = hash_password(npw)
    db.commit()
    return {"ok": True, "message": "密码已更新"}
