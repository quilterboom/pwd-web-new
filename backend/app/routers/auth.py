from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..core.deps import get_current_user, get_user_groups
from ..db import get_db
from ..models import User
from ..security import (
    create_token,
    derive_password_verifier,
    expected_proof,
    make_login_challenge,
    verify_password,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])


# ────────── 旧的「纯明文」登录（兼容路径，登录成功后自动迁移到 SCRAM-SM3） ──────────

class LoginRequest(BaseModel):
    username: str
    password: str


@router.post("/login")
def login(req: LoginRequest, db: Session = Depends(get_db)):
    """旧版登录入口：明文密码。

    仅当用户尚未迁移（pw_verifier 为空）时启用此路径。登录成功后服务端自动为该用户生成
    salt 并写入 pw_verifier（基于本次明文密码一次性迁移）。下一次登录必须改用
    /login/begin + /login/verify 走 SCRAM-SM3 协议。
    """
    user = db.query(User).filter_by(username=req.username).first()
    if user is None or not verify_password(req.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="用户名或密码错误")

    # 自动迁移到 SCRAM-SM3 凭据
    if not user.pw_verifier:
        import secrets
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
def login_begin(req: LoginBeginRequest, db: Session = Depends(get_db)):
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
    return {
        "username": user.username,
        "salt": user.pw_salt,                 # 持久化的盐（与服务端 verifier 一一对应）
        "nonce": chal["nonce"],               # 一次性的挑战随机数（防重放）
        "iter": chal["iter"],                 # 拉伸迭代次数（与 PBKDF2-SM3 保持一致即可）
        "mode": "scram",
    }


@router.post("/login/verify")
def login_verify(req: LoginVerifyRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter_by(username=req.username).first()
    if user is None or not user.pw_verifier:
        raise HTTPException(status_code=401, detail="用户名或密码错误")
    expected = expected_proof(user.pw_verifier, req.nonce)
    # constant-time 比较，避免 timing leak
    import secrets
    if not secrets.compare_digest(expected.lower(), (req.proof or "").lower()):
        raise HTTPException(status_code=401, detail="用户名或密码错误")
    token = create_token(user.username)
    return {"access_token": token, "token_type": "bearer"}


@router.get("/me")
def me(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    groups = [{"id": g.id, "name": g.name} for g in get_user_groups(db, user)]
    return {"username": user.username, "is_admin": bool(user.is_admin), "groups": groups}
