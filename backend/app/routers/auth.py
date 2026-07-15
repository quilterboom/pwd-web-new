from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel
from sqlalchemy.orm import Session

import os
import secrets
import time

from ..config import ALLOW_REGISTRATION, REGISTER_DEFAULT_GROUP
from ..core.deps import get_current_user, get_user_groups, is_global_admin
from ..db import get_db
from ..models import Group, User
from ..perms import (
    PERMISSION_CATALOG,
    get_user_permissions,
    require_perm,
)
from ..seed import _seed_login_material
from .admin import _link_user_group
from ..security import (
    consume_login_challenge,
    create_token,
    decode_token,
    derive_password_verifier,
    expected_proof,
    hash_password,
    make_login_challenge,
    store_login_challenge,
    verify_password,
)
from ..sessions import create_session, new_jti, revoke_session

bearer_scheme = HTTPBearer()

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

    jti = new_jti()
    create_session(db, user.id, jti)
    token = create_token(user.username, jti)
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
    jti = new_jti()
    create_session(db, user.id, jti)
    token = create_token(user.username, jti)
    return {"access_token": token, "token_type": "bearer"}


@router.get("/me")
def me(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    groups = [{"id": g.id, "name": g.name} for g in get_user_groups(db, user)]
    # 管理员永远全开（permissions=None）；普通用户返回授权清单或 None（未授权=全部可用）
    permissions = None if user.is_admin else get_user_permissions(db, user.id)
    return {
        "username": user.username,
        "is_admin": bool(user.is_admin),
        "is_global_admin": is_global_admin(db, user),
        "groups": groups,
        "permissions": permissions,
    }


@router.post("/logout")
def logout(
    creds: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: Session = Depends(get_db),
):
    """服务端登出：吊销当前令牌对应的会话，令该令牌立即失效。

    前端在「手动退出」与「空闲自动登出」时都应调用本接口，以实现服务端强制失效
    （即使令牌被截获，登出后也无法再用）。
    """
    jti = decode_token(creds.credentials).get("jti")
    revoke_session(db, jti)
    return {"ok": True, "message": "已退出登录"}


@router.get("/permissions/catalog")
def permissions_catalog(_: User = Depends(get_current_user)):
    """返回操作授权目录（按页面分组），供授权管理页渲染勾选框。"""
    return PERMISSION_CATALOG


# ────────── 自助注册（受 ALLOW_REGISTRATION 总开关控制）──────────
#
# 设计要点：
#   • 默认关闭（ALLOW_REGISTRATION 不为真）→ 直接 403，避免误开后任意访客灌库。
#   • 仅创建「普通用户」(is_admin=False)；权限/分组由管理员在后台调整。
#   • 同时写入 SCRAM-SM3 凭据（pw_salt/pw_verifier）与 bcrypt 哈希（hashed_password），
#     保证两种登录路径都可用（与首次 seed 建管理员同款写法）。
#   • 自动加入 REGISTER_DEFAULT_GROUP（find-or-create），注册即可看到一个空保险箱。
#   • 独立注册限速，与登录限速分开，遏制批量注册/撞库。

class RegisterRequest(BaseModel):
    username: str
    password: str
    confirm_password: str = ""


# 注册限速（独立于登录限速）：单 IP 在窗口内最多注册次数
_REGISTER_LIMIT = int(os.getenv("REGISTER_RATE_LIMIT", "10"))
_REGISTER_WINDOW = int(os.getenv("REGISTER_RATE_WINDOW", "3600"))  # 默认 1 小时
_register_hits: dict[str, list[float]] = {}


def _register_rate_limit(request: Request) -> None:
    client = request.client.host if request.client else "unknown"
    now = time.time()
    hits = _register_hits.setdefault(client, [])
    _register_hits[client] = [t for t in hits if now - t < _REGISTER_WINDOW]
    if len(_register_hits[client]) >= _REGISTER_LIMIT:
        raise HTTPException(status_code=429, detail="注册过于频繁，请稍后再试")
    _register_hits[client].append(now)


@router.get("/register/status")
def register_status():
    """公开端点：返回当前是否开放自助注册，供登录页决定是否展示「注册」入口。无需鉴权。"""
    return {"allow_registration": bool(ALLOW_REGISTRATION)}


@router.post("/register")
def register(req: RegisterRequest, request: Request, db: Session = Depends(get_db)):
    """自助注册：创建普通用户并自动加入默认分组。受 ALLOW_REGISTRATION 总开关控制。"""
    if not ALLOW_REGISTRATION:
        raise HTTPException(status_code=403, detail="当前系统未开放注册")

    _register_rate_limit(request)

    username = (req.username or "").strip()
    password = req.password or ""
    if len(username) < 3:
        raise HTTPException(status_code=400, detail="用户名至少 3 个字符")
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="密码至少 8 位")
    if req.confirm_password and req.confirm_password != password:
        raise HTTPException(status_code=400, detail="两次输入的密码不一致")
    if db.query(User).filter_by(username=username).first():
        raise HTTPException(status_code=400, detail="该用户名已被注册")

    # 创建普通用户（SCRAM 凭据 + bcrypt 哈希双写，两种登录路径都可用）
    new_user = User(username=username, hashed_password=hash_password(password), is_admin=False)
    _seed_login_material(new_user, password)
    db.add(new_user)
    db.flush()

    # 自动加入默认分组（find-or-create，按 REGISTER_DEFAULT_GROUP）
    group = db.query(Group).filter_by(name=REGISTER_DEFAULT_GROUP).first()
    if group is None:
        group = Group(name=REGISTER_DEFAULT_GROUP, description="系统默认分组")
        db.add(group)
        db.flush()
    _link_user_group(db, new_user.id, group.id)
    db.commit()
    return {"ok": True, "message": "注册成功，请登录"}


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
    _: User = Depends(require_perm("account.change_password")),
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
    _: User = Depends(require_perm("account.change_password")),
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
