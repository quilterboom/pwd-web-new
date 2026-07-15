"""管理员接口：账号管理、分组管理，以及当前用户可见分组查询。

- `/api/groups/mine`：任意登录用户可获取自己所属分组（用于前端下拉选择）。
- `/api/admin/users`：仅管理员。创建/列表/修改/删除账号，并管理其所属分组。
- `/api/admin/groups`：仅管理员。创建/列表/修改/删除分组，并管理其成员。
"""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.deps import (
    get_admin_group_ids,
    get_current_user,
    get_user_groups,
    is_global_admin,
    require_admin,
)
from ..db import get_db
from ..models import Group, History, PasswordEntry, User, user_groups, user_admin_groups
from ..perms import require_perm
from ..security import derive_password_verifier, hash_password

# ---------------- 当前用户可见分组（非管理员接口） ----------------
mine_router = APIRouter(tags=["groups"])

# ---------------- 管理员：用户管理 ----------------
users_router = APIRouter(prefix="/api/admin/users", tags=["admin-users"])
# ---------------- 管理员：分组管理 ----------------
groups_router = APIRouter(prefix="/api/admin/groups", tags=["admin-groups"])
# ---------------- 管理员：审计日志 ----------------
audit_router = APIRouter(prefix="/api/admin/audit", tags=["admin-audit"])


# ============================ 当前用户分组 ============================
@mine_router.get("/api/groups/mine")
def groups_mine(
    user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    groups = get_user_groups(db, user)
    return [{"id": g.id, "name": g.name} for g in groups]


# ============================ 用户管理 ============================
class UserCreate(BaseModel):
    username: str
    password: str
    is_admin: bool = False
    group_ids: list[int] = []
    admin_group_ids: list[int] = []  # 仅全局管理员可指定；为空=管理全部分组


class UserUpdate(BaseModel):
    password: Optional[str] = None
    is_admin: Optional[bool] = None
    group_ids: Optional[list[int]] = None
    admin_group_ids: Optional[list[int]] = None


def _user_groups_out(db: Session, user: User) -> list[dict]:
    return [{"id": g.id, "name": g.name} for g in get_user_groups(db, user)]


def _user_admin_groups_out(db: Session, user: User) -> list[dict]:
    gids = get_admin_group_ids(db, user)
    if not gids:
        return []
    groups = db.query(Group).filter(Group.id.in_(gids)).order_by(Group.name).all()
    return [{"id": g.id, "name": g.name} for g in groups]


def _user_out(db: Session, user: User) -> dict:
    return {
        "id": user.id,
        "username": user.username,
        "is_admin": bool(user.is_admin),
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "groups": _user_groups_out(db, user),
        "admin_groups": _user_admin_groups_out(db, user),
    }


def _group_out(db: Session, group: Group) -> dict:
    members = (
        db.query(User)
        .join(user_groups, user_groups.c.user_id == User.id)
        .filter(user_groups.c.group_id == group.id)
        .order_by(User.username)
        .all()
    )
    return {
        "id": group.id,
        "name": group.name,
        "description": group.description,
        "created_at": group.created_at.isoformat() if group.created_at else None,
        "member_count": len(members),
        "members": [{"id": m.id, "username": m.username} for m in members],
    }


def _unlink_user_admin_group(db: Session, **where) -> None:
    stmt = user_admin_groups.delete()
    for col, val in where.items():
        stmt = stmt.where(getattr(user_admin_groups.c, col) == val)
    db.execute(stmt)


def _set_user_admin_groups(db: Session, user: User, group_ids: list[int]) -> None:
    """覆盖写入某用户「作为管理员可管理的分组」。"""
    _unlink_user_admin_group(db, user_id=user.id)
    for gid in group_ids:
        if db.query(Group).filter_by(id=gid).first():
            db.execute(
                user_admin_groups.insert().values(user_id=user.id, group_id=gid)
            )


def _visible_user_ids(db: Session, caller: User) -> Optional[set[int]]:
    """返回分组管理员可见的用户 id 集合；全局管理员返回 None（表示全部）。"""
    if is_global_admin(db, caller):
        return None
    my_admin_ids = get_admin_group_ids(db, caller)
    rows = db.query(User).all()
    out: set[int] = set()
    for u in rows:
        u_ids = {g.id for g in u.groups} | get_admin_group_ids(db, u)
        if u.id == caller.id or (u_ids & my_admin_ids):
            out.add(u.id)
    return out


def _link_user_group(db: Session, user_id: int, group_id: int) -> None:
    exists = db.execute(
        user_groups.select().where(
            user_groups.c.user_id == user_id,
            user_groups.c.group_id == group_id,
        )
    ).first()
    if not exists:
        db.execute(
            user_groups.insert().values(user_id=user_id, group_id=group_id)
        )


def _unlink_user_group(db: Session, **where) -> None:
    stmt = user_groups.delete()
    for col, val in where.items():
        stmt = stmt.where(getattr(user_groups.c, col) == val)
    db.execute(stmt)


@users_router.get("")
def list_users(
    page: int = None,
    page_size: int = None,
    q: Optional[str] = None,
    caller: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """管理员用户列表。

    - 不传 page_size：返回完整扁平数组（兼容旧调用 / 其它内部脚本）。
    - 传 page_size：返回分页信封 {"items", "total", "page", "page_size"}（前端弹框走此路径）。
    - q：按「用户名 / 所属分组名」模糊搜索。
    """
    rows = db.query(User).order_by(User.username).all()
    # 分组管理员：仅可见「与自己所管理分组有交集」的用户（含自己）
    visible = _visible_user_ids(db, caller)
    if visible is not None:
        rows = [u for u in rows if u.id in visible]
    if q:
        ql = q.strip().lower()
        rows = [
            u for u in rows
            if ql in u.username.lower()
            or any(ql in g.name.lower() for g in u.groups)
        ]
    total = len(rows)
    # 未指定分页 → 兼容旧调用：返回完整扁平数组
    if page_size is None:
        return [_user_out(db, u) for u in rows]
    # 指定分页 → 返回信封
    page = page or 1
    if page < 1:
        page = 1
    if page_size < 1:
        page_size = 20
    if page_size > 5000:
        page_size = 5000
    total_pages = (total + page_size - 1) // page_size or 1
    if page > total_pages:
        page = total_pages
    start = (page - 1) * page_size
    page_rows = rows[start:start + page_size]
    items = [_user_out(db, u) for u in page_rows]
    return {"items": items, "total": total, "page": page, "page_size": page_size}


def _seed_login_material(user: User, password: str) -> None:
    """给新创建 / 重置密码的用户同时写入 SCRAM-SM3 凭据（盐 + 验证器）。
    这样新用户从一开始就走「加密登录」路径——明文密码只在管理员表单里短暂出现一次。
    """
    import secrets
    salt = secrets.token_bytes(16).hex()
    user.pw_salt = salt
    user.pw_verifier = derive_password_verifier(password, salt)


@users_router.post("", dependencies=[Depends(require_perm("sys.user_manage"))])
def create_user(
    req: UserCreate,
    caller: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    if not req.username or not req.password:
        raise HTTPException(status_code=400, detail="用户名与密码均不能为空")
    if db.query(User).filter_by(username=req.username).first():
        raise HTTPException(status_code=409, detail="用户名已存在")

    # 分组管理员：只能在其管理范围内操作，且无权创建其他管理员
    caller_admin_ids = get_admin_group_ids(db, caller)
    is_global = not caller_admin_ids  # 调用者是管理员，admin_group_ids 为空即超级管理员
    if not is_global and req.is_admin:
        raise HTTPException(status_code=403, detail="分组管理员无权创建其他管理员")

    user = User(
        username=req.username,
        hashed_password=hash_password(req.password),
        is_admin=req.is_admin,
    )
    # 同时写入 SCRAM-SM3 凭据，便于新用户启用加密登录
    _seed_login_material(user, req.password)
    db.add(user)
    db.commit()
    db.refresh(user)

    group_ids = req.group_ids if is_global else [gid for gid in req.group_ids if gid in caller_admin_ids]
    for gid in group_ids:
        if db.query(Group).filter_by(id=gid).first():
            _link_user_group(db, user.id, gid)

    # 仅全局管理员可为用户指定「管理的分组」；管理员用户才写入管理分组
    if is_global and req.is_admin and req.admin_group_ids:
        _set_user_admin_groups(db, user, req.admin_group_ids)
    db.commit()
    return {"id": user.id, "username": user.username, "message": "created"}


@users_router.put("/{uid}", dependencies=[Depends(require_perm("sys.user_manage"))])
def update_user(
    uid: int,
    req: UserUpdate,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter_by(id=uid).first()
    if user is None:
        raise HTTPException(status_code=404, detail="用户不存在")

    caller_admin_ids = get_admin_group_ids(db, admin)
    is_global = not caller_admin_ids
    if not is_global:
        # 分组管理员不能修改/保留超级管理员，也不能把任何人设为管理员
        if is_global_admin(db, user):
            raise HTTPException(status_code=403, detail="无权修改超级管理员")
        if req.is_admin is True or (req.is_admin is None and user.is_admin):
            raise HTTPException(status_code=403, detail="分组管理员无权设置其他用户为管理员")

    if user.id == admin.id and req.is_admin is False:
        raise HTTPException(status_code=400, detail="不能取消自己的管理员权限")

    if req.password:
        user.hashed_password = hash_password(req.password)
        # 重置密码时同步更新 SCRAM-SM3 凭据；如未迁移，下一次登录即可走加密路径
        _seed_login_material(user, req.password)
    if req.is_admin is not None:
        user.is_admin = req.is_admin

    if not is_global:
        # 分组管理员：限制分组范围，但保留自己管理范围外的现有分组（避免误删）
        if req.group_ids is not None:
            visible_groups = caller_admin_ids
            existing = {g.id for g in user.groups}
            preserve = existing - visible_groups
            req.group_ids = list(set(req.group_ids) | preserve)
        if req.admin_group_ids is not None:
            req.admin_group_ids = [gid for gid in req.admin_group_ids if gid in caller_admin_ids]

    if req.group_ids is not None:
        _unlink_user_group(db, user_id=user.id)
        for gid in req.group_ids:
            if db.query(Group).filter_by(id=gid).first():
                _link_user_group(db, user.id, gid)

    # 管理分组：取消管理员则清空；否则按请求覆盖（仅全局管理员可写入）
    if req.is_admin is False:
        _set_user_admin_groups(db, user, [])
    elif req.admin_group_ids is not None and is_global:
        _set_user_admin_groups(db, user, req.admin_group_ids)
    db.commit()
    return {"id": user.id, "username": user.username, "message": "updated"}


@users_router.delete("/{uid}", dependencies=[Depends(require_perm("sys.user_manage"))])
def delete_user(
    uid: int,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    if uid == admin.id:
        raise HTTPException(status_code=400, detail="不能删除当前登录的管理员账号")
    user = db.query(User).filter_by(id=uid).first()
    if user is None:
        raise HTTPException(status_code=404, detail="用户不存在")
    _unlink_user_group(db, user_id=user.id)
    db.delete(user)
    db.commit()
    return {"id": uid, "message": "deleted"}


# ============================ 分组管理 ============================
class GroupCreate(BaseModel):
    name: str
    description: str = ""
    member_ids: list[int] = []


class GroupUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    member_ids: Optional[list[int]] = None


@groups_router.get("")
def list_groups(
    page: int = None,
    page_size: int = None,
    q: Optional[str] = None,
    caller: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """管理员分组列表。

    - 不传 page_size：返回完整扁平数组（兼容旧调用 / 其它内部脚本）。
    - 传 page_size：返回分页信封。
    - q：按「分组名」模糊搜索。
    """
    if is_global_admin(db, caller):
        rows = db.query(Group).order_by(Group.name).all()
    else:
        my_admin_ids = get_admin_group_ids(db, caller)
        rows = db.query(Group).filter(Group.id.in_(my_admin_ids)).order_by(Group.name).all()
    if q:
        ql = q.strip().lower()
        rows = [g for g in rows if ql in g.name.lower()]
    total = len(rows)
    if page_size is None:
        return [_group_out(db, g) for g in rows]
    page = page or 1
    if page < 1:
        page = 1
    if page_size < 1:
        page_size = 20
    if page_size > 5000:
        page_size = 5000
    total_pages = (total + page_size - 1) // page_size or 1
    if page > total_pages:
        page = total_pages
    start = (page - 1) * page_size
    page_rows = rows[start:start + page_size]
    items = [_group_out(db, g) for g in page_rows]
    return {"items": items, "total": total, "page": page, "page_size": page_size}


@groups_router.post("", dependencies=[Depends(require_perm("sys.group_manage"))])
def create_group(
    req: GroupCreate,
    caller: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    if not req.name:
        raise HTTPException(status_code=400, detail="分组名称不能为空")
    if db.query(Group).filter_by(name=req.name).first():
        raise HTTPException(status_code=409, detail="分组名称已存在")

    group = Group(name=req.name, description=req.description)
    db.add(group)
    db.commit()
    db.refresh(group)

    # 分组管理员创建的分组自动纳入其管理范围，便于后续管理
    if not is_global_admin(db, caller):
        _set_user_admin_groups(db, caller, list(get_admin_group_ids(db, caller)) + [group.id])

    for uid in req.member_ids:
        u = db.query(User).filter_by(id=uid).first()
        if u:
            _link_user_group(db, uid, group.id)
    db.commit()
    return {"id": group.id, "name": group.name, "message": "created"}


@groups_router.put("/{gid}", dependencies=[Depends(require_perm("sys.group_manage"))])
def update_group(
    gid: int,
    req: GroupUpdate,
    caller: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    group = db.query(Group).filter_by(id=gid).first()
    if group is None:
        raise HTTPException(status_code=404, detail="分组不存在")
    # 分组管理员只能管理自己范围内的分组
    if not is_global_admin(db, caller):
        if gid not in get_admin_group_ids(db, caller):
            raise HTTPException(status_code=403, detail="无权管理该分组")

    if req.name is not None and req.name != group.name:
        if db.query(Group).filter_by(name=req.name).first():
            raise HTTPException(status_code=409, detail="分组名称已存在")
        group.name = req.name
    if req.description is not None:
        group.description = req.description
    if req.member_ids is not None:
        # 分组管理员：仅能改动自己可见范围内的成员，保留范围外的现有成员
        if not is_global_admin(db, caller):
            visible = _visible_user_ids(db, caller)
            if visible is not None:
                existing = {u.id for u in group.members}
                preserve = existing - visible
                req.member_ids = list(set(req.member_ids) | preserve)
        _unlink_user_group(db, group_id=group.id)
        for uid in req.member_ids:
            if db.query(User).filter_by(id=uid).first():
                _link_user_group(db, uid, group.id)
    db.commit()
    return {"id": group.id, "name": group.name, "message": "updated"}


@groups_router.delete("/{gid}", dependencies=[Depends(require_perm("sys.group_manage"))])
def delete_group(
    gid: int,
    caller: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    group = db.query(Group).filter_by(id=gid).first()
    if group is None:
        raise HTTPException(status_code=404, detail="分组不存在")
    if not is_global_admin(db, caller) and gid not in get_admin_group_ids(db, caller):
        raise HTTPException(status_code=403, detail="无权删除该分组")
    bound_pw = db.query(PasswordEntry).filter_by(group_id=gid, deleted=False).count()
    if bound_pw:
        raise HTTPException(
            status_code=400,
            detail=f"该分组仍绑定 {bound_pw} 条密码，请先迁移或删除这些数据",
        )
    _unlink_user_group(db, group_id=gid)
    db.delete(group)
    db.commit()
    return {"id": gid, "message": "deleted"}


# ============================ 审计日志（仅管理员） ============================
def _audit_out(r, groups_by_id: dict) -> dict:
    return {
        "id": r.id,
        "password_id": r.password_id,
        "group_id": r.group_id,
        "group_name": groups_by_id.get(r.group_id, "—"),
        "action": r.action,
        "title": r.title,
        "username": r.username,
        "algorithm": r.algorithm,
        "notes": r.notes,
        "changed_by": r.changed_by,
        "changed_at": r.changed_at.isoformat() if r.changed_at else None,
        "comment": r.comment,
    }


@audit_router.get("", dependencies=[Depends(require_perm("sys.audit_view"))])
def list_audit(
    action: Optional[str] = None,
    q: Optional[str] = None,
    page: int = None,
    page_size: int = None,
    caller: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """管理员审计日志：返回修改记录（含删除），仅管理员可访问。

    - 不传 action：返回全部记录（新增 / 修改 / 删除）。
    - 传 action=delete：仅返回删除密码 / 密钥的记录，便于管理员集中核查删除行为。
    - 传 page_size：返回分页信封 {"items", "total", "page", "page_size"}（前端弹框）。否则返回扁平数组（兼容旧脚本）。
    - q：按「账号 / 标题 / 分组名 / 操作人 / 说明」模糊搜索。
    - 分组管理员：仅返回其管理分组范围内的记录。
    """
    groups_by_id = {g.id: g.name for g in db.query(Group).all()}
    base = db.query(History)
    if not is_global_admin(db, caller):
        my_admin_ids = get_admin_group_ids(db, caller)
        base = base.filter(History.group_id.in_(my_admin_ids))
    if action:
        base = base.filter_by(action=action)
    rows = base.order_by(History.changed_at.desc()).all()
    if q:
        ql = q.strip().lower()
        rows = [
            r for r in rows
            if ql in (r.username or "").lower()
            or ql in (r.title or "").lower()
            or ql in (groups_by_id.get(r.group_id, "") or "").lower()
            or ql in (r.changed_by or "").lower()
            or ql in (r.comment or "").lower()
        ]
    total = len(rows)
    if page_size is None:
        return [_audit_out(r, groups_by_id) for r in rows]
    page = page or 1
    if page < 1:
        page = 1
    if page_size < 1:
        page_size = 20
    if page_size > 5000:
        page_size = 5000
    total_pages = (total + page_size - 1) // page_size or 1
    if page > total_pages:
        page = total_pages
    start = (page - 1) * page_size
    page_rows = rows[start:start + page_size]
    items = [_audit_out(r, groups_by_id) for r in page_rows]
    return {"items": items, "total": total, "page": page, "page_size": page_size}
