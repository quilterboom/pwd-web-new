"""授权管理（仅超级管理员）：查看 / 设置 / 重置 指定用户的操作权限。

- GET  /api/admin/permissions/users/{uid}  → 返回该用户被允许的操作清单（null=全部可用）
- PUT  /api/admin/permissions/users/{uid}  → 覆盖写入允许清单（body: {"permissions": [...]}）
- DELETE /api/admin/permissions/users/{uid} → 删除记录（恢复「全部可用」）
"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..core.deps import require_global_admin
from ..db import get_db
from ..models import User
from ..perms import (
    ALL_PERM_KEYS,
    delete_user_permissions,
    get_user_permissions,
    set_user_permissions,
)

router = APIRouter(prefix="/api/admin/permissions", tags=["admin-permissions"])


class UserPermRequest(BaseModel):
    permissions: list[str] = []


@router.get("/users/{uid}")
def get_user_perm(
    uid: int,
    _: User = Depends(require_global_admin),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter_by(id=uid).first()
    if user is None:
        raise HTTPException(status_code=404, detail="用户不存在")
    return {"user_id": uid, "username": user.username, "permissions": get_user_permissions(db, uid)}


@router.put("/users/{uid}")
def put_user_perm(
    uid: int,
    req: UserPermRequest,
    _: User = Depends(require_global_admin),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter_by(id=uid).first()
    if user is None:
        raise HTTPException(status_code=404, detail="用户不存在")
    # 仅接受已知 key，过滤脏数据
    invalid = [k for k in req.permissions if k not in ALL_PERM_KEYS]
    if invalid:
        raise HTTPException(status_code=400, detail=f"未知的操作权限：{', '.join(invalid)}")
    set_user_permissions(db, uid, req.permissions)
    # 管理员永远全开；此处仅对普通用户生效
    return {"user_id": uid, "username": user.username, "permissions": get_user_permissions(db, uid)}


@router.delete("/users/{uid}")
def delete_user_perm(
    uid: int,
    _: User = Depends(require_global_admin),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter_by(id=uid).first()
    if user is None:
        raise HTTPException(status_code=404, detail="用户不存在")
    delete_user_permissions(db, uid)
    return {"user_id": uid, "username": user.username, "permissions": None}
