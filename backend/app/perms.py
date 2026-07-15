"""逐用户操作授权核心。

设计要点（与「授权即限制」策略一致）：
- 权限以「被允许的操作 key 清单」表达，存于 user_permissions 表。
- 某用户没有记录 → 全部操作可用（默认全开，存量用户不被锁死）。
- 有记录 → 仅清单内的操作可用；管理员（is_admin）永远全开，不受此限制。
- 前端按钮显隐只是辅助，真正的拦截在后端 require_perm 依赖（API 层 403）。
"""

import json
from fastapi import Depends, HTTPException
from sqlalchemy.orm import Session

from .core.deps import get_current_user
from .db import get_db
from .models import User, UserPermission

# 操作目录：按页面分组展示。key 必须与后端 require_perm 使用的常量完全一致。
# 「系统管理」类操作本质仅管理员可执行，逐用户授权对其不生效，仅作展示与说明。
PERMISSION_CATALOG = [
    {
        "category": "密码库",
        "items": [
            {"key": "pw.create", "label": "新增密码"},
            {"key": "pw.edit", "label": "编辑密码"},
            {"key": "pw.delete", "label": "删除密码"},
            {"key": "pw.batch_delete", "label": "批量删除密码"},
            {"key": "pw.import", "label": "导入密码"},
            {"key": "pw.export", "label": "导出密码"},
            {"key": "pw.view", "label": "查看 / 复制密码"},
        ],
    },
    {
        "category": "密钥库",
        "items": [
            {"key": "key.generate", "label": "生成密钥"},
            {"key": "key.import", "label": "导入密钥"},
            {"key": "key.delete", "label": "删除密钥"},
            {"key": "key.batch_delete", "label": "批量删除密钥"},
        ],
    },
    {
        "category": "账户",
        "items": [
            {"key": "account.change_password", "label": "修改密码"},
        ],
    },
    {
        "category": "系统管理（仅管理员可执行，逐用户授权不生效）",
        "items": [
            {"key": "sys.user_manage", "label": "用户管理"},
            {"key": "sys.group_manage", "label": "分组管理"},
            {"key": "sys.audit_view", "label": "查看审计日志"},
        ],
    },
]

# 所有合法的权限 key（用于写入时校验，避免脏数据）
ALL_PERM_KEYS = [item["key"] for cat in PERMISSION_CATALOG for item in cat["items"]]


def get_user_permissions(db: Session, user_id: int):
    """返回该用户被允许的操作清单；None 表示「未授权过 → 全部可用」。"""
    row = db.query(UserPermission).filter_by(user_id=user_id).first()
    if row is None:
        return None
    try:
        return json.loads(row.perms or "[]")
    except Exception:
        return []


def set_user_permissions(db: Session, user_id: int, perms: list) -> None:
    """写入（覆盖）某用户的允许清单。仅接受已知 key。"""
    clean = [k for k in (perms or []) if k in ALL_PERM_KEYS]
    row = db.query(UserPermission).filter_by(user_id=user_id).first()
    if row is None:
        row = UserPermission(user_id=user_id, perms="[]")
        db.add(row)
    row.perms = json.dumps(clean, ensure_ascii=False)
    db.commit()


def delete_user_permissions(db: Session, user_id: int) -> None:
    """删除某用户的授权记录 → 恢复「全部可用」。"""
    row = db.query(UserPermission).filter_by(user_id=user_id).first()
    if row:
        db.delete(row)
        db.commit()


def require_perm(perm_key: str):
    """依赖工厂：校验当前登录用户是否拥有 perm_key 操作权限。

    - 管理员（is_admin）永远放行（绕过权限限制）。
    - 未授权过（无记录）→ 放行（默认全开）。
    - 有记录但 key 不在清单 → 403。
    """

    def dep(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
        if user.is_admin:
            return user
        row = db.query(UserPermission).filter_by(user_id=user.id).first()
        if row is None:
            return user
        allowed = set(json.loads(row.perms or "[]"))
        if perm_key not in allowed:
            raise HTTPException(status_code=403, detail="无权限执行该操作")
        return user

    return dep
