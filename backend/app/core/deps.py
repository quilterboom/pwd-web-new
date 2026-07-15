from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Group, User, user_groups, user_admin_groups
from ..security import decode_token
from ..sessions import is_session_valid

bearer_scheme = HTTPBearer()


def get_current_user(
    creds: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    try:
        payload = decode_token(creds.credentials)
        username = payload.get("sub")
        jti = payload.get("jti")
    except Exception:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="无效或过期的令牌")

    # 服务端会话校验：令牌必须对应一个有效（未吊销、未空闲超时）的会话，
    # 否则即便 JWT 未过期也视为登录失效（服务端强制失效）。
    if not is_session_valid(db, jti):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="登录已失效，请重新登录")

    user = db.query(User).filter_by(username=username).first()
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="用户不存在")
    return user


def require_admin(user: User = Depends(get_current_user)) -> User:
    if not user.is_admin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="需要管理员权限")
    return user


def require_global_admin(
    user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> User:
    """仅超级管理员（is_admin 且未限定管理分组）可通过；分组管理员被拒。"""
    if not is_global_admin(db, user):
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="需要超级管理员权限")
    return user


def _user_admin_group_ids(db: Session, user_id: int) -> set[int]:
    """返回某用户作为「管理员」可管理的分组 id 集合（查关联表）。"""
    rows = (
        db.query(user_admin_groups.c.group_id)
        .filter(user_admin_groups.c.user_id == user_id)
        .all()
    )
    return {r[0] for r in rows}


def get_admin_group_ids(db: Session, user: User) -> set[int]:
    """返回该用户作为管理员可管理的分组 id 集合。

    - 非管理员 → 空集
    - 超级管理员（未指定管理分组）→ 空集（调用方据此判定为「管理全部分组」）
    """
    if not user.is_admin:
        return set()
    return _user_admin_group_ids(db, user.id)


def is_global_admin(db: Session, user: User) -> bool:
    """是否超级管理员：is_admin 为真，且未限定「管理的分组」（即管理全部分组）。"""
    return bool(user.is_admin) and not get_admin_group_ids(db, user)


def get_user_groups(db: Session, user: User) -> list[Group]:
    """返回当前用户可见的分组列表。

    - 普通用户：仅返回其所属分组。
    - 管理员：
        - 未指定「管理的分组」（超级管理员）→ 返回全部分组；
        - 指定了「管理的分组」（分组管理员）→ 返回「所属分组 ∪ 管理的分组」
          （即它既能以管理员身份管理指定分组，也能以普通成员身份查看自己所属分组）。
    """
    if not user.is_admin:
        return (
            db.query(Group)
            .join(user_groups, user_groups.c.group_id == Group.id)
            .filter(user_groups.c.user_id == user.id)
            .order_by(Group.name)
            .all()
        )
    admin_ids = _user_admin_group_ids(db, user.id)
    if not admin_ids:
        return db.query(Group).order_by(Group.name).all()
    member_ids = {g.id for g in user.groups}
    wanted = admin_ids | member_ids
    return (
        db.query(Group)
        .filter(Group.id.in_(wanted))
        .order_by(Group.name)
        .all()
    )


def get_user_group_ids(db: Session, user: User) -> set[int]:
    return {g.id for g in get_user_groups(db, user)}


def visibility_filter(column, user: User, group_ids: set[int]):
    """构造分组可见性过滤条件。

    管理员返回 None（不加过滤，可见全部）；
    普通用户返回 `column IN (group_ids)`（group_ids 为空则查不到任何数据）。
    """
    if user.is_admin:
        return None
    return column.in_(group_ids)


def ensure_group_access(db: Session, user: User, group_id: int | None) -> None:
    """校验用户是否有权访问某个分组（用于写入/读取该分组的数据）。

    管理员可访问任意分组；普通用户只能访问自己所属的分组。
    允许 group_id 为 None 的情况由调用方自行决定（此处仅校验归属）。
    """
    if user.is_admin:
        return
    if group_id is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="必须指定所属分组")
    ids = get_user_group_ids(db, user)
    if group_id not in ids:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="无权访问该分组的数据")
