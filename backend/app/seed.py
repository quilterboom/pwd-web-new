"""首次启动的初始化：建表、创建管理员、生成加解密密钥、默认分组。

兼容旧库：db.init_db 内部会做增量加列迁移，已有数据不会丢失。
"""
from .crypto import manager
from .db import SessionLocal, init_db
from .config import ADMIN_USERNAME, ADMIN_PASSWORD, DEFAULT_GROUP_NAME
from .models import Group, User, user_groups
from .security import derive_password_verifier, hash_password


def _seed_login_material(user: User, password: str) -> None:
    """为新建 / 重置密码的账号同步写入 SCRAM-SM3 登录凭据（盐 + 验证器）。"""
    import secrets
    salt = secrets.token_bytes(16).hex()
    user.pw_salt = salt
    user.pw_verifier = derive_password_verifier(password, salt)


def seed():
    init_db()
    db = SessionLocal()
    try:
        # 管理员账号（带 is_admin 标记），同时写入 SCRAM-SM3 凭据便于登录加密迁移
        admin = db.query(User).filter_by(username=ADMIN_USERNAME).first()
        if admin is None:
            admin = User(
                username=ADMIN_USERNAME,
                hashed_password=hash_password(ADMIN_PASSWORD),
                is_admin=True,
            )
            _seed_login_material(admin, ADMIN_PASSWORD)
            db.add(admin)
            db.commit()
        else:
            if not admin.is_admin:
                admin.is_admin = True
            # 自动迁移：旧账号没有 SCRAM 凭据（pw_verifier 为空）时，本轮用配置文件里的初始密码派生凭据。
            # 注意：仅在库初始管理员还从未「改过密码」时这样做够安全；如果 admin 改过密码，
            # 且 pw_verifier 仍为空，说明其首次登录用的就是现在的 ADMIN_PASSWORD（首次重置就迁移）。
            if not admin.pw_verifier:
                admin.pw_salt = ""
                _seed_login_material(admin, ADMIN_PASSWORD)
            db.commit()

        # 默认分组，保证系统始终至少有一个分组可绑定数据
        group = db.query(Group).filter_by(name=DEFAULT_GROUP_NAME).first()
        if group is None:
            group = Group(name=DEFAULT_GROUP_NAME, description="系统默认分组")
            db.add(group)
            db.commit()
            db.refresh(group)

        # 管理员加入默认分组（便于以管理员身份直接创建数据）
        already = db.execute(
            user_groups.select().where(
                user_groups.c.user_id == admin.id,
                user_groups.c.group_id == group.id,
            )
        ).first()
        if not already:
            db.execute(
                user_groups.insert().values(user_id=admin.id, group_id=group.id)
            )
            db.commit()

        # 兼容旧库：把没有分组的存量数据（group_id 为 NULL）归到默认分组，
        # 避免升级后这些记录对普通用户“消失”。
        from .models import History, PasswordEntry

        for tbl in (PasswordEntry, History):
            db.query(tbl).filter_by(group_id=None).update(
                {tbl.group_id: group.id}, synchronize_session=False
            )
        db.commit()

        manager.ensure_keys(db)
    finally:
        db.close()
