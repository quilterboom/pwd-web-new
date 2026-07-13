from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Table, Text
from sqlalchemy.orm import relationship

from .db import Base


def _utcnow():
    return datetime.now(timezone.utc)


# 用户 <-> 分组 多对多关联表（作为「普通成员」所属的分组）
user_groups = Table(
    "user_groups",
    Base.metadata,
    Column("user_id", ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("group_id", ForeignKey("groups.id", ondelete="CASCADE"), primary_key=True),
)

# 用户 <-> 分组 多对多关联表（作为「管理员」可管理的分组）
# 为空表示「超级管理员」——管理全部分组；非空表示「分组管理员」——仅管理指定的分组。
user_admin_groups = Table(
    "user_admin_groups",
    Base.metadata,
    Column("user_id", ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("group_id", ForeignKey("groups.id", ondelete="CASCADE"), primary_key=True),
)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    # 新方案：SCRAM-SM3 风格「挑战-响应」凭据。
    # pw_salt     : 16 字节随机盐（hex）；pw_verifier : SM3(password || pw_salt)（hex）
    # 为空表示用户仍是 legacy 模式（旧密码登录时一次性自动迁移到新方案）。
    pw_salt = Column(String(64), default="")
    pw_verifier = Column(String(128), default="")
    is_admin = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=_utcnow)

    groups = relationship("Group", secondary=user_groups, back_populates="members")


class Group(Base):
    """分组：数据（密码 / 文件）按分组绑定，用户仅能查看所属分组的数据。"""

    __tablename__ = "groups"

    id = Column(Integer, primary_key=True)
    name = Column(String(64), unique=True, nullable=False, index=True)
    description = Column(String(255), default="")
    created_at = Column(DateTime, default=_utcnow)

    members = relationship("User", secondary=user_groups, back_populates="groups")


class KeyRecord(Base):
    """服务端持有的加解密密钥对。algorithm 取值 'gpg' 或 'sm2'。"""

    __tablename__ = "keys"

    id = Column(Integer, primary_key=True)
    algorithm = Column(String(16), unique=True, nullable=False, index=True)
    public_key = Column(Text, nullable=False)
    private_key = Column(Text, nullable=False)
    created_at = Column(DateTime, default=_utcnow)


class OrgKey(Base):
    """组织级密钥库：每个分组可保存多对命名密钥（公钥 + 可选私钥）。

    用于在团队/部门内部分发加密用的公钥，或导入外部公钥做共享加密。
    私钥字段允许为空（仅公钥条目常用于「只需对方能解密但本地不持有私钥」的场景）。
    """

    __tablename__ = "org_keys"

    id = Column(Integer, primary_key=True)
    group_id = Column(Integer, ForeignKey("groups.id", ondelete="CASCADE"), index=True, nullable=False)
    name = Column(String(128), nullable=False)  # 用户起的名字，例如 "研发中心 GPG 主密钥"
    algorithm = Column(String(16), nullable=False)  # 'gpg' | 'sm2'
    public_key = Column(Text, nullable=False)
    private_key = Column(Text, nullable=True)
    fingerprint = Column(String(64), default="")  # 指纹/标识，方便识别密钥
    has_private = Column(Boolean, nullable=False, default=False)  # 是否存有私钥（便于前端显示）
    # 私钥口令保护（GPG 私钥可能受 passphrase 保护）。
    # private_protected   : True 表示该私钥在导入时本身已带口令（用 passphrase 解锁才能解密 / 签名）
    # private_passphrase  : 口令本身（受保护的私钥在导入时已要求用户填写并与服务端数据一起保存；
    #                       后续所有解锁 / 签名 / 解密都使用这个口令）。为空表示私钥未受保护。
    private_protected = Column(Boolean, nullable=False, default=False)
    private_passphrase = Column(String(255), default="")
    # 历史遗留列：老版本库里 ``is_protected`` 用于 pgpy 私钥 password 保护（无口令时也置 true 是错的），
    # 仅仅为了不破坏老库的 NOT NULL 约束。真实判定请使用 ``private_protected``。
    is_protected = Column(Boolean, nullable=False, default=False)
    created_by = Column(String(64), default="")
    created_at = Column(DateTime, default=_utcnow)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)


class PasswordEntry(Base):
    __tablename__ = "passwords"

    id = Column(Integer, primary_key=True)
    title = Column(String(255), nullable=True, default="")  # 密码文件名称（条目显示名）；新增时由前端必填
    username = Column(String(255), default="")
    # algorithm: 'gpg' | 'sm2' 为 legacy 方案，'symmetric' 为每条独立密码加密
    algorithm = Column(String(16), nullable=False, default="symmetric")
    # scheme: 'legacy' = legacy 方案（兼容旧数据）；
    #         'entry'  = 每条密码用自己的「条目密码」对称加密（服务端不持有密钥，查看/修改必须输密码）
    scheme = Column(String(16), default="legacy")
    ciphertext = Column(Text, nullable=False)  # legacy: gpg armored / sm2 base64；entry: SM4-CBC 十六进制密文
    entry_salt = Column(String(64), default="")  # entry 方案：PBKDF2-SM3 的 salt（hex）
    entry_iv = Column(String(64), default="")  # entry 方案：SM4-CBC 的 iv（hex）
    notes = Column(Text, default="")
    system = Column(String(255), default="")  # 系统（如邮箱 / 服务器 / GitLab），自由文本
    group_id = Column(Integer, index=True, nullable=True)  # 绑定分组
    orgkey_id = Column(Integer, ForeignKey("org_keys.id", ondelete="SET NULL"), index=True, nullable=True)  # legacy 方案使用的 OrgKey（选用，不填则用服务端 KeyRecord）
    created_at = Column(DateTime, default=_utcnow)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)
    created_by = Column(String(64), default="")
    updated_by = Column(String(64), default="")
    deleted = Column(Boolean, default=False)


class History(Base):
    """修改记录（审计日志）。仅保存加密后的密文快照，绝不落库明文。"""

    __tablename__ = "history"

    id = Column(Integer, primary_key=True)
    password_id = Column(Integer, index=True)
    group_id = Column(Integer, index=True, nullable=True)
    action = Column(String(16), nullable=False)  # create | update | delete
    title = Column(String(255))
    username = Column(String(255))
    system = Column(String(255), default="")  # 系统（与 PasswordEntry.system 对应，用于审计）
    algorithm = Column(String(16))
    ciphertext = Column(Text)  # 该次操作时的密文快照（用于审计，不包含明文）
    notes = Column(Text)
    changed_by = Column(String(64))
    changed_at = Column(DateTime, default=_utcnow)
    comment = Column(String(255))  # 人类可读说明，如“修改了 secret,notes”

