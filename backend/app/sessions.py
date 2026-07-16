"""登录会话（服务端强制失效）核心。

JWT 本身无状态，签发后到过期前都可用，无法在「登出 / 空闲超时」后令其作废。
本模块用 `auth_sessions` 表为每张令牌记录一个服务端会话，从而：

- 登出时吊销该会话 → 令牌立即失效（即使被截获也无法再用）。
- 服务端按 `last_activity` 检测空闲：距上次请求超过 `SESSION_IDLE_SECONDS` 即吊销，
  作为前端空闲登出的兜底（前端因故未上报时也生效）。

所有函数均接收 SQLAlchemy Session，便于在依赖中直接调用。
"""

import secrets
import time

from .config import SESSION_IDLE_SECONDS
from .db import get_db
from .models import AuthSession

# last_activity 写入节流：距上次写超过该秒数才更新，降低高频请求的 DB 写压力
_LAST_ACTIVITY_WRITE_GAP = 15


def new_jti() -> str:
    """生成一个全局唯一的会话 id。"""
    return secrets.token_hex(16)


def create_session(db, user_id: int, jti: str, ip: str = "") -> AuthSession:
    """登录成功时调用：为本次令牌建立服务端会话。ip 为登录时的客户端 IP。"""
    now = int(time.time())
    sess = AuthSession(
        jti=jti,
        user_id=user_id,
        created_at=now,
        last_activity=now,
        revoked=False,
        ip=ip or "",
    )
    db.add(sess)
    db.commit()
    return sess


def revoke_other_sessions(db, user_id: int, current_jti: str) -> int:
    """单账号单会话：吊销该用户除 current_jti 之外的所有会话（含其他 IP 的登录）。

    新登录成功后调用，保证「同一账号只能在一个登录态下有效」——
    无论新登录来自哪个 IP，此前该账号在其它 IP 上的登录都会立即失效。
    返回被吊销的会话数。
    """
    n = (
        db.query(AuthSession)
        .filter(
            AuthSession.user_id == user_id,
            AuthSession.jti != current_jti,
            AuthSession.revoked == False,
        )
        .update({AuthSession.revoked: True})
    )
    db.commit()
    return n


def revoke_session(db, jti: str) -> None:
    """吊销指定会话（登出时调用）。jti 无效也不报错。"""
    if not jti:
        return
    sess = db.query(AuthSession).filter_by(jti=jti).first()
    if sess and not sess.revoked:
        sess.revoked = True
        db.commit()


def touch_session(db, jti: str) -> bool:
    """显式刷新会话最近活动时间（前端空闲监听在用户操作系统时周期调用）。

    用于让「服务端空闲计时」与「真实用户操作」对齐：用户即便只做纯前端操作
    （不打业务 API），只要在操作，服务端就不会因空闲而吊销令牌。
    返回会话当前是否有效（已吊销 / 不存在 / 无 jti 返回 False）。
    """
    if not jti:
        return False
    sess = db.query(AuthSession).filter_by(jti=jti).first()
    if sess is None or sess.revoked:
        return False
    sess.last_activity = int(time.time())
    db.commit()
    return True


def is_session_valid(db, jti: str):
    """校验会话是否有效，并在有效时刷新空闲计时。

    返回 (valid: bool, reason: str)：
    - ("none")   无 jti（旧令牌）/ 会话不存在 → 视为登录失效。
    - ("revoked") 会话已被吊销（登出 / 被新登录踢下线）→ 登录失效。
    - ("idle")    距 last_activity 超过 SESSION_IDLE_SECONDS → 吊销并返回失效。
    - ("", True) 有效，且已（节流）刷新空闲计时。
    """
    if not jti:
        return False, "none"
    sess = db.query(AuthSession).filter_by(jti=jti).first()
    if sess is None:
        return False, "none"
    if sess.revoked:
        return False, "revoked"

    now = time.time()
    last = sess.last_activity
    # 服务端空闲超时：直接吊销，令牌立即作废
    if now - last > SESSION_IDLE_SECONDS:
        sess.revoked = True
        db.commit()
        return False, "idle"

    # 节流刷新最近活动时间
    if now - last > _LAST_ACTIVITY_WRITE_GAP:
        sess.last_activity = int(now)
        db.commit()
    return True, ""
