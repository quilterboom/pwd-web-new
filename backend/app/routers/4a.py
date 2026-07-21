"""4A 统一认证接入（中广核 UAP 风格 OAuth2 授权码模式）。

流程：
  1. 未登录用户访问前端 → 前端调 /api/auth/4a/config
     （后端对 FOURA_AUTHORIZE_URL 做短超时探活，判断「4A 是否可达」）。
     - 可达：返回 authorize_url，前端直接 location.href 跳 4A 登录页。
     - 不可达 / 未启用：返回 reachable=false，前端回退普通账号密码登录。
  2. 用户在 4A 完成登录 → 4A 带着 code+state 重定向回 FOURA_REDIRECT_URI（即本回调）。
  3. 本回调：code → 换 access_token（FOURA_TOKEN_URL）→ 取用户信息（FOURA_USERINFO_URL）
     → 提取 usercode → 匹配本地用户 → 签发本系统 JWT → 重定向前端首页带 4a_token。
  4. 前端读取 4a_token 写入本地即完成登录。

所有地址/凭证均来自 config.FOURA_*（环境变量）。未启用或地址缺失时，探活失败、
所有 4A 端点安全降级为「不可达」，不影响普通登录。
"""

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import RedirectResponse
import json
import os
import time
import urllib.parse
import urllib.request
import urllib.error
from sqlalchemy.orm import Session

from ..config import (
    FOURA_ENABLED,
    FOURA_AUTHORIZE_URL,
    FOURA_TOKEN_URL,
    FOURA_USERINFO_URL,
    FOURA_CLIENT_ID,
    FOURA_STATE,
    FOURA_CLIENT_SECRET,
    FOURA_REDIRECT_URI,
    FOURA_USER_FIELD,
    FOURA_LOCAL_MATCH_FIELD,
    FOURA_TOKEN_METHOD,
    FOURA_USERINFO_METHOD,
    FOURA_PROBE_TIMEOUT,
)
from ..db import get_db
from ..models import User
from ..security import create_token
from ..sessions import create_session, new_jti, revoke_other_sessions

router = APIRouter(prefix="/api/auth/4a", tags=["4a"])


# ── 探活结果缓存：避免每次加载登录页都打 4A，降低延迟与误判 ──
_probe_cache = {"ok": None, "ts": 0.0}
_PROBE_TTL = 30.0


def _http_json(url: str, params: dict, method: str = "GET", timeout: float = 8.0):
    """极简 HTTP 客户端（标准库，无额外依赖）。GET 拼 query；POST 用 form 体。返回解析后的 dict。"""
    if not url:
        raise Exception("4A 接口地址未配置（请检查 FOURA_* 环境变量）")
    method = method.upper()
    if method == "GET":
        q = urllib.parse.urlencode(params)
        sep = "&" if "?" in url else "?"
        full = url + sep + q
        req = urllib.request.Request(full, method="GET")
    else:
        req = urllib.request.Request(
            url, data=urllib.parse.urlencode(params).encode("utf-8"), method="POST"
        )
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        # 4A 可能用非 200 表达业务错误，但仍返回 JSON
        body = e.read().decode("utf-8", "replace")
    try:
        return json.loads(body)
    except Exception:
        raise Exception("4A 返回非 JSON：" + body[:200])


def _probe_reachable() -> bool:
    """对 authorize URL 做短超时探测，判定 4A 是否可达。可达即视为「应当走 4A 登录」。"""
    if not FOURA_ENABLED or not FOURA_AUTHORIZE_URL:
        return False
    now = time.time()
    if _probe_cache["ok"] is not None and now - _probe_cache["ts"] < _PROBE_TTL:
        return _probe_cache["ok"]
    try:
        req = urllib.request.Request(FOURA_AUTHORIZE_URL, method="GET")
        # 不跟随重定向也能判定连通：捕获 HTTPError（3xx/4xx）即视为可达；
        # 仅在连接/超时等网络层异常时不可达。
        try:
            with urllib.request.urlopen(req, timeout=FOURA_PROBE_TIMEOUT) as resp:
                _ = resp.status
        except urllib.error.HTTPError:
            pass  # 3xx/4xx 仍说明服务在线
        _probe_cache["ok"] = True
        _probe_cache["ts"] = now
        return True
    except Exception:
        _probe_cache["ok"] = False
        _probe_cache["ts"] = now
        return False


def _build_authorize_url() -> str:
    q = urllib.parse.urlencode(
        {
            "response_type": "code",
            "client_id": FOURA_CLIENT_ID,
            "redirect_uri": FOURA_REDIRECT_URI,
            "state": FOURA_STATE,
        }
    )
    sep = "&" if "?" in FOURA_AUTHORIZE_URL else "?"
    return FOURA_AUTHORIZE_URL + sep + q


def _exchange_code(code: str) -> dict:
    params = {
        "grant_type": "authorization_code",
        "client_id": FOURA_CLIENT_ID,
        # 4A 约定：client_secret 用 state 的值（见 GH4AComponent）；允许用独立 secret 覆盖
        "client_secret": FOURA_CLIENT_SECRET or FOURA_STATE,
        "code": code,
        "redirect_uri": FOURA_REDIRECT_URI,
    }
    return _http_json(FOURA_TOKEN_URL, params, method=FOURA_TOKEN_METHOD)


def _fetch_userinfo(access_token: str) -> dict:
    params = {"access_token": access_token, "client_id": FOURA_CLIENT_ID}
    return _http_json(FOURA_USERINFO_URL, params, method=FOURA_USERINFO_METHOD)


@router.get("/config")
def foura_config():
    """公开端点：返回 4A 是否启用、是否可达、以及跳转地址。前端据此决定自动跳转还是回退普通登录。"""
    reachable = _probe_reachable()
    return {
        "enabled": bool(FOURA_ENABLED),
        "reachable": reachable,
        "authorize_url": _build_authorize_url() if reachable else "",
    }


@router.get("/callback")
def foura_callback(
    code: str = Query(None),
    state: str = Query(None),
    request: Request = None,
    db: Session = Depends(get_db),
):
    """4A 登录成功后的回跳地址（GET，由浏览器发起）。

    处理：code→token→userinfo→匹配本地用户→签发 JWT→重定向前端首页带 4a_token。
    任何失败都重定向前端 /login?4a_error=...，由登录页展示清晰错误，并允许用户改用普通登录。
    """
    if not code:
        return RedirectResponse(
            "/login?4a_error=" + urllib.parse.quote("4A 未返回授权码（code）")
        )
    # 防 CSRF：若配置了 state 且 4A 回传了 state，必须一致
    if FOURA_STATE and state and state != FOURA_STATE:
        return RedirectResponse(
            "/login?4a_error=" + urllib.parse.quote("4A 回传的 state 不一致，已拒绝（疑似 CSRF）")
        )
    try:
        token_json = _exchange_code(code)
        access_token = token_json.get("access_token")
        if not access_token:
            raise Exception("未能从 4A 换取到 access_token（检查令牌端点与凭证）")

        user_json = _fetch_userinfo(access_token)
        if user_json.get("error"):
            raise Exception("4A 返回错误：" + str(user_json.get("error")))
        # 提取用户唯一标识（优先配置字段，回退常见字段名）
        uc = (
            user_json.get(FOURA_USER_FIELD)
            or user_json.get("usercode")
            or user_json.get("username")
            or user_json.get("loginName")
        )
        if not uc:
            raise Exception(f"4A 未返回用户标识字段「{FOURA_USER_FIELD}」")

        # 匹配本地用户（默认按 username == usercode）
        match_field = FOURA_LOCAL_MATCH_FIELD or "username"
        user = db.query(User).filter_by(**{match_field: str(uc)}).first()
        if not user:
            raise Exception(
                f"本地不存在与 4A 账号（{uc}）对应的用户，请联系管理员创建或绑定"
            )

        # 签发本系统 JWT（单账号单会话，与 /login/verify 一致）
        jti = new_jti()
        ip = request.client.host if request and request.client else ""
        revoke_other_sessions(db, user.id, jti)
        create_session(db, user.id, jti, ip)
        jwt = create_token(user.username, jti)
        return RedirectResponse("/?4a_token=" + urllib.parse.quote(jwt))
    except Exception as e:
        return RedirectResponse(
            "/login?4a_error=" + urllib.parse.quote("4A 登录失败：" + str(e))
        )
