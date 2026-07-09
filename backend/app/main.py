from contextlib import asynccontextmanager
import os

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pathlib import Path

from . import seed
from .routers import admin, auth, history, keys, passwords, users_batch
from .routers.keys import orgkeys_router

STATIC_DIR = Path(__file__).resolve().parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    # 启动时确保数据库、管理员账号与加解密密钥都已就绪
    seed.seed()
    yield


app = FastAPI(title="密码管理 - 服务端加解密密码管理器", lifespan=lifespan)

# CORS：本应用前端与 API 同源（均由本服务托管），默认不允许任何跨域来源；
# 仅在确实需要跨域访问时，通过环境变量 CORS_ALLOW_ORIGINS 显式指定（逗号分隔）。
# 应用使用 Bearer Token 鉴权（无 Cookie），故关闭 credentials，避免凭据型跨站风险。
_CORS_ORIGINS = [o.strip() for o in os.getenv("CORS_ALLOW_ORIGINS", "").split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    """统一补充安全响应头（点击劫持 / MIME 嗅探 / 引用泄露 / 内联脚本注入 等防护）。"""
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault(
        "Permissions-Policy", "geolocation=(), microphone=(), camera=(), payment=()"
    )
    # 严格 CSP：仅允许同源脚本/样式/图片/连接；frame-ancestors 'none' 防嵌套；
    # 因模板中存在内联 style 属性，style-src 保留 'unsafe-inline'（脚本一律外链，无需内联）。
    csp = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'"
    )
    response.headers.setdefault("Content-Security-Policy", csp)
    return response


app.include_router(auth.router)
app.include_router(admin.mine_router)
app.include_router(admin.users_router)
app.include_router(admin.groups_router)
app.include_router(admin.audit_router)
app.include_router(passwords.router)
app.include_router(history.router)
app.include_router(keys.router)
app.include_router(orgkeys_router)
app.include_router(users_batch.router)


# 前端静态资源（html/js/css）禁止浏览器缓存，避免“旧 app.js + 新 html（或反之）”资源不一致
# 导致的 handler 崩溃（例如 openAdd 给不存在的元素赋值）。API 响应不受影响。
# 注意：用子类在 get_response 里加头——@app.middleware 不会拦截 mounted 子应用(StaticFiles)的响应。
class NoCacheStaticFiles(StaticFiles):
    async def get_response(self, path: str, scope):
        response = await super().get_response(path, scope)
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response


# 挂载前端静态资源（html=True 时 "/" 会返回 index.html）
app.mount("/", NoCacheStaticFiles(directory=str(STATIC_DIR), html=True), name="static")
