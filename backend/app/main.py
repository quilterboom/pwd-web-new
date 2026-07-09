from contextlib import asynccontextmanager

from fastapi import FastAPI
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

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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
