"""应用配置。所有可外部化的参数都通过环境变量或本地持久文件提供。"""
import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent  # backend/
DATA_DIR = Path(os.getenv("DATA_DIR", BASE_DIR / "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = DATA_DIR / "password_manager.db"
DATABASE_URL = f"sqlite:///{DB_PATH}"

# 文件保险箱：加密后的文件落盘目录（数据库只存元数据）
FILES_DIR = DATA_DIR / "files"
FILES_DIR.mkdir(exist_ok=True)

# JWT 密钥：优先用环境变量，否则在 data/.secret_key 文件持久化（与数据库同目录，
# 便于 Docker 通过同一个卷挂载持久化，避免容器重启后令牌失效）。
SECRET_KEY_FILE = DATA_DIR / ".secret_key"
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    if SECRET_KEY_FILE.exists():
        SECRET_KEY = SECRET_KEY_FILE.read_text().strip()
    else:
        SECRET_KEY = secrets.token_hex(32)
        SECRET_KEY_FILE.write_text(SECRET_KEY)

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("TOKEN_EXPIRE_MINUTES", "1440"))  # 默认 24h

# 服务端「登录态空闲失效」阈值（秒）：距上次活动时间超过该值，令牌在服务端被吊销，
# 任何携带该令牌的请求都返回 401。与前端空闲自动登出（默认 10 分钟）保持一致；
# 该值是服务端兜底——即使前端因故未上报（如直接关标签页），服务端也会在空闲超时后失效令牌。
# 可通过环境变量 SESSION_IDLE_SECONDS 覆盖（单位：秒）。
SESSION_IDLE_SECONDS = int(os.getenv("SESSION_IDLE_SECONDS", "600"))  # 默认 10 分钟

# 首次启动时创建的管理员账号（生产环境务必通过环境变量覆盖）
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")

# 首次启动时自动创建的默认分组名称
DEFAULT_GROUP_NAME = os.getenv("DEFAULT_GROUP_NAME", "默认分组")

# 是否开放「自助注册」：默认关闭（"0"）。设为 1/true/yes/on 才允许任意访客注册为普通用户。
# 注意：开启后任何能访问站点的人都能建账号，请仅在可信内网或配合管理员审核流程时使用。
ALLOW_REGISTRATION = os.getenv("ALLOW_REGISTRATION", "0") in ("1", "true", "yes", "on")

# 自助注册用户自动加入的默认分组（默认与首次启动创建的默认分组一致，可用 REGISTER_DEFAULT_GROUP 覆盖）
REGISTER_DEFAULT_GROUP = os.getenv("REGISTER_DEFAULT_GROUP", DEFAULT_GROUP_NAME)

HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "9010"))

# ───── 4A 统一认证（中广核 UAP 风格 OAuth2 授权码）─────
# 全部通过环境变量提供；留空 / 不启用即不接入，登录页走普通账号密码。
# 启用后：未登录用户访问页面时，后端对 authorizeUrl 做短超时探活，
#   可达 → 前端自动跳转 4A 登录；不可达 → 回退普通账号密码登录。
FOURA_ENABLED = os.getenv("FOURA_ENABLED", "0") in ("1", "true", "yes", "on")
# 4A 各端点完整 URL（内网部署时填内网地址，例如 https://uap.xxx.cgnpc.com.cn/...）
FOURA_AUTHORIZE_URL = os.getenv("FOURA_AUTHORIZE_URL", "")
FOURA_TOKEN_URL = os.getenv("FOURA_TOKEN_URL", "")
FOURA_USERINFO_URL = os.getenv("FOURA_USERINFO_URL", "")
FOURA_CLIENT_ID = os.getenv("FOURA_CLIENT_ID", "")
# 4A 约定：把 state 的值当作 client_secret 发送（见 4A示例 GH4AComponent）；
# 若平台另有独立 secret，用 FOURA_CLIENT_SECRET 覆盖。
FOURA_STATE = os.getenv("FOURA_STATE", "")
FOURA_CLIENT_SECRET = os.getenv("FOURA_CLIENT_SECRET", "")
# 4A 登录成功后回跳本系统的地址（必须在 4A 平台侧登记）；例如 http://内网IP:9010/api/auth/4a/callback
FOURA_REDIRECT_URI = os.getenv("FOURA_REDIRECT_URI", "")
# 4A 返回 JSON 中的「用户唯一标识」字段名（4A示例为 usercode）
FOURA_USER_FIELD = os.getenv("FOURA_USER_FIELD", "usercode")
# 把上面的标识映射到本系统本地用户表的字段（默认 username）；如需按工号匹配可改 employee_no 等
FOURA_LOCAL_MATCH_FIELD = os.getenv("FOURA_LOCAL_MATCH_FIELD", "username")
# 4A 令牌/用户端点 HTTP 方法（4A示例用 GET；若平台要求 POST 改 POST）
FOURA_TOKEN_METHOD = os.getenv("FOURA_TOKEN_METHOD", "GET").upper()
FOURA_USERINFO_METHOD = os.getenv("FOURA_USERINFO_METHOD", "GET").upper()
# 探活超时（秒）：决定「请求得通」的判定快慢
FOURA_PROBE_TIMEOUT = float(os.getenv("FOURA_PROBE_TIMEOUT", "2"))
