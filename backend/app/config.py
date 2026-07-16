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
