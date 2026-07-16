# 离线部署指南（Offline Deployment）

本指南适用于**目标服务器无外网**的场景：在一台能联网的机器上构建并导出镜像，再把镜像与少量文件拷到内网服务器运行。

> 本文档与 `docker-compose.yml`、`.env.example` 配套使用。如有冲突，以这两个文件为准。

---

## 一、需要传到离线服务器的文件

保持如下目录结构（因为 `docker-compose.yml` 使用相对路径 `./backend/ssl` 与 `./backend/data`）：

```
<任意目录，例如 /opt/passwd>/
├── docker-compose.yml              ← 项目根目录那个
├── .env                            ← 由 .env.example 复制而来，填好密码与 SSL 路径（见下）
└── backend/
    ├── offline/
    │   └── password_manager_image.tar   ← 镜像（约 226MB）
    └── ssl/                        ← 放证书（见第三节）
        ├── server.crt
        └── server.key
```

说明：
- `backend/data/` **不用传**，Docker 首次启动会自动建空目录并持久化数据库与密钥。
- `gen_cert.sh` 不是必须文件；若证书在目标服务器本地生成（推荐），可把它也带上。

---

## 二、SSL 证书（HTTPS 必需）

证书必须包含目标服务器的 **IP / 域名**，所以**推荐在离线服务器本地生成**：

```bash
# 在目标服务器上（需已装 openssl）
bash backend/offline/gen_cert.sh <服务器IP> <域名>
# 例：bash backend/offline/gen_cert.sh 192.168.1.10 pm.internal.com
```

产物（`server.crt` / `server.key`）会落到 `backend/ssl/`，compose 已将其只读挂载到容器的 `/app/ssl`。

> 也可在任意装有 openssl 的机器提前生成，再把 `backend/ssl/` 整个目录拷过去——注意 IP/域名要填**目标服务器**的。

---

## 三、配置 `.env`

放在项目根目录（与 `docker-compose.yml` 同级）。最简单：

```bash
cp .env.example .env
```

然后至少修改：管理员初始密码、并启用 HTTPS（取消 SSL 两行注释）。

### 完整环境变量说明

| 变量 | 默认值 | 说明 |
|---|---|---|
| `HOST` | `0.0.0.0` | 容器内监听地址（一般无需改） |
| `PORT` | `9010` | HTTPS 监听端口 |
| `TOKEN_EXPIRE_MINUTES` | `1440` | 登录令牌有效期（分钟），默认 24 小时 |
| `ADMIN_USERNAME` | `admin` | 首次初始化创建的管理员账号名 |
| `ADMIN_PASSWORD` | `admin123` | **首次初始化**的管理员密码（生产务必改强）；账号已存在时改此值无效，需登录后用「修改密码」改 |
| `ALLOW_REGISTRATION` | `0` | 自助注册总开关。`0` 关闭；`1` 允许任意访客在登录页注册为普通用户 |
| `REGISTER_DEFAULT_GROUP` | （空） | 自助注册用户自动加入的分组，不填用系统默认分组 |
| `SECRET_KEY` | （空） | 不填则自动生成并持久化到 `backend/data/.secret_key`，重启会话不失效 |
| `SESSION_IDLE_SECONDS` | `600` | 登录态空闲失效阈值（秒）。超过该时长无任何操作，令牌在服务端被吊销；任何携带该令牌的请求返回 401。前端会定时心跳重置计时（默认 10 分钟对齐） |
| `SSL_CERTFILE` | （空） | SSL 证书路径，如 `/app/ssl/server.crt`。**不设则维持明文 HTTP** |
| `SSL_KEYFILE` | （空） | SSL 私钥路径，如 `/app/ssl/server.key` |
| `SSL_REDIRECT` | `1` | 明文 HTTP 是否自动 307 跳转到 HTTPS（仅启用 SSL 时生效） |
| `HTTP_PORT` | `9080` | 明文 HTTP 端口，启用 SSL 时仅用于重定向 |
| `HSTS` | `0` | HSTS 响应头（仅 TLS 生效）。自签名证书建议保持 `0`，避免轮换时锁死浏览器 |

### 最小可用 `.env` 示例（HTTPS）

```ini
PORT=9010
TOKEN_EXPIRE_MINUTES=1440
ADMIN_USERNAME=admin
ADMIN_PASSWORD=这里改成强密码
ALLOW_REGISTRATION=0
SESSION_IDLE_SECONDS=600

# ── HTTPS ──
SSL_CERTFILE=/app/ssl/server.crt
SSL_KEYFILE=/app/ssl/server.key
SSL_REDIRECT=1
HTTP_PORT=9080
HSTS=0
```

> `.env` 含密码等机密，已被 `.gitignore` 忽略，**切勿提交到代码仓库**。

---

## 四、在离线服务器启动（无需联网）

```bash
# 1. 加载镜像（password_manager_image.tar 在 backend/offline/ 下）
docker load -i backend/offline/password_manager_image.tar

# 2. 启动（compose 读 .env，使用已加载的镜像，不会重新构建）
docker compose up -d
```

> 注意：`docker-compose.yml` 同时写了 `image:` 和 `build:`，只用 `up -d`（**不要加 `--build`**）就会直接用你 load 进来的镜像，不会触发联网构建。

---

## 五、访问

- **HTTPS**：`https://<服务器IP>:9010/`（或 `https://<域名>:9010/`）
- 明文 `http://<IP>:9080` 会自动 307 跳转到 HTTPS（`SSL_REDIRECT=1` 时）
- 自签名证书浏览器会提示「不受信任」，手动「继续 / 添加例外」即可（内网工具属正常）

---

## 六、升级已有版本（不丢数据）⚠️

**只要保留旧的 `backend/data/` 目录，上传新镜像并重启不会丢失任何数据。**

数据（数据库、JWT 密钥、文件保险箱）全部落在宿主机 `./backend/data`，不在镜像内。镜像只含代码，`docker load` + `docker compose up -d` 会把新容器挂到**同一个宿主机目录**，旧数据原样保留。

启动时的自动迁移是「只加列、不删表」——只补齐新版本需要的列（如 `auth_sessions.ip`），已有数据行原封不动。

升级步骤（在旧服务器、保留 `backend/data` 前提下）：

```bash
docker compose down
docker load -i backend/offline/password_manager_image.tar
docker compose up -d
```

唯一会导致数据丢失的坑：**不要把新项目里的空 `backend/data/` 覆盖到旧服务器上**。只更新「镜像 tar + `docker-compose.yml` + `.env` + `backend/ssl` 证书」，`backend/data/` 保持不变。

---

## 七、其它说明

- **管理员默认密码 `admin123` 太弱**：不配 `.env` 时即为该值，任何能访问站点的人都能登录。上线后第一件事请用顶栏「🔑 修改密码」改掉，或最好先在 `.env` 设强密码（仅 admin 尚不存在时生效）。
- **不配 `.env` 也能启动**：所有变量都有默认值，会以明文 HTTP + `admin/admin123` 运行，能跑但不安全也不加密。
- **JWT 密钥持久化**：`backend/data/.secret_key` 首次启动生成，升级后密钥不变 → 已登录用户会话不会失效。
- **单账号单会话**：新登录会吊销该账号所有其它登录态（含其它 IP），只有最新一次有效；被踢下线的用户会看到明确提示。
- 若需从源码本地构建（需要联网 + Node 环境），见 `docker-compose.yml` 顶部注释，执行 `bash backend/offline/build_image.sh` 重新生成 tar。
