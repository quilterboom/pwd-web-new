# 密码管理 · 服务端加解密密码管理器

一个面向团队的 **零知识密码保险箱**。每条密码由用户自己的「解密密码」保护（PBKDF2-SM3 + SM4-CBC），**服务端永远拿不到你的明文密码**——即便数据库泄露，没有「解密密码」依然无法还原。适用于需要集中托管密钥、审计密码变更、按分组隔离可见性的内部场景。

## 加密体系（先看这里）

本工具默认走**零知识方案**，所有数据使用「外层非对称（可选 GPG / SM2）+ 内层 SM4-CBC 对称」的双层加密；对称方案则只有内层。每层的密码都由对应密钥独立掌握，服务端不持有任何能直接解出明文的密钥。

| 数据类型 | 默认加密方案 | 服务端能否解出明文 | 说明 |
| --- | --- | --- | --- |
| **密码条目（对称）** | `symmetric` —— 每条独立的「解密密码」做 PBKDF2-SM3 + SM4-CBC | ❌ **不能** | 默认行为。任何算法下都会加这一层（即使外层是 GPG/SM2）。服务端只存 salt/iv/密文，没有「解密密码」还原不了明文。 |
| **密码条目（GPG / SM2）** | 外层用所选 OrgKey 公钥（或回退服务端密钥）加密内层 SM4-CBC 密文 | ❌ **不能** | 「外层非对称 + 内层对称」双重保护。私钥在服务端时属于历史遗留兼容场景，新数据仍走对称层。 |
| **密钥库条目** | 公钥必填、私钥可选（无口令保护） | ✅ 仅在持有私钥时能 | 多密钥支持：每分组可保存多对命名密钥（GPG / SM2）。 |

> **零知识方案的含义**：即便数据库泄露，没有「解密密码」依然无法还原明文。
> 「解密密码」**不会**被持久化，每次查看/修改由用户在弹窗中输入、随请求传至服务端。

## 功能

- ✅ **零知识密码存储**：每条密码由用户自己的「解密密码」保护（PBKDF2-SM3 + SM4-CBC），服务端不可解密。
- ✅ **完整 CRUD**：密码查看 / 新增 / 修改 / 删除。
  - 新增：选择加密算法（**对称零知识** / GPG / SM2），任何算法都必须设置一条「解密密码」并要求输入两次确认。
  - 编辑：受「解密密码」保护的条目先弹锁框输入当前密码，解密回填后才能编辑；可单独设置新「解密密码」。
  - 查看：「解密密码」保护时通过 `POST /{id}/unlock` 在请求体中传入密码解密。
- ✅ **组织密钥库**：在「密钥库」页签查看 / 生成 / 导入 / 导出本组织下的 GPG 与 SM2 密钥对；公钥下载便于给他人加密、私钥下载自留；按组织隔离，非管理员只看自己所属组织。
- ✅ **批量明文导出**：多选密码 → 一次性输入或逐项填写各条目的「解密密码」→ 下载 JSON / CSV（仅含明文）。解压密码通过请求体传，不会出现在 URL / 访问日志 / 浏览器历史中。
- ✅ **修改记录（审计日志）**：每次新增、修改、删除都留下时间、操作人、变更说明（自动汉化变更字段），仅存密文快照不存明文。
- ✅ **多账号 + 分组隔离**：管理员可新增账号；数据按分组绑定，普通用户只看到所属分组的数据，管理员可跨组查看。
- ✅ **系统管理面板**：在界面上管理账号（创建 / 编辑 / 删除 / 分配分组）和分组（创建 / 编辑成员 / 删除，分组有数据时阻止删除）。
- ✅ **简单登录**：JWT 登录（`passlib` + `bcrypt`）。
- ✅ **SQLite 本地存储**：零外部依赖，开箱即用。平滑迁移：旧库首次启动自动加列、存量数据归入默认分组。
- ✅ **完全离线可用**：前端无 CDN 依赖，加解密全部为纯 Python 实现（`pgpy` / `gmssl`），运行时无任何外部网络请求。

## 技术栈

| 层 | 选型 |
| --- | --- |
| 后端 | Python + FastAPI + SQLAlchemy |
| 加密 | `pgpy`（GPG/OpenPGP）、`gmssl`（SM2 / SM3 / SM4）+ `cryptography` 的 `hashes.SM3` 用于加速 PBKDF2 |
| 存储 | SQLite |
| 认证 | JWT（PyJWT）+ bcrypt |
| 前端 | 原生 HTML / CSS / JS（由后端静态托管） |

## 目录结构

```
pwd-web/
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI 入口，挂载 API 与静态资源
│   │   ├── config.py            # 配置（端口、密钥、管理员）
│   │   ├── db.py                # SQLAlchemy 引擎 / Session
│   │   ├── models.py            # User / Group / KeyRecord / OrgKey / PasswordEntry / History
│   │   ├── security.py          # 密码哈希 + JWT
│   │   ├── seed.py              # 首次启动初始化（建表、管理员、默认分组、密钥）
│   │   ├── crypto/
│   │   │   ├── gpg_crypto.py    # GPG/OpenPGP 加解密（pgpy）
│   │   │   ├── sm2_crypto.py    # SM2 加解密（gmssl）
│   │   │   ├── entry_cipher.py  # 条目密码对称加密（PBKDF2-SM3 + SM4-CBC）
│   │   │   └── manager.py       # 算法分发与密钥读取
│   │   ├── core/deps.py         # 认证与分组权限依赖
│   │   ├── routers/             # auth / passwords / history / keys / admin
│   │   └── static/              # 前端 index.html / app.js / styles.css
│   ├── run.py                   # 启动脚本
│   ├── requirements.txt
│   ├── Dockerfile               # 容器镜像构建（支持离线 / 联网两种依赖来源）
│   ├── offline/                 # 离线部署套件（build_image、get_wheels、install、systemd、smoke_* 冒烟脚本）
│   └── .env.example
├── docker-compose.yml           # 容器编排（端口 / 卷 / 环境变量，platform=linux/amd64）
└── README.md
```

## 快速开始（直接跑 Python）

### 1. 准备 Python 虚拟环境（推荐 3.13）

```bash
cd backend
python -m venv venv
# Windows
venv\Scripts\pip install -r requirements.txt
# 或 macOS / Linux
python -m venv venv && venv/bin/pip install -r requirements.txt
```

### 2. 配置环境变量（可选）

复制 `backend/.env.example` 为 `backend/.env` 并按需修改，**至少改掉默认管理员密码**：

```ini
ADMIN_USERNAME=admin
ADMIN_PASSWORD=请改成强密码
```

> 若不设置 `SECRET_KEY`，服务会在 `backend/data/.secret_key` 自动生成并持久化，避免重启后令牌失效。

### 3. 启动

```bash
# 在 backend/ 目录下
venv\Scripts\python run.py        # Windows
# 或
venv/bin/python run.py            # macOS / Linux
```

启动后访问 <http://localhost:9010> ，使用环境变量中的管理员账号登录（默认 `admin / admin123`）。

### 4. 使用（首次添加密码）

1. 用管理员登录后，在「密码」页签点 **新增密码**。
2. 填写账号 / 密码明文 / 备注 / **所属分组**。
3. 选择**加密方式**（默认「对称加密（条目密码，零知识）」）。GPG / SM2 时可选择本组织 OrgKey，否则使用服务端默认密钥。
4. **必填：「解密密码」** —— 无论采用哪种加密方式都必须填写一次、且新增时需要两次确认。**该密码一旦忘记无法找回**（这是零知识方案的代价）。
5. 保存后，列表里会出现这一条；点击查看需输入刚才设置的「解密密码」。

## 离线部署（不用 Docker，纯 Python）

本工具**完全离线可用**：前端无 CDN，加解密均为纯 Python 实现（`pgpy` / `gmssl`），运行时不访问任何外部网络。只需在离线服务器上装好 Python（建议 3.13）并装好依赖。

### 第 1 步：在一台「联网且与目标服务器 OS / Python 版本相同」的机器上准备依赖包

```bash
# Windows
backend\offline\get_wheels.bat
# Linux / macOS
bash backend/offline/get_wheels.sh
```

这会把所有依赖（含 `pgpy` 源码包构建所需的 setuptools / wheel）下载到 `backend/offline/wheels/`。

> ⚠️ 依赖包是**平台相关**的（`cryptography` / `bcrypt` / `watchfiles` 等含编译产物）。
> 若目标服务器是 **Linux**，必须在同架构的 Linux 机器上跑 `get_wheels.sh`；
> 当前仓库自带的 `offline/wheels/` 是 **Windows** 版本，仅供 Windows 目标服务器直接使用。
> 若目标为 Linux x86_64，也可在任意联网机器上跨平台下载：
> ```bash
> pip download -r requirements.txt setuptools wheel \
>   --platform manylinux2014_x86_64 --python-version 313 --abi cp313 \
>   --dest offline/wheels
> ```

### 第 2 步：把整个项目拷贝到离线服务器，安装依赖

将含 `backend/offline/wheels/` 的整个目录拷贝到离线服务器，然后：

```bash
# Windows
backend\offline\install.bat
# Linux / macOS
bash backend/offline/install.sh
```

脚本会创建本地 `venv` 并用 `--no-index` 从本地 wheels 安装，**全程不联网**。

### 第 3 步：启动

```bash
# Windows
backend\venv\Scripts\python run.py
# Linux
backend/venv/bin/python run.py
```

### Linux 以系统服务常驻（systemd）

示例单元文件见 `backend/offline/password-manager.service`。部署时：

```bash
# 假设项目放在 /opt/password-manager，并创建专用用户 password-manager
sudo cp backend/offline/password-manager.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now password-manager
```

## Docker 部署

容器镜像**自包含**：依赖在构建期已固化进镜像，运行时零联网，非常适合离线服务器。

整体思路：在一台**能联网**的机器上构建镜像并导出成 tar 包，再把 tar 包与 `docker-compose.yml` 一起拷到离线服务器加载运行。

### 平台与架构

- **目标服务器**：Linux x86_64（标准）。
- **构建脚本已固化 `--platform linux/amd64`**：即便构建主机是 Apple Silicon（arm64），也会产出可在 x86_64 服务器运行的镜像（通过 QEMU 模拟）。
- **`docker-compose.yml` 也已声明 `platform: linux/amd64`**，compose up / build 行为一致。

### 第 1 步：在联网机器上构建并导出镜像

```bash
# 联网构建（依赖从 PyPI 拉取），导出为 backend/offline/password_manager_image.tar
bash backend/offline/build_image.sh          # Linux / macOS
# 或  backend\offline\build_image.bat         # Windows

# 完全离线构建（依赖来自 offline/wheels 中已准备好的 Linux 版依赖包）
bash backend/offline/build_image.sh offline
```

导出后的 tar 包约 **222MB**（含全部加密算法 + OrgKey 库）。

> ⚠️ 离线构建时，`backend/offline/wheels/` 必须是 **Linux (manylinux x86_64, cp313)** 版依赖包，
> 可用 `get_wheels.sh` 配合 `--platform manylinux2014_x86_64 --python-version 313 --abi cp313` 在任意联网机下载。

### 第 2 步：在离线服务器加载并启动

```bash
# 1) 加载镜像（无需联网）
docker load -i backend/offline/password_manager_image.tar

# 2) 启动（建议先用环境变量覆盖管理员密码）
ADMIN_PASSWORD='请改成强密码' docker compose up -d
```

> ⚠️ 若离线服务器是老版 Docker（缺 compose v2 插件），`docker compose` 会报
> `unknown shorthand flag: 'd'`。请改用 `docker run`：
> ```bash
> docker run -d --name password-manager --platform linux/amd64 \
>   -p 9010:9010 \
>   -v $(pwd)/backend/data:/app/data \
>   -e ADMIN_PASSWORD='请改成强密码' \
>   --restart unless-stopped \
>   password-manager:latest
> ```

启动后访问 <http://localhost:9010> 。`docker-compose.yml` 已做：

- 端口映射 `${PORT:-9010}:9010`
- 数据卷 `./backend/data:/app/data`（数据库 + JWT 密钥持久化）
- `restart: unless-stopped` 自动重启
- 强制 `platform: linux/amd64`

> 若是 Windows 目标服务器，直接用 **Docker Desktop + 联网构建** 即可，无需 tar 包搬运：
> 在该机器上 `docker compose up -d --build` 即可（要求 Docker Desktop 能访问 PyPI）。

## 安全说明

- **明文走网络**：加解密在服务端进行，查看 / 新增 / 明文批量导出时，「解密密码」会通过 HTTP 传输。生产环境务必启用 **HTTPS**（反向代理如 Nginx / Caddy 配置 TLS）。
- **私钥保护**：数据库中 GPG / SM2 私钥以明文存储（用于兼容旧 `legacy` 密码条目）；新增条目默认走对称方案，服务端密钥不再是解密主路径。生产环境建议：
  - 对 `data/password_manager.db` 做文件权限限制与备份加密；
  - 或将私钥字段改为使用主密钥（环境变量 `SECRET_KEY`）加密后再落库。
- **零知识密码条目不受私钥泄露影响**：因「解密密码」独立派生 SM4 密钥，服务端密钥仅兼容 legacy 数据。
- **JWT 有效期**：默认 24 小时，可用 `TOKEN_EXPIRE_MINUTES` 调整。
- **CORS**：当前为 `allow_origins=["*"]`，仅适用于内网工具部署；公网部署请收敛 origin。

## API 一览

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/auth/login` | 登录获取 token |
| GET | `/api/auth/me` | 当前用户（含可见分组） |
| GET | `/api/keys/status` | 服务端密钥就绪情况（兼容 legacy 方案） |
| GET | `/api/orgkeys?group_id=&algorithm=` | 组织密钥库列表（按分组 + 算法过滤；非管理员看自己所属组织） |
| POST | `/api/orgkeys/generate` | 新建密钥（GPG / SM2，公私钥完整生成） |
| POST | `/api/orgkeys/import` | 导入密钥（公钥必填、私钥可选；带 round-trip 自检；私钥必须**无口令保护**） |
| GET | `/api/orgkeys/{kid}/export?kind=public\|private` | 导出公钥 / 私钥为附件下载（双 Content-Disposition 兼容中文文件名） |
| DELETE | `/api/orgkeys/{kid}` | 删除密钥记录 |
| GET | `/api/passwords` | 密码列表（不含明文） |
| POST | `/api/passwords` | 新增（**必填**：`secret` `group_id` `entry_password`；另可选 `algorithm`、`orgkey_id`、`comment`） |
| GET | `/api/passwords/{id}` | 查看（旧式 `legacy` 免条目密码；`entry` 受保护请用 unlock） |
| POST | `/api/passwords/{id}/unlock` | 解密（请求体 JSON `{entry_password}`，不在 URL 中） |
| PUT | `/api/passwords/{id}` | 修改（`entry` 方案需 `entry_password`；可选 `new_entry_password` 改密；可选 `comment`） |
| DELETE | `/api/passwords/{id}` | 删除（软删除 + 记审计） |
| GET | `/api/passwords/{id}/history` | 修改记录 |
| POST | `/api/passwords/export` | 批量明文导出（请求体 JSON `{ids, passwords, format}`，无加密备份） |
| GET | `/api/groups/mine` | 当前用户可见分组（用于创建数据时的下拉） |
| GET | `/api/admin/users` | 账号列表（仅管理员） |
| POST | `/api/admin/users` | 新增账号（含分组归属） |
| PUT | `/api/admin/users/{uid}` | 编辑账号（密码 / 管理员标记 / 分组） |
| DELETE | `/api/admin/users/{uid}` | 删除账号 |
| GET | `/api/admin/groups` | 分组列表（含成员） |
| POST | `/api/admin/groups` | 新增分组（含成员） |
| PUT | `/api/admin/groups/{gid}` | 编辑分组（名称 / 成员） |
| DELETE | `/api/admin/groups/{gid}` | 删除分组（有数据时阻止） |

## 修改记录（审计）示例

每条密码的变更都会保存在 `history` 表，前端「记录」按钮可查看：

| 时间 | 动作 | 账号 | 算法 | 操作人 | 说明 |
| --- | --- | --- | --- | --- | --- |
| 2026-07-08 11:00 | 新增 | root | 对称加密 | admin | 新增密码 |
| 2026-07-08 15:20 | 修改 | root | 对称加密 | admin | 修改了密码明文、解密密码 |
| 2026-07-08 16:01 | 删除 | root | 对称加密 | admin | 删除密码 |
