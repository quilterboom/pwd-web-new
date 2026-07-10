# passwd-web 项目长期笔记

## 项目身份
- 路径：`D:\aicode\passwd-web-new`（后端源码 `backend/app`；**前端为 Vue3+Vite**：源 `backend/frontend/`，构建产物 `backend/frontend/dist/`；运行态由 FastAPI 从 `backend/app/static/`（即容器内 `/app/app/static`）同源托管）。
- 类型：FastAPI + SQLAlchemy + SQLite + pgpy/gmssl 离线密码保险箱；**前端已重构为 Vue3 SFC（Vite 构建，单文件 `app.js` 时代结束）**；多租户（按 group_id 隔离）。
- 部署：内网离线 x86_64 Linux（Docker 镜像 `password-manager`，tar `backend/offline/password_manager_image.tar`，**单阶段 Dockerfile，构建机预编译 `frontend/dist` 后 `COPY` 进镜像；镜像 ~318MB**）。

## 认证
- **SCRAM-SM3 登录**：`POST /api/auth/login/begin {username}` → 返回持久化 `pw_salt`+一次性`nonce`；前端算 `T=SM3(password||salt_raw)`、`proof=SM3(T||nonce_raw)`；`POST /api/auth/login/verify {username,nonce,proof}` 比对 `expected=SM3(pw_verifier||nonce)`。旧用户登录 `/api/auth/login` 成功自动迁移；前端 `doLogin` 遇 409 回退明文 `/login`。
- **JS SM3 关键**：拼接必须原始字节（`sm3Bytes` 拼接 `T_raw`+`nonce_raw`），不能把 hex 当 UTF-8 再哈希。常量 `_sm3Tj` 用 `0x79cc4519`/`0x7a879d8a`。
- **自助改密（2026-07-10 新增）**：`POST /api/auth/change-password/begin`（登录态，返 salt+nonce；legacy 用户返 `mode:"legacy"` 且无 salt/nonce） + `POST /api/auth/change-password/verify {nonce,proof,new_password | current_password,new_password}`。校验当前密码（SCRAM 优先，legacy 兜底 `verify_password`）后同时更新 `pw_salt`/`pw_verifier`/`hashed_password`。新密码≥8 位且不能与当前相同。所有登录用户可用（非管理员仅能改自己）。前端顶栏「🔑 修改密码」按钮（`changepw-modal` + `doChangePw`）。
- `User.pw_salt`(hex16B)+`pw_verifier`(SM3hex) 由 `security.derive_password_verifier` 生成；`routers/admin._seed_login_material` 共用。

## 加密体系
- 内层「解密密码」SM4-CBC（所有算法都先过此层，零知识）；外层 gpg/sm2 用 OrgKey 公钥再包一层。`needs_password = bool(entry_salt) and bool(entry_iv)`。
- GPG 私钥可带 passphrase：`OrgKey.private_protected`+`private_passphrase`；`manager.decrypt_with_orgkey(db,orgkey_id,ct,passphrase=None)` 优先用存的口令。
- 条目算法合法值 `VALID_ALGOS=("symmetric","gpg","sm2")`；**勿用 `manager.SUPPORTED`（仅 gpg/sm2）**校验条目算法（曾致导入 400）。

## 关键模块
- `routers/`：`auth.py`(begin/verify/legacy/change-password) `admin.py` `keys.py` `passwords.py`(含 `/template`·`/import` 须排在 `/{pid}` 前) `users_batch.py` `history.py`。
- `crypto/gpg_crypto.py` 顶部 stub `imghdr`（Py3.13 移除）；`core/deps.py` 权限核心 `get_current_user`/`require_admin`/`ensure_group_access`。

## ⚠️ 易踩的坑（保命）
- **路由顺序**：本 Starlette 版本 `{pid}:int` 先匹配路径再校验 int，`template`/`import` 等非 int 段不回退直接 422。同前缀静态路由必须定义在 `@router.get("/{pid}")` 之前。
- **docker commit 捕获 ENTRYPOINT（致命）**：临时容器若用 `--entrypoint sleep` 起，commit 后镜像 Entrypoint 变 `['sleep']` → `docker run` 报 `sleep: invalid time interval 'python'`。正确命令：`docker commit --change 'ENTRYPOINT ["python","run.py"]' --change 'CMD []' --change 'EXPOSE 9010' --change 'VOLUME ["/app/data"]' <容器> password-manager:latest`，commit 后 `docker inspect` 验 Entrypoint=python run.py。
- **docker cp 增量覆盖坑**：`rm -rf /app/app` 后 `docker cp` 已存在同名文件可能不覆盖（overlay 缓存）→ cp 后务必 `grep` 校验每个改动文件 + `py_compile`；个别未更新先 `docker exec rm -f` 再单独 cp。
- **DB 迁移必须「通用」**：`db._migrate_columns()` 扫描 `Base.metadata` 所有列 `ALTER TABLE ADD COLUMN` 补齐，绝不停回硬编码列清单（曾漏 `passwords.deleted` 致 500）。
- **`api()` 抛错必附 `e.status=res.status`**：`doLogin` 靠 `err.status===409` 判断迁移回退；只放中文 detail 则 `includes("409")` 永远 false。
- **provider 接口一致（SM2 passphrase）**：所有 decrypt/encrypt 签名对齐 gpg/sm2（SM2 的 decrypt 须加 `passphrase:str=None` 形参忽略），否则 SM2 解密 500。
- **沙箱强杀加密进程**：加密测试进容器跑；本机只 `py_compile`/`node --check`。
- **Dockerfile 静态资源 COPY 路径（致命）**：`WORKDIR /app` 下相对 COPY 目标会多嵌套一层。正确：`COPY frontend/dist ./app/static`（→ `/app/app/static`，正是 `main.py` 的 `STATIC_DIR`）。**绝不可写 `./app/app/static`**（会落 `/app/app/app/static`，应用读不到）。多阶段 `COPY --from` 在 Apple Silicon+QEMU 模拟 amd64 下出现过层物化异常（前端产物不物化或路径偏移），故本镜像改用**单阶段 + 宿主机预编译 `frontend/dist`**（静态资源与架构无关）再直接 COPY，目标路径显式可控、跨架构稳。`build_image.sh` 已含 `cd backend/frontend && npm install && npm run build` 预构建；`docker build` 用 `--no-cache` 避免陈旧前端缓存。
- **前端改动流程**：改 `backend/frontend/src/*` 后须 `cd backend/frontend && npm run build`（更新 `dist/`），再 `docker build`/`docker save`。已无 `?v=N` 机制（Vite 产物带 content-hash 文件名，天然长效缓存）。

## 验证
- E2E（需 live 容器如 `pm-test2` 9012）：
  - `e2e_import_test.py`：SCRAM 登录 + 模板/批量导入 + 导出权限（非管理员 403）+ 解密验证。
  - `e2e_changepw_test.py`：非管理员/管理员自助改密、错误当前密码 401、新密码过短 400、改后新密码可登录（最后还原 admin 密码）。
- 测试容器：`docker run -d --name pm-verify --platform linux/amd64 -p 9014:9010 -e ADMIN_PASSWORD='TestPass!2026' -v <干净绝对路径>:/app/data password-manager:latest`（**卷路径用项目内绝对路径**，Git Bash 的 /tmp 删不干净 WSL2 卷）。
- 容器内生成 GPG 受口令密钥见历史；冒烟脚本 `smoke_*.py` 作 500 回归护栏。
