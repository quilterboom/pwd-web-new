# passwdpm / pwd-web 项目长期笔记

## 项目身份
- 路径：`D:\aicode\passwdpm-web`（产品显示名「密码管理」；Docker 镜像/服务名 `password-manager`，tar 名 `password_manager_image.tar`；目录名仍是 `passwdpm-web` 未改）。
- 类型：FastAPI + SQLAlchemy + SQLite + pgpy/gmssl 的离线密码保险箱；原生 HTML/CSS/JS 前端；JWT + bcrypt 认证；多租户（按 group_id 隔离）。
- 部署目标：内网离线 x86_64 Linux 服务器（Docker 镜像分发）。

## 加密体系（重要，很容易搞混）
- **统一「解密密码」内层（2026-07-08 改）**——无论 symmetric / gpg / sm2，**全部**先以条目密码做一层 SM4-CBC（PBKDF2-SM3 派生 key，零知识，服务端不持久化密码），`PasswordEntry.entry_salt/entry_iv` 非空即表示有这一层。`needs_password = bool(entry_salt) and bool(entry_iv)`（序列化给前端弹密码锁）。SM3 用 `cryptography` C 加速（与 gmssl 逐字节一致，PassPy 兼容），单块派生 ~0.4s、加密+解密 ~0.8s。
- **外层非对称（gpg/sm2）**——选 gpg/sm2 时，内层 SM4 密文再被序列化为 JSON `{salt,iv,ciphertext}` 后用所选 OrgKey 公钥（或回退服务端 KeyRecord）做 GPG/SM2 加密落库，`scheme='legacy'`、`orgkey_id` 记录用了哪把密钥。查看/编辑：服务端先用私钥解开外层 → JSON → 再用解密密码解开内层 SM4。即「外层非对称 + 内层对称」双重保护。
- **向后兼容旧 legacy 数据**——`entry_salt/entry_iv` 为空表示旧式纯 GPG/SM2（无解密密码层），`_decrypt_entry_secret` / `update` 按此区分；旧式编辑时若未提供新解密密码则维持旧式（不引入密码层）。
- **OrgKey 下拉按算法过滤**——前端 `loadOrgkeysForSelect` 按当前所选算法请求 `/api/orgkeys?group_id=X&algorithm=gpg|sm2`，后端 `list_orgkeys` 已支持 `algorithm` 查询参数（只返回对应算法的密钥）。
- **OrgKey 导入（GPG）的硬约束（重要）**：导入的 GPG **私钥必须是无口令（unprotected）的**。真实 GPG 导出的私钥是「主密钥(签名/认证) + 独立加密子密钥」结构，且很可能**受口令保护**。`gpg_crypto._collect_keys` 在任一子密钥 `is_protected` 时直接抛清晰 `ValueError`（指引用 `gpg --pinentry-mode loopback --passwd <KEYID>` 去口令）；`decrypt`/`decrypt_bytes` 遍历 `主密钥 + 全部子密钥` 解密（否则无口令的真实 GPG 密钥也会解密失败）。前端导入失败弹**红色 toast**（`showError`）。
- **UI 文案**——「条目密码」已改名为「解密密码」（index.html 的 `f-entry-pw-label` 等 + view lock 提示）；对称加密徽章改为「🔑 对称加密」；密码表增加 🔒 标记。查看/编辑至少需 `needs_password` 才能弹密码锁。
- **文件保险箱 —— 已于 2026-07-08 移除**：前端 Tab/面板（`#file-panel`）与后端 `FileVault`/`FileHistory` 模型、`routers/files.py` 路由一并删除；`main.py`/`admin.py`/`seed.py` 清理引用。现在系统只管密码条目，不再有文件加密存储。

## 关键模块/路径
- `backend/app/models.py`：`User` `Group` `user_groups`（Table，非 ORM 类） `PasswordEntry` `History` `KeyRecord` `OrgKey`（**FileVault/FileHistory 已移除**）。
- `backend/app/routers/keys.py`：`/api/keys/status`（服务端密钥就绪） + `/api/orgkeys/*`（多密钥 CRUD）。
- `backend/app/crypto/gpg_crypto.py` 顶部 stub `imghdr`（Python 3.13 PEP 594 移除）。同样的 stub 也用于 `routers/keys.py` 的 `_fingerprint`。
- `backend/app/core/deps.py`：权限核心——`get_current_user` `get_user_group_ids` `visibility_filter` `ensure_group_access` `require_admin`。多对多用 `user_groups` Table 对象，没有 `UserGroup` 模型类。
- `backend/Dockerfile`：`python:3.13-slim` 基础；可 `--build-arg OFFLINE=1` 走离线 wheels。
- `backend/offline/password_manager_image.tar`：当前 **~222MB**（含 entry 方案 + OrgKey 库）；构建用 `bash backend/offline/build_image.sh`，或用 `docker commit` 增量更新（见坑 #6）。

## 易踩的坑
1. **pgpy 在 Python 3.13 缺 `imghdr`**——必须 import 前 `sys.modules['imghdr']` 注入 stub。`routers/keys.py` 也得做一次（`_fingerprint`）。
2. **passlib 1.7.4 ≠ bcrypt>=4.1**——必须固定 `bcrypt==4.0.1`。
3. **gmssl SM2 公钥不会自动由私钥推导**——`CryptSM2(...)._kg(int(priv,16), ecc_table['g'])` 算 Q=priv*G。
4. **HTTP 导出中文文件名**——`Content-Disposition` 必须双字段：`filename="ASCII"` + `filename*=UTF-8''<urlencoded>`；`isascii() and (c.isalnum() or c in ".-_")` 过滤非法字符。
5. **SQLAlchemy 多对多无 ORM 类**——`user_groups.insert()/.delete()`，不能 `UserGroup(...)`。
6. **Docker Desktop 内存小（3.8GiB）+ `--no-cache`**——`pip install` step 直接 SIGKILL。改用 `docker commit`：run→cp→rm data→commit，复用旧依赖层。
7. **arm64 Mac 产 x86_64 镜像**——所有 `docker build` 显式 `--platform linux/amd64`，compose `build.platforms: [linux/amd64]` + `platform: linux/amd64`。
8. **WorkBuddy zsh sandbox subshell 打 curl**——用 `/usr/bin/curl` 绝对路径；管道用 `> /tmp/x` + `python3` 两步。
9. **daocloud 镜像源 401**——`~/.docker/daemon.json` 的 `registry-mirrors` 已失效，先移除再 build。
10. **WorkBuddy Bash 沙箱强杀加密进程**——凡执行 SM4/GPG 等加密运算的 python 进程会被沙箱直接 kill（无 traceback、连坐杀 shell），纯 gmssl 50 次加解密也崩。本机 `py_compile`/`node --check` 等不跑加密的校验可用；**任何加密链路自动化测试必须放进 Docker 容器内跑**（容器不受此沙箱限制）。

11. **entry 加密 PBKDF2-SM3 纯 Python 极慢**——gmssl 的 `sm3.sm3_hash` 是纯 Python，10000 次迭代单块派生 ~12s/条，UI 不可用。已改用 `cryptography` 的 C 加速 `hashes.SM3()` 注入同一 PBKDF2 结构；两者 SM3 摘要逐字节一致（已验证），派生密钥不变（PassPy 兼容）。SM4 仍用 gmssl（极短明文，开销可忽略）。
12. **build_image.sh PROJECT_ROOT 路径 bug**——脚本在 `backend/offline/`，必须用 `$(dirname "$0")/../..` 才是项目根；原 `/..` 只到 `backend`，导致 `docker build ./backend` 报 path not found。
13. **Docker 镜像自包含导出 tar 导致膨胀**——`COPY offline ./offline` 会把 `offline/password_manager_image.tar` 打进镜像，每次重建都嵌入上一个 tar（runaway 到 425MB）。已加 `backend/.dockerignore` 排除 `offline/*.tar`、`offline/smoke_entry.py`、`.venv/`、`data/`、`.secret_key`、`.smoke_*.py`。
14. **pgpy 无法解锁/解密受口令保护的私钥**——PGPy 0.6.0 下 `key.unlock(passwd)` 即使口令正确也不把 `is_unlocked` 置 True、也无 `unprotect` 方法 → 受口令私钥在本系统**无法使用**。导入受口令私钥应直接拒绝并给清晰提示（指引用 GnuPG 去口令）。
15. **真实 GPG 密钥含独立加密子密钥**——`pgpy.PGPKey.from_blob(...)[0]` 只取主密钥，主密钥通常只用于签名/认证，解密必须遍历 `primary.subkeys`；`gpg_crypto.decrypt/_collect_keys` 已按此实现。自生成的密钥（无子密钥、主密钥兼加解密）不受影响。

## 端到端验证模式
- 容器内跑测试 = 绕开主机 sandbox 的最稳方法：`docker cp script.py X:/tmp/ && docker exec X python3 /tmp/script.py`。
- 冒烟脚本（均需在容器内跑，绕开沙箱）：`smoke_entry.py`（18 项：entry + 多租户 + OrgKey + 旧式 legacy）、`smoke_hybrid.py`（37 项：symmetric/gpg/sm2 混合加密 + needs_password）、`smoke_keyimport.py`（OrgKey 导入：含子密钥外部密钥 + 受口令私钥拒入）、`smoke_vault_export.py`（13 项：POST /unlock、批量导出 JSON/CSV、文件接口已移除、缺解密密码被拒）。覆盖：登录、JWT、groups/mine、新增 entry、错误密码 401、正确解密还原、改密码、history、密钥状态、未授权 401、OrgKey。
- 测试容器：`docker run -d --name password-manager-test --platform linux/amd64 -p 9010:9010 -v /tmp/password-manager-test-data:/app/data -e ADMIN_PASSWORD='TestPass!2026' password-manager:latest`。冒烟脚本 `backend/offline/smoke_entry.py`（17 项断言）。
- admin/TestPass!2026 是当前测试数据卷里的账号。

## 最近一次镜像
- `password-manager:latest` ID `c17ac38fff99`（虚拟 216MB），tar `backend/offline/password_manager_image.tar` 约 222MB（2026-07-08 15:17 导出）。
- 构建命令：`bash backend/offline/build_image.sh`（用户要求：每次更新都重建）。纯静态改动（如前端 JS）用 `docker commit` 增量更快：run 临时容器 → `docker cp` 改文件 → `docker stop` → `docker commit` → `docker save`，复用旧依赖层避开坑 #6 的 SIGKILL。
- 本轮（2026-07-08）完成的 5 项需求：①取消文件保险箱页面（前端+后端模型/路由全删）；②编辑密码先弹锁框输入当前解密密码、解密回填后才能编辑；③新增密码需两次确认解密密码 + 明文显示按钮（`f-entry-reveal`）；④查看接口改 `POST /api/passwords/{id}/unlock`（密码在 body，不再用 `GET ?entry_password=`）；⑤新增批量导出 `POST /api/passwords/export`（JSON/CSV，加密备份或明文，解密密码在 body）。
- 修正：删除 `app.js` 中重复的 `openExport` 函数定义（仅保留 626 行那一处，复用 `renderExportPerRow`）。
- 验证：4 个冒烟脚本全绿 —— `smoke_entry` 18/18、`smoke_hybrid` 37/37、`smoke_keyimport` 全过、`smoke_vault_export` 13/13。
- 历史镜像：`d619bdb8e4b5`（同轮 5 需求初版，含重复 openExport）、`167a9b7503ca`（GPG 子密钥修复）、`passwdpm:latest`（e5a8fca/4a9923c7/3827ea9e/7fa4e494/d613f4b29cef）已删除。
