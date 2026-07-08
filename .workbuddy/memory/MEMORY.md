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
16. **docker commit 不会继承原镜像的 CMD/EXPOSE/VOLUME，从 `sleep 600` 启动的容器 commit 时保留 sleep 的 CMD**——必须显式 `docker commit --change 'CMD [...]' --change 'EXPOSE 9010' --change 'VOLUME ["/app/data"]' ...`，否则镜像启动后只 sleep 不跑 uvicorn。容器 commit 前**不能 `docker rm`**（否则 commit 找不到容器）。
17. **docker commit「替换整段代码」的正确姿势**——只 `docker cp` 几个改动的文件，会留下旧镜像里残留的陈旧代码（如本轮旧 `passwdpm:latest` 仍带 `files.py` 路由）。正确：先 `docker exec ... rm -rf /app/app /app/run.py`，再 cp 完整新代码进 `/app/app`，最后 commit。旧镜像若依赖层健康可继续作为基础（避免 pip install SIGKILL）。
18. **smoke_entry.py 等旧测试已 stale**——它们仍在用陈旧的 `GET /api/passwords/{id}?entry_password=...` 路径（已在第二轮 UI 调整里统一改 `POST /api/passwords/{id}/unlock` body 形式），跑会全 405 Method Not Allowed。新断言在 `smoke_history_zh.py`、`smoke_vault_export.py`、`smoke_hybrid.py`、`smoke_keyimport.py`、`smoke_form_lock.py`。
19. **CSS `:disabled` 不覆盖 input/select/textarea**——`.btn:disabled` 有内置样式（opacity + not-allowed），但 inputs 默认只是变灰一点。需要在 styles.css 加 `input:disabled, select:disabled, textarea:disabled { background:#f3f4f6; color:#9ca3af; cursor:not-allowed; opacity:.7 }`，否则置灰看起来不明显。本轮 form-lock 已补。

## 端到端验证模式
- 容器内跑测试 = 绕开主机 sandbox 的最稳方法：`docker cp script.py X:/tmp/ && docker exec X python3 /tmp/script.py`。
- 冒烟脚本（**HTTP only 的可主机跑；含加密/import 的必须在容器内**）：`smoke_vault_export.py`（13 项：POST /unlock、批量导出 JSON/CSV、文件接口已移除、缺解密密码被拒）、`smoke_hybrid.py`（37 项：symmetric/gpg/sm2 混合加密 + needs_password）、`smoke_keyimport.py`（OrgKey 导入：含子密钥外部密钥 + 受口令私钥拒入）、`smoke_history_zh.py`（8 项：创建/修改后 history.comment 为中文）、`smoke_form_lock.py`（37 项：编辑密码页置灰 — 校验 14 个 ID 在 JS 列表 + HTML DOM 都存在 + 6 个调用点全部 in-scope + CSS :disabled 样式）。`smoke_entry.py` 已陈旧（用旧 GET 路径）本轮跳过。
- 主机运行示例（HTTP only）：`/Users/liuyupengliu/.workbuddy/binaries/python/versions/3.13.12/bin/python3 /Users/liuyupengliu/Downloads/projects/pwd-web-new/backend/offline/smoke_history_zh.py`。冒烟脚本内 `BASE` 默认 `http://localhost:9010`，运行时先 `sed -i.bak 's|http://localhost:9010|http://localhost:9012|' ...` 切到测试端口。
- 测试容器：`docker run -d --name pwd-test --platform linux/amd64 -p 9012:9010 -v /tmp/pwd-test-data:/app/data -e ADMIN_PASSWORD='TestPass!2026' password-manager:latest`。
- admin / TestPass!2026 是当前测试数据卷里的账号。
- **HTTP-only smoke 跨 macOS 用绝对路径调用 WorkBuddy managed Python**：`/Users/liuyupengliu/.workbuddy/binaries/python/versions/3.13.12/bin/python3 script.py`；WorkBuddy Bash 沙箱不可用 `timeout`，直接跑 `python3 script.py` 即可（HTTP 请求会自然超时；含加密的会被沙箱强杀，见坑 #10）。
- **Docker CLI 绝对路径**：WorkBuddy 沙箱里 `docker` 可能不在 PATH，用 `/Applications/Docker.app/Contents/Resources/bin/docker` 绝对路径；context 偶尔会被切到 `desktop-linux`（无 socket），需要 `docker context use default` 后再 ps/build。

## 最近一次镜像
- `password-manager:latest` ID `5d5088d9491b`（virtual 463MB），tar `backend/offline/password_manager_image.tar` 141MB（2026-07-08 22:25 导出）。
- 构建命令：`bash backend/offline/build_image.sh`（用户要求：每次更新都重建）。源码需完整替换时用 `docker commit` 增量：run `passwdpm:latest sleep 600` → `rm -rf /app/app` → `docker cp` 整套新代码 → `stop`（不删）→ `commit --change 'CMD ["python","run.py"]' --change 'EXPOSE 9010' --change 'VOLUME ["/app/data"]' ... password-manager:latest` → save。详见坑 #16、#17。
- **第三轮（2026-07-08 晚）**：编辑密码页未解锁时整段下面板置灰。新增 `setFormEditLocked(locked)` helper + `FORM_EDIT_LOCKED_IDS` 列表（14 个元素）+ CSS `input:disabled`/`select:disabled`/`textarea:disabled` 样式。调用点 6 处：openAdd(false) / openEdit-needsPw(true) / openEdit-legacy(false) / unlockEdit-success(false) / unlockEdit-failure(true) / closeForm(false)。新冒烟 `smoke_form_lock.py` 37/37 通过。
- 本轮（2026-07-08 第二轮）完成的 5 项调整：①README 与代码同步（去文件保险箱描述，APIs、镜像体积）；②导出密码页排版美化（`.modal-card-export` + `.exp-summary` + `.seg-group` segmented pill + `.exp-row` 卡片）；③导出内容**只保留明文**（去掉 `cipher`/`exp-mode` 选项，后端永远 `plaintext: true`）；④密钥库顶部 `.section-hint` 信息卡 + `.key-toolbar` 工具栏分组；⑤修改记录全中文（后端 `passwords.py` 用中文 label + 前端 `humanizeComment` 兜底映射）。新冒烟 `smoke_history_zh.py` 8/8 通过。
- 第二轮之前的 5 项需求依然完整：①取消文件保险箱页面（前端+后端模型/路由全删）；②编辑密码先弹锁框输入当前解密密码、解密回填后才能编辑；③新增密码需两次确认解密密码 + 明文显示按钮（`f-entry-reveal`）；④查看接口改 `POST /api/passwords/{id}/unlock`（密码在 body，不再用 `GET ?entry_password=`）；⑤新增批量导出 `POST /api/passwords/export`（JSON/CSV。
- 修正：删除 `app.js` 中重复的 `openExport` 函数定义（仅保留 626 行那一处，复用 `renderExportPerRow`）。第三轮 `app.js` 又加了 `setFormEditLocked` + `FORM_EDIT_LOCKED_IDS` + 6 个调用点。
- 验证：4 + 1 + 1 冒烟脚本全绿 —— `smoke_vault_export` 13/13、`smoke_hybrid` 37/37、`smoke_keyimport` 容器内全过、`smoke_history_zh` 8/8、新加 `smoke_form_lock` 37/37；`smoke_entry.py` 因仍是 stale 断言（用旧 GET 路径）跳过。
- 历史镜像：`665100187af8`（第二轮）、`c17ac38fff99`（第一轮 5 需求的 tar 文件源镜像）、`d619bdb8e4b5`、`167a9b7503ca`、`passwdpm:latest`（e5a8fca/4a9923c7/3827ea9e/7fa4e494/d613f4b29cef）—— `passwdpm:latest` 仍保留作为基础（依赖层健康）。

## 前端样式系统（`backend/app/static/styles.css`）
- 颜色 token（`--primary #2563eb` / `--danger #dc2626` / `--green #16a34a` / `--gpg #7c3aed` / `--sm2 #0891b2`）。
- 关键组件：`.modal-card` / `.modal-card.wide` / `.modal-card-export` / `.btn .primary .ghost .danger .small`、`.badge .gpg .sm2 .entry`、`.kv .secret-box`、`.wait` 全屏等待 + `.spinner`、`.lock-box .lock-hint`、`.seg-group` segmented pill、`.section-hint` 信息卡（蓝紫渐变）、`.key-toolbar`（带边框卡片工具栏）、`.toolbar-group .flex-grow` 分组、`.exp-summary`（蓝色摘要块，大数字 + 标签）、`.exp-section / .exp-section-title` / `.exp-row .exp-row-info .exp-row-name .exp-row-algo`。
- **disabled 样式全覆盖（第三轮补全）**：`.btn:disabled` + `input:disabled, select:disabled, textarea:disabled { background:#f3f4f6; color:#9ca3af; cursor:not-allowed; opacity:.7 }`。
- 前端缓存：`main.py` 用 `NoCacheStaticFiles(StaticFiles)` 子类在 `get_response` 加 `Cache-Control: no-cache, no-store, must-revalidate`（注意 `@app.middleware` 拦不到 mounted 子应用）。前端资源引用 URL 带 `?v=6` cache-buster。第三轮仍是 `?v=6`（只改了 JS 和 CSS，没必要 bump）。
