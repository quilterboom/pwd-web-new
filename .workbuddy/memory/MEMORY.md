# passwd-web 项目长期笔记

## 项目身份
- 路径：`D:\aicode\passwd-web-new`（源码 `backend/app`；前端 `backend/app/static/{index.html,app.js,styles.css}`）。
- 类型：FastAPI + SQLAlchemy + SQLite + pgpy/gmssl 的离线密码保险箱；原生 HTML/CSS/JS 前端；多租户（按 group_id 隔离）。
- 部署：内网离线 x86_64 Linux（Docker 镜像 `password-manager`，tar `backend/offline/password_manager_image.tar`，当前 **231MB / 镜像 234MB**）。

## 认证：SCRAM-SM3 挑战-响应（取代旧明文登录）
- 协议：`POST /api/auth/login/begin {username}` → 返回持久化 `pw_salt` + 一次性 `nonce`；前端算 `T=SM3(password||salt_bytes)`、`proof=SM3(T||nonce_bytes)`；`POST /api/auth/login/verify {username,nonce,proof}` 比对 `expected=SM3(pw_verifier||nonce)`。
- `User.pw_salt`(hex16B) + `pw_verifier`(SM3 hex) 由 `security.derive_password_verifier` 生成；`admin._seed_login_material` 与 `routers/admin._seed_login_material` 共用。
- 旧用户（仅 bcrypt）登录 `/api/auth/login` 成功后自动迁移；前端 `doLogin` 遇 409 回退明文 `/login`。
- **前端 JS SM3 关键**：拼接必须用 **原始字节**（`sm3Bytes(Buffer.concat([T_raw, nonce_raw]))`），不能把 hex 字符串当 UTF-8 再哈希（否则 proof 不匹配）。JS 实现在 `app.js` 顶部，`_sm3Tj` 用 `0x79cc4519`/`0x7a879d8a`（GM/T 0003-2012）。
- `login/begin` 对不存在用户直接返 401（拒绝发挑战），属预期。

## 加密体系（关键，易混）
- **内层「解密密码」SM4-CBC**：symmetric/gpg/sm2 全部先以条目密码做 SM4（PBKDF2-SM3 派生 key，零知识）。`entry_salt/entry_iv` 非空=有此层；`needs_password = bool(entry_salt) and bool(entry_iv)`。SM3 用 `cryptography` C 加速。
- **外层非对称（gpg/sm2）**：内层 SM4 密文序列化为 JSON `{salt,iv,ciphertext}` 后用 OrgKey 公钥加密落库，`scheme='legacy'`、`orgkey_id` 记录所用密钥。查看/编辑：私钥解外层→JSON→解密密码解内层。
- **GPG 私钥口令（passphrase）支持（NEW）**：`OrgKey.private_protected`(bool) + `private_passphrase`(明文存，回退用)；`gpg_crypto._collect_keys` 返 `(primary, all_keys, any_protected)`，`decrypt/_collect_keys` 遍历主密钥+全部子密钥，`with k.unlock(passphrase):` 解锁后解密。`manager.decrypt_with_orgkey(db, orgkey_id, ct, passphrase=None)` 优先用 OrgKey 存的口令。
- **导入约束**：`routers/keys.ImportRequest` 含 `private_passphrase`；导入受口令私钥时必须传对口令，否则 `400 私钥与公钥不匹配或无效：Passphrase was incorrect!`。

## 五大功能落点（本轮实现）
1. **密钥库工具栏**：`index.html` 按钮改短文案（导入/生成/＋新增/📤 导出）+ `title` 提示；`styles.css` `.toolbar-group.toolbar-actions .btn{gap:8px;min-width:88px}`。
2. **编辑页无结果置灰**：`app.js` `FORM_EDIT_LOCKED_IDS`（含 `form-lock-password`/`form-unlock`/`f-*` 全字段/`form-save`）+ `setFormEditLocked(locked)`；`needs_password` 时弹锁框且 `setFormEditLocked(true)`，仅「取消」可用；解密失败保留置灰。`styles.css` 需覆盖 `input/select/textarea:disabled`。
3. **GPG 口令兼容**：见上「GPG 私钥口令」。`openKeyImport/saveKeyImport` 处理 `ki-passphrase`；`applyImportPassphraseUI` 仅 GPG+贴了私钥时显示口令行。
4. **登录加密**：见「SCRAM-SM3」。
5. **批量新增用户**：`routers/users_batch.py` — `GET /api/admin/users/template?fmt=xlsx|csv`（openpyxl 生成/解析，中文表头 用户名/密码/是否管理员/所属分组，多分组半角逗号）；`POST /api/admin/users/batch`（multipart，逐行建用户+逐行结果报告）。前端 `openUserBatch/downloadUserTemplate/doUserBatchUpload`。模板示例组「研发部/测试组」若不存在→该行 error（属预期）。

## 关键模块
- `models.py`：`User`(+`pw_salt`/`pw_verifier`) `Group` `user_groups`(Table) `PasswordEntry` `History` `KeyRecord` `OrgKey`(+`private_protected`/`private_passphrase`/`is_protected` 兼容旧列)。
- `routers/`：`auth.py`(begin/verify/legacy) `admin.py`(含 `_seed_login_material`/`_link_user_group`) `keys.py` `passwords.py` `users_batch.py`(NEW) `history.py`。
- `crypto/gpg_crypto.py`：顶部 stub `imghdr`（Py3.13 移除）。
- `core/deps.py`：权限核心 `get_current_user`/`get_user_group_ids`/`ensure_group_access`/`require_admin`。
- `Dockerfile`：`python:3.13-slim`，`COPY offline ./offline`，`CMD ["python","run.py"]`，`VOLUME ["/app/data"]`，`EXPOSE 9010`。

## 易踩的坑
- **pgpy Py3.13 缺 `imghdr`**：import 前 `sys.modules['imghdr']=types.ModuleType('imghdr')`。
- **pgpy 正确 API**：算法枚举 `PubKeyAlgorithm.RSAEncryptOrSign`（非 `PGPKeyAlgorithm.RSA`）；用法 `KeyFlags`（非 `KeyUsage`）；公钥半 `str(key.pubkey)`（私钥含公私→导入会报 `is_public==True` 错）。受口令 `key.protect(pass, AES256, SHA256)`（非 `add_uid(passphrase=)`）。
- **bcrypt 固定 `==4.0.1`**；**gmssl SM2 公钥手动推导**；**SQLAlchemy 多对多用 `user_groups` Table**；**HTTP 导出中文名双字段 Content-Disposition**。
- **批量导入必须是 multipart/form-data**（FastAPI `File()`），裸 `text/csv` body → 422。
- **沙箱强杀加密进程**：加密链路测试进容器跑；本机只 `py_compile`/`node --check`。
- **docker commit 增量**（避免 `--no-cache` SIGKILL）：起临时容器（可用 `--entrypoint sleep 600` 让它空转）→ `rm -rf /app/app /app/run.py /app/requirements.txt` → `docker cp` 完整新代码 → 清 `*.pyc` → commit。commit 前不得 `docker rm`。
- **⚠️ commit 会捕获容器的 ENTRYPOINT（致命坑，2026-07-09 爆过）**：若临时容器是用 `--entrypoint sleep` 起的，commit 出来的镜像 `Entrypoint` 会被写成 `['sleep']`，而 `CMD` 仍是 `['python','run.py']` → 真实 `docker run` 直接执行 `sleep python run.py` 报错（`sleep: invalid time interval 'python'`），应用根本起不来。**此坑在「exec 进容器手动跑 python run.py」的测试里完全发现不了**，只有真正 `docker run` 部署时才暴露。
  - **正确 commit 命令（必须显式覆盖 ENTRYPOINT）**：`docker commit --change 'ENTRYPOINT ["python","run.py"]' --change 'CMD []' --change 'EXPOSE 9010' --change 'VOLUME ["/app/data"]' <容器> password-manager:latest`。
  - 不要只写 `--change 'CMD ["python","run.py"]'`（漏了 ENTRYPOINT 覆盖就会继承 sleep）。`--change 'ENTRYPOINT []'` 空数组 Docker 会**忽略**，必须给明确值。
  - 验证：commit 后 `docker inspect` 确认 `Entrypoint: ['python','run.py']`、`Cmd: None`；再**不加 `--entrypoint`** 起一个容器，`docker logs` 应看到 uvicorn 启动日志而非 sleep 报错。
- **docker cp 增量覆盖坑**：在临时容器上 `rm -rf /app/app` 后 `docker cp backend/app 容器:/app/app`，**已存在的同名文件可能不会覆盖**（overlay 缓存，表现为 app.js 更新了但 admin.py/main.py 仍是旧代码）。务必 cp 后 `grep` 校验每个改动文件已更新 + `py_compile` 确认；个别未更新的文件先 `docker exec 容器 rm -f 该文件` 再单独 `docker cp`。
- **前端改 JS/CSS 记得 bump `?v=N`**（index.html 现 `?v=7`）。
- **DB 迁移必须「通用」**：`db._migrate_columns()` 扫描 `Base.metadata` 所有模型列，`ALTER TABLE ADD COLUMN` 补齐旧库缺失列（带 SQLite 兼容默认值）。**绝不能退回硬编码列清单**——曾因漏列 `passwords.deleted` 导致部署库 `GET /api/passwords` 报 `no such column: passwords.deleted` → 500。新加模型列后无需改迁移代码。
- **`api()` 抛错务必附 `e.status = res.status`**：前端 `doLogin` 靠 `err.status === 409` 判断「未迁移账号→回退明文 `/login`」。若只把中文 `detail` 放进 `message`，`includes("409")` 永远 false，用户会卡在 409 无法登录。
- **provider 接口必须一致（SM2 passphrase 坑）**：`manager.decrypt_with_orgkey` / `keys._validate_keys` 对 gpg/sm2 **统一**调用 `.decrypt(ct, priv, passphrase=pp)`。GPG 的 `decrypt` 有 `passphrase=None` 形参，但 **SM2 的 `sm2_crypto.decrypt/decrypt_bytes` 没有** → 用 SM2 OrgKey 解密就抛 `TypeError: decrypt() got an unexpected keyword argument 'passphrase'`（被包装成「用 OrgKey 私钥解密失败」500）。**修复**：给 SM2 两个 decrypt 函数加 `passphrase: str = None` 形参并直接忽略（SM2 私钥是 raw hex，无 passphrase 概念）。以后加新 provider 时，所有 `decrypt/encrypt` 签名要对齐 gpg/sm2。

## 验证模式
- E2E HTTP 测试（加密在服务端容器内，本机 HTTP 客户端安全）：`backend/offline/e2e_http_test.py`（SCRAM 登录 + xlsx/csv 模板 + 批量导入 + GPG 受口令密钥导入/加解密）+ `e2e_extra.py`（xlsx 回环 + 错口令拒绝）。需 live 容器（如 `pm-test2` 9012）。
- 容器内生成 GPG 受口令密钥：`docker exec X python3 -c "import sys,types;sys.modules['imghdr']=types.ModuleType('imghdr');from pgpy import PGPKey,PGPUID;from pgpy.constants import SymmetricKeyAlgorithm,HashAlgorithm,KeyFlags,PubKeyAlgorithm;k=PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign,2048);k.add_uid(PGPUID.new('t',email='t@l'),usage={KeyFlags.EncryptCommunications,KeyFlags.EncryptStorage});k.protect('pw',SymmetricKeyAlgorithm.AES256,HashAlgorithm.SHA256);open('/tmp/p','w').write(str(k));open('/tmp/pu','w').write(str(k.pubkey))"`。
- 测试容器：`docker run -d --name pwd-test --platform linux/amd64 -p 9012:9010 -v /tmp/pwd-test-data:/app/data -e ADMIN_PASSWORD='TestPass!2026' password-manager:latest`；admin/TestPass!2026。
- 容器内跑旧冒烟：`smoke_vault_export.py` `smoke_hybrid.py` `smoke_keyimport.py` `smoke_history_zh.py` `smoke_form_lock.py` `smoke_audit.py` `smoke_migration.py`（500 回归护栏：旧库缺列仍能 GET /api/passwords==200）；`smoke_entry.py` 已 stale 跳过。
