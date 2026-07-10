# 前端 Vue 重构可行性评估

> 评估对象：`passwdpm-web` 前端（原生 HTML/CSS/JS，约 2007 行 `app.js` + 587 行 `index.html` + 459 行 `styles.css`），后端 FastAPI 不动。
> 评估日期：2026-07-10
> 结论：**可行性高（推荐）**。后端已是干净的 REST API，前端是自包含 SPA，迁移到 Vue 3 + Vite 风险低、收益明显。

---

## 1. 当前前端画像（实测数据）

| 维度 | 现状 |
|---|---|
| 代码量 | `app.js` 2007 行、126 个函数、75 处 `addEventListener`；`index.html` 587 行（纯静态挂载点 + 模态框模板）；`styles.css` 459 行 |
| 架构 | 单文件 vanilla JS SPA，挂载在 FastAPI `StaticFiles` 下，无构建步骤、无 npm 依赖、无打包器 |
| 数据交互 | 全部通过 REST（`fetch` + Bearer JWT），前端自管 `state.token` 与 `state` 全局对象；API 边界清晰（约 24 个 `/api/*` 端点） |
| 渲染方式 | 手写 DOM（`$()`、`innerHTML`、`createElement`），表格渲染已用 `esc()` 转义防 XSS |
| 离线约束 | 镜像 `docker load` 后内网离线运行，**禁止使用任何 CDN** |

## 2. 为什么可行（核心依据）

1. **后端零改动**：所有加解密（SM4/SM3/GPG/SM2）、鉴权、多租户隔离都在服务端。前端只是 REST 消费者，Vue 复用同一套 `/api/*` 契约即可，协议不变、回归范围小。
2. **CSP 已就绪**：此前加固已加 `Content-Security-Policy: script-src 'self'`。Vue 经 **Vite 构建**后产出带 hash 的 `app.[hash].js` / `app.[hash].css`，由 `'self'` 加载，天然契合 CSP（无需 `'unsafe-inline'` 脚本）。仅需把当前 `style-src 'unsafe-inline'` 收敛为 SFC `<style scoped>`。
3. **无前端密码学 / WASM**：加密全在服务端，前端只传明文密码与文件，Vue 处理 `FormData`/`Blob` 下载与现在完全一致。
4. **状态模型简单**：单个 `state` 对象（当前用户、选中条目、分组过滤、模态开关）可平滑映射到 Pinia store 或组合式 `composables`。

## 3. 推荐技术栈

- **Vue 3**（`<script setup>` SFC）+ **Vite**（构建静态产物）
- **Pinia**（状态：auth、entries、orgkeys、ui 模态）
- **TypeScript**（可选但推荐，能锁定 API 契约、减少端口期错误）
- **Vue Router**（若拆多页；当前其实是单页 + 模态，也可仅用组件切换，不强制引入路由）
- 表单校验 / 二次确认 / Toast / 等待遮罩 → 抽成可复用组件
- 网络层：把现有 `api()` 封装成 `useApi()` composable（统一 Bearer、错误处理、`!res.ok` 透传中文 `detail`）

## 4. 迁移路径（低风险、可验证）

1. **脚手架**：`npm create vite@latest frontend -- --template vue-ts`，产出 `dist/` 静态资源。
2. **网络层**：将原 `api()`（fetch + JWT + 中文错误）封装为 `useApi` composable，全项目共用。
3. **按"屏幕"拆组件**：
   - `LoginView`
   - `PasswordListView`（列表 + 多选 + 解密密码逐项/统一输入）
   - `PasswordFormModal`（新增/编辑，含算法切换、密钥选择）
   - `ImportModal`（Excel 模板下载 + 上传 + 结果回执）
   - `ExportModal`（统一解密密码 + 逐项输入 + 置灰逻辑）
   - `KeyVaultView` + `KeyGenModal` / `KeyImportModal`
   - `AdminTabs`（用户/分组/审计日志）
   - 通用：`ConfirmTwoStepModal`（删除密码/密钥的"输入确认删除"）、`Toast`、`WaitOverlay`
4. **XSS 自然消除**：原 `innerHTML` + `esc()` 改为 Vue 模板 `{{ }}` 自动转义；仅对真正需富文本处用 `v-html`（本项目基本没有）。
5. **构建与离线分发**：
   - `vite build` → `dist/`
   - 方案 A（推荐）：把 `dist/` 作为 FastAPI 静态根（`StaticFiles` 指向构建产物），`index.html`（Vite 入口）替换原 `index.html`；`docker build` 时把 `dist` 拷进镜像。
   - 方案 B（最小改动）：保留原 `index.html` 仅改 `<script src>` 指向构建后的 `assets/app.[hash].js`，其余静态托管不变。
6. **回归**：现有 `smoke_*.py`（后端契约测试）全部继续可用，保障迁移不破坏 API；前端可用 Playwright/Vitest 做组件级冒烟。

## 5. 成本与风险

| 项 | 评估 |
|---|---|
| 工作量 | 1:1 端口约 **1.5–3 人日**（2000 行逻辑，多为机械迁移）；若引入 TS + 路由 + 单测则 **3–5 人日** |
| 主要风险 | ① 引入构建步骤，需改 `Dockerfile`/CI（必须**预构建**后入镜像，不能运行时 CDN）；② 离线镜像体积略增（Node 只在构建期用，运行期仍是 Python）；③ 一次性全量重写，**无法增量**与原 vanilla 并存（建议单独分支完成后再合并） |
| 收益 | 组件化可维护性↑、XSS 面收敛、二次确认/模态等逻辑复用、后续加功能（如分页、搜索、富校验）成本下降 |
| 不推荐做法 | 用 CDN 引入 Vue（违反离线）；保留 `innerHTML` 拼接（浪费 Vue 的转义优势）；与旧 `app.js` 长期双轨并存 |

## 6. 决策建议

- **可以做，且值得做**。后端 API 已是最佳迁移形态，迁移风险主要在"前端重写"本身，而非架构耦合。
- **若短期只想止血/交付**：本次"仅 Excel"等需求用现有 vanilla 实现即可，不阻塞业务；Vue 重构可作为独立技术债清理项排期。
- **若启动重构**：建议新建 `frontend/` 子目录 + Vite，保留 `backend/app/static` 作为构建产物落点，单开分支、配 `docker build` 把 `dist` 拷入，避免影响当前可运行镜像。

---

*注：本报告仅为可行性评估，未改动任何源码。如需启动重构，可另开分支并按第 4 节路径实施。*
