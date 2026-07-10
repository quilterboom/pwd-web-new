"use strict";

/* ────────── SM3 哈希（SCRAM-SM3 与密码锁都依赖此实现）────────── */

// left-rotate for 32-bit unsigned value (掩码强制无符号，避免 JS << 负值问题)
function _rotl32(x, n) {
  x = (x >>> 0);
  n = n % 32;
  return (((x << n) | (x >>> (32 - n))) >>> 0);
}
function _sm3P0(x) { return ((x ^ _rotl32(x, 9) ^ _rotl32(x, 17)) >>> 0); }
function _sm3P1(x) { return ((x ^ _rotl32(x, 15) ^ _rotl32(x, 23)) >>> 0); }
function _sm3FF(j, x, y, z) {
  if (j < 16) return ((x ^ y ^ z) >>> 0);
  return ((((x & y) | (x & z) | (y & z)) >>> 0));
}
function _sm3GG(j, x, y, z) {
  if (j < 16) return ((x ^ y ^ z) >>> 0);
  return (((x & y | ((~x) >>> 0) & z)) >>> 0);
}
function _sm3Tj(j) { return j < 16 ? 0x79cc4519 : 0x7a879d8a; }  // GM/T 0003-2012 标准常量

function _sm3compress(v, block) {
  const W = new Array(68);
  for (let i = 0; i < 16; i++) {
    W[i] = ((block[i*4] << 24) | (block[i*4+1] << 16) | (block[i*4+2] << 8) | block[i*4+3]) >>> 0;
  }
  for (let i = 16; i < 68; i++) {
    W[i] = (_sm3P1(((W[i-16] ^ W[i-9] ^ _rotl32(W[i-3], 15)) >>> 0))
            ^ _rotl32(W[i-13], 7) ^ W[i-6]) >>> 0;
  }
  const Wp = new Array(64);
  for (let i = 0; i < 64; i++) Wp[i] = ((W[i] ^ W[i+4]) >>> 0);

  let A = v[0]>>>0, B = v[1]>>>0, C = v[2]>>>0, D = v[3]>>>0;
  let E = v[4]>>>0, F = v[5]>>>0, G = v[6]>>>0, H = v[7]>>>0;
  for (let j = 0; j < 64; j++) {
    const A12 = _rotl32(A, 12);
    const SS1 = _rotl32(((A12 + E + _rotl32(_sm3Tj(j), j % 32)) >>> 0), 7);
    const SS2 = ((SS1 ^ A12) >>> 0);
    const TT1 = ((_sm3FF(j, A, B, C) + D + SS2 + Wp[j]) >>> 0);
    const TT2 = ((_sm3GG(j, E, F, G) + H + SS1 + W[j]) >>> 0);
    D = C; C = _rotl32(B, 9); B = A; A = TT1;
    H = G; G = _rotl32(F, 19); F = E; E = _sm3P0(TT2);
  }
  v[0] = ((v[0] ^ A) >>> 0); v[1] = ((v[1] ^ B) >>> 0);
  v[2] = ((v[2] ^ C) >>> 0); v[3] = ((v[3] ^ D) >>> 0);
  v[4] = ((v[4] ^ E) >>> 0); v[5] = ((v[5] ^ F) >>> 0);
  v[6] = ((v[6] ^ G) >>> 0); v[7] = ((v[7] ^ H) >>> 0);
}

const _SM3_IV = [0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
                 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e];

/** 对 Uint8Array 跑 SM3，返回 32 字节的 Uint8Array。 */
function sm3Bytes(bytes) {
  const len = bytes.length;
  const bufLen = (((len + 1 + 8 + 63) >> 6) << 6);
  const buf = new Uint8Array(bufLen);
  buf.set(bytes);
  buf[len] = 0x80;
  let bitLen = BigInt(len) * 8n;
  for (let i = 0; i < 8; i++) {
    buf[bufLen - 1 - i] = Number(bitLen & 0xffn);
    bitLen >>= 8n;
  }
  const v = _SM3_IV.slice();
  for (let off = 0; off < bufLen; off += 64) {
    _sm3compress(v, buf.subarray(off, off + 64));
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 8; i++) {
    out[i*4]   = (v[i] >>> 24) & 0xff;
    out[i*4+1] = (v[i] >>> 16) & 0xff;
    out[i*4+2] = (v[i] >>> 8) & 0xff;
    out[i*4+3] = v[i] & 0xff;
  }
  return out;
}

/** 对 string（UTF-8）跑 SM3，返回 hex 字符串。 */
function sm3Hex(s) {
  const bytes = new TextEncoder().encode(s || "");
  return Array.from(sm3Bytes(bytes), b => b.toString(16).padStart(2, "0")).join("");
}

/** hex 字符串 → Uint8Array（辅助函数：把后端返回的 salt/nonce/verifier 字符串转回字节）。 */
function hexToBytes(hex) {
  const n = (hex || "").length;
  if (n % 2 !== 0) return new Uint8Array(0);
  const out = new Uint8Array(n / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substr(i * 2, 2), 16) || 0;
  }
  return out;
}

const TOKEN_KEY = "password_manager_token";
const USER_KEY = "password_manager_user";

const $ = (id) => document.getElementById(id);

let state = {
  token: localStorage.getItem(TOKEN_KEY) || "",
  user: localStorage.getItem(USER_KEY) || "",
  isAdmin: false,
  groups: [], // 当前用户可见分组（管理员为全部）
  users: [], // 管理员视角下的全部用户
  entries: [],
  editingId: null,
  viewingId: null,
  originalSecret: "",
  originalAlgorithm: "",
  selected: new Set(),      // 批量导出：已勾选的密码 id
  editEntryPassword: null,  // 编辑解锁后记住的当前解密密码
};

/* ---------- 工具函数 ---------- */
function api(path, opts = {}) {
  const headers = Object.assign({}, opts.headers || {});
  if (state.token) headers["Authorization"] = "Bearer " + state.token;
  if (opts.body && !(opts.body instanceof FormData)) headers["Content-Type"] = "application/json";
  return fetch(path, Object.assign({}, opts, { headers })).then(async (res) => {
    let data = null;
    try { data = await res.json(); } catch (e) { /* empty body */ }
    if (!res.ok) {
      const msg = (data && (data.detail || data.message)) || ("请求失败 (" + res.status + ")");
      const e = new Error(typeof msg === "string" ? msg : JSON.stringify(msg));
      e.status = res.status;
      throw e;
    }
    return data;
  });
}

function showToast(msg) {
  const t = $("toast");
  t.textContent = msg;
  t.classList.remove("hidden", "error");
  clearTimeout(showToast._t);
  showToast._t = setTimeout(() => t.classList.add("hidden"), 2200);
}

/* 失败提示：红色 toast，停留更久，确保用户一定看到 */
function showError(msg) {
  const t = $("toast");
  t.textContent = "❌ " + msg;
  t.classList.remove("hidden");
  t.classList.add("error");
  clearTimeout(showError._t);
  showError._t = setTimeout(() => t.classList.add("hidden"), 5000);
}

/* 全屏等待窗口：等待后台解析（加解密 / 网络）完成或失败后关闭 */
function showWait(text) {
  const m = $("wait-modal");
  if (!m) return;
  $("wait-text").textContent = text || "正在处理…";
  m.classList.remove("hidden");
}
function hideWait() {
  const m = $("wait-modal");
  if (m) m.classList.add("hidden");
}

function algoBadge(a) {
  if (a === "symmetric") return `<span class="badge entry">🔑 对称加密</span>`;
  const label = a === "sm2" ? "SM2" : "GPG";
  return `<span class="badge ${a}">${label}</span>`;
}

function groupName(id) {
  const g = state.groups.find((x) => x.id === id);
  return g ? g.name : "—";
}

function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

function fmtTime(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  return d.toLocaleString("zh-CN", { hour12: false });
}

function isAuthErr(e) {
  return String((e && e.message) || "").includes("401") || String((e && e.message) || "").includes("令牌");
}

/* ---------- 登录 / 登出 ----------
 * 登录走「SCRAM-SM3 挑战-响应」：不再以明文密码传输。
 *   1) POST /api/auth/login/begin {username} → {salt, nonce, iter, mode}
 *      - salt 来自服务端持久化（前后端共用）
 *      - nonce 是本次会话一次性随机数（防重放）
 *   2) 前端计算 verifier = SM3(password || salt_bytes) → proof = SM3(verifier || nonce_bytes)
 *   3) POST /api/auth/login/verify {username, nonce, proof} → {access_token}
 * 对历史未迁移的账号（后端 pw_verifier 仍为空），后端会返回 409，
 * 此时前端自动回退到旧路径 /api/auth/login {username, password}（明文 POST）做一次性迁移。
 */
async function doLogin(e) {
  e.preventDefault();
  $("login-error").textContent = "";
  const username = ($("login-username").value || "").trim();
  const password = $("login-password").value || "";
  if (!username || !password) {
    $("login-error").textContent = "请输入用户名和密码";
    return;
  }
  try {
    let chal;
    try {
      chal = await api("/api/auth/login/begin", {
        method: "POST",
        body: JSON.stringify({ username }),
      });
    } catch (err) {
      // 409: 旧账号尚未迁移 → 走明文 /login 完成一次性迁移
      if (err.status === 409 || String(err.message).includes("409")) {
        const data = await api("/api/auth/login", {
          method: "POST",
          body: JSON.stringify({ username, password }),
        });
        state.token = data.access_token;
        localStorage.setItem(TOKEN_KEY, state.token);
        await refreshMe();
        enterApp();
        return;
      }
      throw err;
    }
    // SCRAM-SM3: T = SM3(password || salt) ; proof = SM3(T || nonce)
    const saltBytes = hexToBytes(chal.salt);
    const nonceBytes = hexToBytes(chal.nonce);
    const pwBytes = new TextEncoder().encode(password);
    const tInput = new Uint8Array(pwBytes.length + saltBytes.length);
    tInput.set(pwBytes, 0);
    tInput.set(saltBytes, pwBytes.length);
    const verifierBytes = sm3Bytes(tInput);     // T（与服务端 pw_verifier 同值）
    const proofInput = new Uint8Array(verifierBytes.length + nonceBytes.length);
    proofInput.set(verifierBytes, 0);
    proofInput.set(nonceBytes, verifierBytes.length);
    const proofBytes = sm3Bytes(proofInput);     // proof = SM3(T || nonce)
    const proofHex = Array.from(proofBytes, b => b.toString(16).padStart(2, "0")).join("");

    const data = await api("/api/auth/login/verify", {
      method: "POST",
      body: JSON.stringify({ username, nonce: chal.nonce, proof: proofHex }),
    });
    state.token = data.access_token;
    localStorage.setItem(TOKEN_KEY, state.token);
    await refreshMe();
    enterApp();
  } catch (err) {
    $("login-error").textContent = err.message || "登录失败";
  }
}

function doLogout() {
  state.token = "";
  state.user = "";
  state.isAdmin = false;
  state.groups = [];
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
  $("app-view").classList.add("hidden");
  $("login-view").classList.remove("hidden");
}

async function refreshMe() {
  const me = await api("/api/auth/me");
  state.user = me.username;
  state.isAdmin = !!me.is_admin;
  state.groups = me.groups || [];
  localStorage.setItem(USER_KEY, me.username);
}

async function loadMe() {
  try {
    await refreshMe();
    return true;
  } catch (e) {
    // token 失效：清空本地凭据，回退到登录页，避免带着无效 token 展示主界面
    state.token = "";
    localStorage.removeItem(TOKEN_KEY);
    return false;
  }
}

/* ---------- 主界面 ---------- */
function enterApp() {
  $("login-view").classList.add("hidden");
  $("app-view").classList.remove("hidden");
  $("current-user").textContent = "👤 " + state.user + (state.isAdmin ? "（管理员）" : "");
  if (state.isAdmin) $("admin-btn").classList.remove("hidden");
  else $("admin-btn").classList.add("hidden");
  // 密码导出属于高风险操作，仅管理员可用：非管理员直接隐藏「导出」按钮
  if (state.isAdmin) $("export-btn").classList.remove("hidden");
  else $("export-btn").classList.add("hidden");
  loadKeysStatus();
  loadEntries();
}

async function loadKeysStatus() {
  try {
    const s = await api("/api/keys/status");
    const gpg = s.gpg ? '<span class="ok">● GPG 就绪</span>' : '<span class="no">● GPG 缺失</span>';
    const sm2 = s.sm2 ? '<span class="ok">● SM2 就绪</span>' : '<span class="no">● SM2 缺失</span>';
    $("keys-status").innerHTML = `服务端密钥：${gpg}　${sm2}`;
  } catch (e) {
    $("keys-status").textContent = "密钥状态获取失败";
  }
}

async function loadEntries() {
  try {
    state.entries = await api("/api/passwords");
    renderTable();
  } catch (e) {
    if (isAuthErr(e)) doLogout();
    else showToast("加载失败：" + e.message);
  }
}

function renderTable() {
  const q = ($("search-input").value || "").trim().toLowerCase();
  const rows = state.entries.filter((e) =>
    !q || (e.username || "").toLowerCase().includes(q) || (e.key_name || "").toLowerCase().includes(q)
  );
  const tbody = $("pw-tbody");
  tbody.innerHTML = "";
  $("empty-hint").classList.toggle("hidden", state.entries.length > 0);
  if (!rows.length && state.entries.length) {
    tbody.innerHTML = `<tr><td colspan="7" style="color:#6b7280">无匹配结果</td></tr>`;
    return;
  }
  for (const e of rows) {
    const tr = document.createElement("tr");
    const keyTip = e.key_name ? `<div style="font-size:11px;color:#6b7280;margin-top:2px">🔑 ${esc(e.key_name)}</div>` : "";
    const lockTip = e.needs_password ? ` <span title="需输入解密密码才能查看">🔒</span>` : "";
    const checked = state.selected.has(e.id) ? "checked" : "";
    tr.innerHTML = `
      <td class="col-select"><input type="checkbox" class="row-select" data-id="${e.id}" ${checked} /></td>
      <td>${esc(e.username) || "<span style='color:#9ca3af'>未填</span>"}</td>
      <td>${algoBadge(e.algorithm)}${lockTip}${keyTip}</td>
      <td>${esc(groupName(e.group_id))}</td>
      <td>${fmtTime(e.updated_at)}</td>
      <td>${esc(e.updated_by || e.created_by || "")}</td>
      <td><div class="ops">
        <button class="btn ghost small" data-act="view" data-id="${e.id}">查看</button>
        <button class="btn ghost small" data-act="edit" data-id="${e.id}">编辑</button>
        <button class="btn ghost small" data-act="hist" data-id="${e.id}">记录</button>
        <button class="btn danger small" data-act="del" data-id="${e.id}">删除</button>
      </div></td>`;
    tbody.appendChild(tr);
  }
  // 同步工具栏「全选」框（按当前过滤结果）
  const allBox = $("select-all");
  if (allBox) {
    const allIds = rows.map((r) => r.id);
    allBox.checked = allIds.length > 0 && allIds.every((id) => state.selected.has(id));
  }
  updateExportBtn();
}

function updateExportBtn() {
  const btn = $("export-btn");
  const n = state.selected.size;
  btn.disabled = n === 0;
  btn.textContent = n > 0 ? `📤 导出 (${n})` : "📤 导出";
}

function onRowSelect(ev) {
  const cb = ev.target.closest("input.row-select");
  if (!cb) return;
  const id = Number(cb.dataset.id);
  if (cb.checked) state.selected.add(id);
  else state.selected.delete(id);
  updateExportBtn();
}

function onSelectAll(ev) {
  const checked = ev.target.checked;
  const q = ($("search-input").value || "").trim().toLowerCase();
  const rows = state.entries.filter((e) =>
    !q || (e.username || "").toLowerCase().includes(q) || (e.key_name || "").toLowerCase().includes(q)
  );
  for (const e of rows) {
    if (checked) state.selected.add(e.id);
    else state.selected.delete(e.id);
  }
  renderTable();
}

/* ---------- 分组下拉填充 ---------- */
function fillGroupSelect(selId, selectedId) {
  const sel = $(selId);
  sel.innerHTML = "";
  if (!state.groups.length) {
    sel.innerHTML = `<option value="">（无可用分组，请联系管理员）</option>`;
    sel.disabled = true;
    return;
  }
  sel.disabled = false;
  for (const g of state.groups) {
    const opt = document.createElement("option");
    opt.value = g.id;
    opt.textContent = g.name;
    if (selectedId != null && g.id === selectedId) opt.selected = true;
    sel.appendChild(opt);
  }
}

/* ---------- 加密方式 ↔ 解密密码框 + OrgKey 选择联动 ---------- */
let pendingOrgkeyId = null;  // 编辑时用于预选 OrgKey

async function loadOrgkeysForSelect(selectId) {
  const sel = $("f-orgkey");
  sel.innerHTML = "";
  const algo = $("f-algorithm").value;  // 'gpg' | 'sm2'
  const groupId = Number($("f-group").value || 0);
  if (!groupId) {
    sel.innerHTML = `<option value="">（请先选择分组）</option>`;
    return;
  }
  sel.disabled = true;
  try {
    const rows = await api(`/api/orgkeys?group_id=${groupId}&algorithm=${algo}`);
    sel.innerHTML = `<option value="">（默认：服务端密钥）</option>`;
    for (const k of rows) {
      const opt = document.createElement("option");
      opt.value = k.id;
      const hasLabel = k.has_private ? "（含私钥）" : "（仅公钥）";
      opt.textContent = `${k.name} · ${k.algorithm.toUpperCase()} ${hasLabel}`;
      sel.appendChild(opt);
    }
    if (selectId != null) sel.value = String(selectId);
    // 若表单当前处于「未解密」锁定状态，加载完成后仍保持置灰
    sel.disabled = formLocked;
  } catch (e) {
    sel.innerHTML = `<option value="">（加载失败：${esc(e.message)}）</option>`;
  }
}

function applyAlgoUI() {
  const algo = $("f-algorithm").value;
  const isSymmetric = algo === "symmetric";
  const isAdd = state.editingId == null;
  // 「解密密码」内层始终显示且必填（symmetric / gpg / sm2 都需要）
  $("f-entry-pw-label").classList.remove("hidden");
  $("f-entry-password").classList.remove("hidden");
  $("f-entry-password").required = true;
  // 确认解密密码：仅「新增」模式显示（需两次输入确认）
  $("f-entry-pw-confirm-label").classList.toggle("hidden", !isAdd);
  $("f-entry-password-confirm").classList.toggle("hidden", !isAdd);
  if (!isAdd) $("f-entry-password-confirm").value = "";
  // 新解密密码（编辑时可选，留空则沿用）
  $("f-new-pw-label").classList.toggle("hidden", isAdd);
  $("f-new-entry-password").classList.toggle("hidden", isAdd);
  // OrgKey 选取：gpg/sm2 显示（按当前算法过滤），symmetric 隐藏
  $("f-orgkey-label").classList.toggle("hidden", isSymmetric);
  $("f-orgkey").classList.toggle("hidden", isSymmetric);
  $("f-orgkey-hint").classList.toggle("hidden", isSymmetric);
  if (!isSymmetric) loadOrgkeysForSelect(pendingOrgkeyId);
}

/* 明文显示 / 隐藏「解密密码」相关输入框（新增确认 + 编辑新密码） */
function toggleEntryReveal() {
  const ids = ["f-entry-password", "f-entry-password-confirm", "f-new-entry-password"];
  const visible = ids.filter((id) => !$(id).classList.contains("hidden"));
  if (!visible.length) return;
  const show = $(visible[0]).type === "password";
  visible.forEach((id) => { $(id).type = show ? "text" : "password"; });
  $("f-entry-reveal").textContent = show ? "隐藏" : "显示";
}

/* 编辑解锁成功后：把「解密密码」框锁为只读，禁止当场修改（查看/修改已要求先输入此密码）。 */
function lockEntryPasswordField() {
  const inp = $("f-entry-password");
  inp.disabled = true;
  inp.readOnly = true;
  inp.title = "解密成功后已锁定，不可修改；如需更改请使用下方「新解密密码」";
  const rev = $("f-entry-reveal");
  rev.disabled = true;
  rev.textContent = "🔒已锁定";
}

/* ---------- 表单弹窗（新增 / 编辑） ---------- */
// 编辑模式下「未成功解密」时，除「取消」外，下方表单的所有字段都置灰；
// 但锁框自身的「解密密码」输入框与「解密并继续」按钮必须保持可用，否则无法解锁；
// 未解密时，加密密钥（OrgKey）选项同样保持置灰。只保留「取消」一个逃生出口。
let formLocked = false;  // 当前表单是否处于「未解密」锁定状态
const FORM_EDIT_LOCKED_IDS = [
  // 表单字段
  "f-username", "f-algorithm",
  "f-entry-password", "f-entry-password-confirm", "f-new-entry-password",
  "f-orgkey", "f-group", "f-secret",
  // 表单内联按钮
  "f-reveal", "f-gen", "f-entry-reveal",
  // 备注 / 说明
  "f-notes", "f-comment",
  // 主操作按钮
  "form-save",
];
function setFormEditLocked(locked) {
  formLocked = !!locked;
  for (const id of FORM_EDIT_LOCKED_IDS) {
    const el = document.getElementById(id);
    if (el) el.disabled = !!locked;
  }
  // 锁框的解密输入框 / 解锁按钮始终可用；取消按钮永远可用
  const cancel = document.getElementById("form-cancel");
  if (cancel) cancel.disabled = false;
}

function openAdd() {
  state.editingId = null;
  state.originalSecret = "";
  state.originalAlgorithm = "";
  state.editEntryPassword = null;
  pendingOrgkeyId = null;
  $("form-title").textContent = "新增密码";
  $("f-username").value = "";
  $("f-secret").value = "";
  $("f-secret").type = "password";
  $("f-reveal").textContent = "显示";
  $("f-algorithm").value = "symmetric";
  $("f-entry-password").value = "";
  $("f-entry-password-confirm").value = "";
  $("f-new-entry-password").value = "";
  $("f-notes").value = "";
  $("f-comment").value = "";
  $("f-group").disabled = false;
  // 新增场景：解密密码框必须可编辑（复位上一次编辑遗留的只读/锁定态）
  $("f-entry-password").disabled = false;
  $("f-entry-password").readOnly = false;
  $("f-entry-password").title = "";
  $("f-entry-reveal").disabled = false;
  $("f-entry-reveal").textContent = "显示";
  $("form-lock").classList.add("hidden");
  $("form-save").disabled = false;
  fillGroupSelect("f-group", null);
  $("form-error").textContent = "";
  applyAlgoUI();
  setFormEditLocked(false);
  $("form-modal").classList.remove("hidden");
  $("f-username").focus();
}

async function openEdit(id) {
  const rec = state.entries.find((e) => e.id === id);
  if (!rec) return;
  state.editingId = id;
  state.originalAlgorithm = rec.algorithm;
  state.editEntryPassword = null;
  const needsPw = rec.needs_password;
  $("form-title").textContent = needsPw ? "编辑密码（需先解密）" : "编辑密码";
  $("f-username").value = rec.username;
  $("f-notes").value = rec.notes || "";
  $("f-comment").value = "";
  $("f-entry-password").value = "";
  $("f-entry-password-confirm").value = "";
  $("f-new-entry-password").value = "";
  fillGroupSelect("f-group", rec.group_id);
  $("f-group").disabled = true; // 数据归属固定
  $("form-error").textContent = "";

  // 根据当前方案选择默认算法
  $("f-algorithm").value = rec.algorithm; // 'symmetric' | 'gpg' | 'sm2'
  pendingOrgkeyId = rec.orgkey_id != null ? rec.orgkey_id : null;
  applyAlgoUI(); // 内部会按当前算法拉取并预选 OrgKey

  if (needsPw) {
    // 受「解密密码」保护：先弹锁，输入当前密码解密后才能编辑
    state.originalSecret = "";
    $("f-secret").value = "";
    $("f-secret").type = "password";
    $("f-reveal").textContent = "显示";
    $("form-lock").classList.remove("hidden");
    setFormEditLocked(true);
    $("form-modal").classList.remove("hidden");
    $("form-lock-password").value = "";
    $("form-lock-error").textContent = "";
    $("form-lock-password").focus();
  } else {
    // 旧式 legacy（无解密密码层）：服务端密钥 / OrgKey 私钥可直接取明文
    try {
      const full = await api("/api/passwords/" + id);
      state.originalSecret = full.secret;
    } catch (e) {
      showToast("加载失败：" + e.message);
      return;
    }
    $("f-secret").value = state.originalSecret;
    $("f-secret").type = "password";
    $("f-reveal").textContent = "显示";
    $("form-lock").classList.add("hidden");
    setFormEditLocked(false);
    $("form-modal").classList.remove("hidden");
    $("f-username").focus();
  }
}

/* 编辑解锁：输入当前解密密码，解密后回填明文并允许编辑 */
async function unlockEdit() {
  const id = state.editingId;
  const pw = $("form-lock-password").value;
  if (!pw) { $("form-lock-error").textContent = "请输入当前解密密码"; return; }
  showWait("正在解密…");
  try {
    const full = await fetchSecret(id, pw);
    state.originalSecret = full.secret;
    state.editEntryPassword = pw;
    $("f-secret").value = full.secret;
    $("f-secret").type = "password";
    $("f-reveal").textContent = "显示";
    $("f-entry-password").value = pw; // 记住当前密码，保存时作为 entry_password 使用
    $("form-lock").classList.add("hidden");
    setFormEditLocked(false);
    // 已解密：把「解密密码」框锁为只读 —— 查看/修改时必须先输入此密码才能解锁，
    // 解锁后该值即本条目当前解密密码，禁止当场修改（避免与已解密明文不一致）。
    lockEntryPasswordField();
    $("f-username").focus();
  } catch (e) {
    // 解密失败：保留锁框 + 下方面板继续置灰
    $("form-lock-error").textContent = e.message;
    setFormEditLocked(true);
  } finally {
    hideWait();
  }
}

/* 用请求体（POST，不在 URL 中）传解密密码，解密并返回明文 */
async function fetchSecret(id, pw) {
  return await api("/api/passwords/" + id + "/unlock", {
    method: "POST",
    body: JSON.stringify({ entry_password: pw || "" }),
  });
}

function closeForm() {
  setFormEditLocked(false);
  $("form-modal").classList.add("hidden");
}

async function saveForm() {
  $("form-error").textContent = "";
  const secret = $("f-secret").value;
  const algo = $("f-algorithm").value;
  const entryPassword = $("f-entry-password").value;
  const newEntryPassword = $("f-new-entry-password").value;
  const orgkeyVal = $("f-orgkey").value;
  const orgkeyId = orgkeyVal ? Number(orgkeyVal) : null;
  if (!secret) return ($("form-error").textContent = "请输入密码 / 密钥明文");
  if (!state.groups.length) return ($("form-error").textContent = "你没有可用的分组，无法创建");

  const payload = {
    username: $("f-username").value.trim(),
    notes: $("f-notes").value,
    comment: $("f-comment").value,
  };

  if (state.editingId == null) {
    // 新增：三种算法都必须填写解密密码，且需两次确认一致
    if (!entryPassword)
      return ($("form-error").textContent = "请输入解密密码");
    if (entryPassword !== $("f-entry-password-confirm").value)
      return ($("form-error").textContent = "两次输入的解密密码不一致");
    // 重复新增校验：同一分组下不允许「账号名称 + 加密方式」完全相同
    const groupId = Number($("f-group").value);
    const uName = $("f-username").value.trim().toLowerCase();
    const dup = state.entries.find(
      (e) =>
        e.group_id === groupId &&
        (e.username || "").trim().toLowerCase() === uName &&
        e.algorithm === algo
    );
    if (dup) {
      return ($("form-error").textContent =
        `该分组下已存在账号「${$("f-username").value.trim()}」且加密方式相同（${algo}），请勿重复新增`);
    }
    payload.group_id = groupId;
    payload.secret = secret;
    payload.algorithm = algo;
    payload.entry_password = entryPassword;
    if (algo !== "symmetric" && orgkeyId) payload.orgkey_id = orgkeyId;
  } else {
    const rec = state.entries.find((e) => e.id === state.editingId);
    const needsPw = rec && rec.needs_password;
    // 受解密密码保护：以解锁时输入的密码（或此处填写的）为准
    const curPw = entryPassword || state.editEntryPassword || "";
    // 受解密密码保护：必须提供当前解密密码（或新解密密码）
    if (needsPw && !curPw && !newEntryPassword)
      return ($("form-error").textContent = "请输入当前解密密码才能修改");
    // 目标 symmetric：必须提供（或设置新）解密密码
    if (algo === "symmetric" && !curPw && !newEntryPassword)
      return ($("form-error").textContent = "切换到「对称加密」必须提供解密密码或新解密密码");
    // 目标 gpg/sm2 且当前为旧式 legacy（无解密密码层）升级时：必须提供解密密码
    if (algo !== "symmetric" && !needsPw && !curPw && !newEntryPassword && !orgkeyId)
      return ($("form-error").textContent = "为该记录设置解密密码后才能保存（请输入解密密码或新解密密码）");
    payload.algorithm = algo;
    payload.secret = secret;
    if (curPw) payload.entry_password = curPw;
    if (newEntryPassword) payload.new_entry_password = newEntryPassword;
    if (algo !== "symmetric" && orgkeyId) payload.orgkey_id = orgkeyId;
  }

  const waitText = state.editingId == null ? "正在加密保存…" : "正在解密并重新加密…";
  showWait(waitText);
  try {
    if (state.editingId == null) {
      await api("/api/passwords", { method: "POST", body: JSON.stringify(payload) });
      showToast("已新增");
    } else {
      await api("/api/passwords/" + state.editingId, { method: "PUT", body: JSON.stringify(payload) });
      showToast("已保存");
    }
    closeForm();
    loadEntries();
  } catch (e) {
    $("form-error").textContent = e.message;
    showToast("保存失败：" + e.message);
  } finally {
    hideWait();
  }
}

/* ---------- 查看弹窗 ---------- */
async function openView(id) {
  const rec = state.entries.find((e) => e.id === id);
  if (!rec) return;
  state.viewingId = id;
  $("view-title").textContent = "查看：" + (rec.username || rec.id);
  $("view-username").textContent = rec.username || "—";
  const keyTip = rec.key_name ? ` <span style="color:#6b7280;font-size:13px">🔑 ${esc(rec.key_name)}</span>` : "";
  $("view-algorithm").innerHTML = algoBadge(rec.algorithm) + keyTip;
  $("view-group").textContent = groupName(rec.group_id);
  $("view-notes").textContent = rec.notes || "—";
  $("view-lock-error").textContent = "";
  $("view-entry-password").value = "";

  if (rec.needs_password) {
    // 需输入解密密码才能查看（symmetric / hybrid gpg / sm2 均如此）
    $("view-lock").classList.remove("hidden");
    $("view-secret-wrap").classList.add("hidden");
    $("view-secret").textContent = "";
    $("view-modal").classList.remove("hidden");
    $("view-entry-password").focus();
  } else {
    // 旧式 legacy（无解密密码层）：服务端密钥，直接取明文（带等待窗口）
    showWait("正在解密…");
    try {
      const full = await api("/api/passwords/" + id);
      $("view-lock").classList.add("hidden");
      $("view-secret-wrap").classList.remove("hidden");
      $("view-secret").textContent = full.secret;
      $("view-modal").classList.remove("hidden");
    } catch (e) {
      showToast("加载失败：" + e.message);
    } finally {
      hideWait();
    }
  }
}

async function viewUnlock() {
  const id = state.viewingId;
  const pw = $("view-entry-password").value;
  if (!pw) { $("view-lock-error").textContent = "请输入解密密码"; return; }
  showWait("正在解密…");
  try {
    // 密码通过请求体（POST）传输，不会出现在 URL / 服务器访问日志 / 浏览器历史中
    const full = await fetchSecret(id, pw);
    $("view-lock").classList.add("hidden");
    $("view-secret-wrap").classList.remove("hidden");
    $("view-secret").textContent = full.secret;
  } catch (e) {
    $("view-lock-error").textContent = e.message;
  } finally {
    hideWait();
  }
}

function copySecret() {
  const text = $("view-secret").textContent;
  navigator.clipboard.writeText(text).then(() => showToast("已复制到剪贴板"), () => showToast("复制失败"));
}

/* ---------- 修改记录弹窗 ---------- */
// 历史 comment 里可能出现的英文字段名 -> 中文标签；新写入已直接用中文，这里是对存量/接口残留做兜底
const HISTORY_FIELD_LABELS = {
  title: "标题",
  username: "账号",
  notes: "备注",
  secret: "密码明文",
  entry_password: "解密密码",
  algorithm: "加密方式",
  orgkey_id: "加密密钥",
};
const HISTORY_ACTION_LABELS = { create: "新增", update: "修改", delete: "删除", export: "导出" };

/* 把后端写入的 comment 里残留的英文字段名替换成中文。
 * 例："修改了 secret,entry_password,notes" -> "修改了 密码明文，解密密码，备注"
 */
function humanizeComment(c) {
  if (!c) return c;
  // 匹配 "修改了 xxx,yyy" 形式（xxx 可能是英文或中文，统一查表翻译）
  return c.replace(/(修改了)\s+([^\s,.，。；;]+(?:[\s,，；;][^\s,.，。；;]+)*)/g, (_, verb, list) => {
    const parts = list.split(/[\s,，;；]+/).filter(Boolean);
    const translated = parts.map((p) => HISTORY_FIELD_LABELS[p] || p).join("，");
    return verb + " " + translated;
  });
}

async function openHistory(id) {
  try {
    const rows = await api("/api/passwords/" + id + "/history");
    const tbody = $("history-tbody");
    tbody.innerHTML = "";
    if (!rows.length) {
      tbody.innerHTML = `<tr><td colspan="6" style="color:#6b7280">暂无记录</td></tr>`;
    }
    for (const r of rows) {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${fmtTime(r.changed_at)}</td>
        <td class="act-${r.action}">${HISTORY_ACTION_LABELS[r.action] || r.action}</td>
        <td>${esc(r.username || "")}</td>
        <td>${algoBadge(r.algorithm)}</td>
        <td>${esc(r.changed_by || "")}</td>
        <td>${esc(humanizeComment(r.comment || ""))}</td>`;
      tbody.appendChild(tr);
    }
    $("history-modal").classList.remove("hidden");
  } catch (e) {
    showToast("加载失败：" + e.message);
  }
}

/* ---------- 删除（两步确认） ---------- */
let pendingDeleteId = null;
let pendingDeleteType = "pw";
let pendingDeleteName = "";

function _delAccountLabel(id) {
  const e = state.entries.find((x) => x.id === id);
  if (!e) return "未知账号";
  return e.username || e.title || ("#" + id);
}

/* 第一步：风险提示弹窗（密码 / 密钥通用） */
function doDelete(id) {
  const e = state.entries.find((x) => x.id === id);
  const name = e ? (e.username || e.title || ("#" + id)) : "未知账号";
  _openDelConfirm(name, "账号", id, "pw");
}

/* 密钥删除：走与密码删除相同的二次确认流程 */
function doDeleteKey(id) {
  const k = keyState.entries.find((x) => x.id === id);
  const name = k ? (k.name || ("#" + id)) : ("#" + id);
  _openDelConfirm(name, "密钥", id, "key");
}

function _openDelConfirm(name, kind, id, type) {
  pendingDeleteId = id;
  pendingDeleteType = type;
  pendingDeleteName = name;
  $("del-kind-1").textContent = kind;
  $("del-target-1").textContent = name;
  $("del-confirm-modal").classList.remove("hidden");
}

/* 第二步：键入「确认删除」才放行 */
function showDelTypeStep() {
  if (pendingDeleteId == null) return;
  $("del-kind-2").textContent = pendingDeleteType === "key" ? "密钥" : "账号";
  $("del-target-2").textContent = pendingDeleteName;
  const inp = $("del-type-input");
  inp.value = "";
  $("del-type-confirm").disabled = true;
  $("del-type-hint").textContent = "";
  $("del-type-hint").classList.remove("ok");
  $("del-confirm-modal").classList.add("hidden");
  $("del-type-modal").classList.remove("hidden");
  inp.focus();
}

function onDelTypeInput() {
  const val = $("del-type-input").value.trim();
  const ok = val === "确认删除";
  $("del-type-confirm").disabled = !ok;
  $("del-type-hint").textContent = val && !ok ? "输入内容不符，请键入「确认删除」" : "";
  $("del-type-hint").classList.toggle("ok", ok);
}

async function confirmDelTyped() {
  if (pendingDeleteId == null) return;
  if ($("del-type-input").value.trim() !== "确认删除") return;
  const id = pendingDeleteId;
  const type = pendingDeleteType;
  $("del-type-modal").classList.add("hidden");
  pendingDeleteId = null;
  pendingDeleteType = "pw";
  pendingDeleteName = "";
  try {
    if (type === "key") {
      await api("/api/orgkeys/" + id, { method: "DELETE" });
      showToast("已删除密钥（已记入审计日志）");
      loadOrgKeys();
    } else {
      await api("/api/passwords/" + id, { method: "DELETE" });
      showToast("已删除密码（已记入审计日志）");
      loadEntries();
    }
  } catch (e) {
    showToast("删除失败：" + e.message);
  }
}

function cancelDel() {
  $("del-confirm-modal").classList.add("hidden");
  $("del-type-modal").classList.add("hidden");
  pendingDeleteId = null;
}

/* ---------- 随机密码 ---------- */
function genRandom() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#$%^&*";
  let s = "";
  for (let i = 0; i < 16; i++) s += chars[Math.floor(Math.random() * chars.length)];
  $("f-secret").value = s;
  $("f-secret").type = "text";
  $("f-reveal").textContent = "隐藏";
}

/* ---------- 批量导出密码（仅明文） ---------- */
function openExport() {
  if (!state.selected.size) { showToast("请先勾选要导出的密码"); return; }
  $("export-count").textContent = String(state.selected.size);
  // 默认 JSON 格式
  $("exp-fmt-json").checked = true;
  $("exp-fmt-csv").checked = false;
  $("export-master-pw").value = "";
  renderExportPerRow("");
  $("export-error").textContent = "";
  $("export-modal").classList.remove("hidden");
  $("export-master-pw").focus();
}

function renderExportPerRow(masterPw) {
  const tbody = $("export-perrow");
  tbody.innerHTML = "";
  const map = {};
  state.entries.forEach((e) => { if (state.selected.has(e.id)) map[e.id] = e; });
  const ids = [...state.selected];
  for (const id of ids) {
    const e = map[id];
    const uname = (e && e.username) || ("#" + id);
    const algoText = e && e.algorithm === "symmetric" ? "对称加密" : (e && e.algorithm === "sm2" ? "SM2" : "GPG");
    const div = document.createElement("div");
    div.className = "exp-row";
    div.innerHTML = `
      <div class="exp-row-info">
        <div class="exp-row-name" title="${esc(uname)}">${esc(uname)}</div>
        <div class="exp-row-algo">${esc(algoText)}</div>
      </div>
      <input type="password" class="exp-pw" data-id="${id}" value="${esc(masterPw)}" placeholder="该条目解密密码" autocomplete="off" />`;
    tbody.appendChild(div);
  }
}

/* 输入「统一解密密码」后：逐项密码框置灰，并展示统一密码内容；
   清空统一密码则恢复逐项可填并清空镜像内容。 */
function syncMasterToPerRow() {
  const master = $("export-master-pw").value;
  const hasMaster = master !== "";
  document.querySelectorAll("#export-perrow .exp-pw").forEach((inp) => {
    inp.disabled = hasMaster;
    if (hasMaster) inp.value = master;
    else inp.value = "";
  });
}

async function doExport() {
  const fmt = document.querySelector('input[name="exp-format"]:checked').value;
  const ids = [...state.selected];
  const master = $("export-master-pw").value || "";
  const passwords = {};
  document.querySelectorAll("#export-perrow .exp-pw").forEach((inp) => {
    passwords[inp.dataset.id] = inp.value || master;
  });
  $("export-error").textContent = "";
  showWait("正在导出…");
  try {
    const res = await fetch("/api/passwords/export", {
      method: "POST",
      headers: { Authorization: "Bearer " + state.token, "Content-Type": "application/json" },
      body: JSON.stringify({ ids, passwords, format: fmt, plaintext: true }),
    });
    if (!res.ok) {
      let detail = null;
      try { detail = await res.json(); } catch (e) {}
      const msg = (detail && (detail.detail || detail.message)) || ("导出失败 (" + res.status + ")");
      throw new Error(typeof msg === "string" ? msg : JSON.stringify(msg));
    }
    const blob = await res.blob();
    const disp = res.headers.get("Content-Disposition");
    const ext = fmt === "csv" ? "csv" : "json";
    triggerDownload(blob, filenameFromDisposition(disp, "password_export." + ext));
    showToast("已导出 " + ids.length + " 条");
    $("export-modal").classList.add("hidden");
  } catch (e) {
    $("export-error").textContent = e.message;
  } finally {
    hideWait();
  }
}

/* ---------- 批量导入密码 ---------- */
function openImport() {
  $("pw-import-file").value = "";
  $("pw-import-entry-pw").value = "";
  $("pw-import-entry-pw").type = "password";
  $("pw-import-pw-reveal").textContent = "显示";
  $("pw-import-algorithm").value = "symmetric";
  $("pw-import-error").textContent = "";
  $("pw-import-summary").classList.add("hidden");
  $("pw-import-summary").textContent = "";
  $("pw-import-results").classList.add("hidden");
  $("pw-import-results").innerHTML = "";
  $("pw-import-go").disabled = true;
  loadImportOrgkeys();
  $("pw-import-modal").classList.remove("hidden");
}

function closeImport() {
  $("pw-import-modal").classList.add("hidden");
}

function onImportFileChange(ev) {
  $("pw-import-go").disabled = !(ev.target.files && ev.target.files.length > 0);
  // 重置上一次回执
  $("pw-import-summary").classList.add("hidden");
  $("pw-import-summary").textContent = "";
  $("pw-import-results").classList.add("hidden");
  $("pw-import-results").innerHTML = "";
  $("pw-import-error").textContent = "";
}

async function loadImportOrgkeys() {
  const sel = $("pw-import-orgkey");
  const algo = $("pw-import-algorithm").value;
  if (algo === "symmetric") {
    sel.classList.add("hidden");
    $("pw-import-orgkey-label").classList.add("hidden");
    return;
  }
  sel.classList.remove("hidden");
  $("pw-import-orgkey-label").classList.remove("hidden");
  sel.innerHTML = "";
  try {
    const rows = await api(`/api/orgkeys?algorithm=${algo}`);
    sel.innerHTML = `<option value="">（默认：服务端密钥）</option>`;
    for (const k of rows) {
      const opt = document.createElement("option");
      opt.value = k.id;
      const hasLabel = k.has_private ? "（含私钥）" : "（仅公钥）";
      opt.textContent = `${k.name} · ${groupName(k.group_id)} ${hasLabel}`;
      sel.appendChild(opt);
    }
  } catch (e) {
    sel.innerHTML = `<option value="">（加载失败：${esc(e.message)}）</option>`;
  }
}

function pwImportAlgoChange() {
  loadImportOrgkeys();
}

function pwImportPwReveal() {
  const inp = $("pw-import-entry-pw");
  if (inp.type === "password") { inp.type = "text"; $("pw-import-pw-reveal").textContent = "隐藏"; }
  else { inp.type = "password"; $("pw-import-pw-reveal").textContent = "显示"; }
}

async function downloadPasswordTemplate(fmt) {
  try {
    const resp = await fetch(`/api/passwords/template?fmt=${fmt}`, {
      headers: { Authorization: "Bearer " + state.token },
    });
    if (!resp.ok) throw new Error("模板下载失败 (" + resp.status + ")");
    const blob = await resp.blob();
    triggerDownload(blob, `密码批量导入模板.${fmt}`);
  } catch (e) {
    showError("模板下载失败：" + e.message);
  }
}

async function doPasswordImport() {
  const fileEl = $("pw-import-file");
  if (!fileEl.files || !fileEl.files.length) {
    $("pw-import-error").textContent = "请先选择要导入的文件";
    return;
  }
  const entryPassword = $("pw-import-entry-pw").value;
  if (!entryPassword) {
    $("pw-import-error").textContent = "请先填写「加密密码（解密密码）」";
    return;
  }
  const algorithm = $("pw-import-algorithm").value;
  const orgkeyVal = $("pw-import-orgkey").value;
  const orgkeyId = orgkeyVal ? Number(orgkeyVal) : null;

  const fd = new FormData();
  fd.append("file", fileEl.files[0]);
  fd.append("algorithm", algorithm);
  fd.append("entry_password", entryPassword);
  if (orgkeyId) fd.append("orgkey_id", String(orgkeyId));

  $("pw-import-error").textContent = "";
  showWait("正在导入…");
  try {
    const res = await fetch("/api/passwords/import", {
      method: "POST",
      headers: { Authorization: "Bearer " + state.token },
      body: fd,
    });
    const data = await res.json().catch(() => null);
    if (!res.ok) {
      const msg = (data && (data.detail || data.message)) || ("导入失败 (" + res.status + ")");
      throw new Error(typeof msg === "string" ? msg : JSON.stringify(msg));
    }
    renderImportResults(data);
    showToast(`导入完成：成功 ${data.created}，失败 ${data.errored}，跳过 ${data.skipped}`);
    loadEntries();
  } catch (e) {
    $("pw-import-error").textContent = e.message;
  } finally {
    hideWait();
  }
}

function renderImportResults(data) {
  $("pw-import-summary").classList.remove("hidden");
  $("pw-import-summary").textContent =
    `共 ${data.total} 行：成功 ${data.created}，失败 ${data.errored}，跳过 ${data.skipped}`;
  const box = $("pw-import-results");
  box.classList.remove("hidden");
  box.innerHTML = "";
  for (const r of data.rows) {
    const cls = r.status === "created" ? "exp-pill-ok" : (r.status === "skipped" ? "exp-pill-warn" : "exp-pill-err");
    const label = r.status === "created" ? "成功" : (r.status === "skipped" ? "跳过" : "失败");
    const div = document.createElement("div");
    div.className = "exp-row";
    div.innerHTML = `
      <div class="exp-row-info">
        <div class="exp-row-name">第 ${r.row} 行 · ${esc(r.username || "(空)")}</div>
        <div class="exp-row-algo">${esc(r.message || "")}</div>
      </div>
      <span class="exp-pill ${cls}">${label}</span>`;
    box.appendChild(div);
  }
}

async function apiBlob(path) {
  const res = await fetch(path, { headers: { Authorization: "Bearer " + state.token } });
  // 一定要先按 Content-Type 分支消费 body；
  // 否则对非 JSON 响应（公钥文本/文件密文）盲目 res.json() 会消耗 stream，
  // 后续 res.blob() 抛 "body stream already read"。
  const ct = (res.headers.get("Content-Type") || "").toLowerCase();
  if (!res.ok) {
    let detail = null;
    if (ct.includes("json")) {
      try { detail = await res.json(); } catch (e) {}
      const msg = (detail && (detail.detail || detail.message)) || ("下载失败 (" + res.status + ")");
      throw new Error(typeof msg === "string" ? msg : JSON.stringify(msg));
    }
    throw new Error("下载失败 (" + res.status + ")");
  }
  return { blob: await res.blob(), disposition: res.headers.get("Content-Disposition") };
}

function filenameFromDisposition(disp, fallback) {
  if (!disp) return fallback;
  const star = disp.match(/filename\*=UTF-8''([^;]+)/i);
  if (star) { try { return decodeURIComponent(star[1]); } catch (e) {} }
  const m = disp.match(/filename="?([^";]+)"?/i);
  if (m) return m[1];
  return fallback;
}

function triggerDownload(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/* ---------- 密钥库（按组织维度） ---------- */
let keyState = { entries: [] };

async function loadOrgKeys() {
  try {
    fillGroupSelect("key-group-filter", null);
    keyState.entries = await api("/api/orgkeys");
    renderKeyTable();
  } catch (e) {
    if (isAuthErr(e)) doLogout();
    else showToast("加载密钥库失败：" + e.message);
  }
}

function renderKeyTable() {
  const tbody = $("key-tbody");
  tbody.innerHTML = "";
  const filterGid = Number($("key-group-filter").value || 0);
  const q = ($("key-search").value || "").trim().toLowerCase();
  let rows = keyState.entries;
  if (filterGid > 0) rows = rows.filter((k) => k.group_id === filterGid);
  if (q) rows = rows.filter((k) => (k.name + " " + (k.created_by || "")).toLowerCase().includes(q));
  rows.forEach((k) => tbody.appendChild(keyRow(k)));
  $("key-empty").classList.toggle("hidden", keyState.entries.length > 0);
  if (!rows.length && keyState.entries.length) {
    tbody.innerHTML = `<tr><td colspan="8" style="color:#6b7280">无匹配结果</td></tr>`;
  } else if (!keyState.entries.length) {
    tbody.innerHTML = "";
  }
}

function keyRow(k) {
  const tr = document.createElement("tr");
  tr.innerHTML = `
    <td>${esc(k.name)}</td>
    <td>${algoBadge(k.algorithm)}</td>
    <td>${esc(groupName(k.group_id))}</td>
    <td><code style="font-size:11px">${esc(k.fingerprint)}</code></td>
    <td>${k.has_private ? '<span class="ok">✓ 有</span>' : '<span style="color:#9ca3af">— 无</span>'}</td>
    <td>${fmtTime(k.created_at)}</td>
    <td>${esc(k.created_by || "")}</td>
    <td><div class="ops">
      <button class="btn ghost small" data-kact="pub"  data-id="${k.id}">导出公钥</button>
      ${k.has_private ? `<button class="btn ghost small" data-kact="priv" data-id="${k.id}">导出私钥</button>` : ""}
      <button class="btn danger small" data-kact="del" data-id="${k.id}">删除</button>
    </div></td>`;
  return tr;
}

function openKeyGen() {
  if (!state.groups.length) { showToast("你没有可用的分组，无法生成"); return; }
  $("kg-name").value = "";
  $("kg-algorithm").value = "gpg";
  fillGroupSelect("kg-group", state.isAdmin ? null : state.groups[0].id);
  $("kg-error").textContent = "";
  $("keygen-modal").classList.remove("hidden");
  $("kg-name").focus();
}
function closeKeyGen() { $("keygen-modal").classList.add("hidden"); }

async function saveKeyGen() {
  $("kg-error").textContent = "";
  const name = $("kg-name").value.trim();
  const algorithm = $("kg-algorithm").value;
  const groupId = Number($("kg-group").value);
  if (!name) return ($("kg-error").textContent = "请输入密钥名称");
  if (!groupId) return ($("kg-error").textContent = "请选择所属分组");
  showWait("正在生成密钥对…");
  try {
    await api("/api/orgkeys/generate", {
      method: "POST",
      body: JSON.stringify({ name, algorithm, group_id: groupId }),
    });
    showToast("已生成并保存密钥对");
    closeKeyGen();
    loadOrgKeys();
  } catch (e) {
    $("kg-error").textContent = e.message;
  } finally {
    hideWait();
  }
}

function openKeyImport() {
  if (!state.groups.length) { showToast("你没有可用的分组，无法导入"); return; }
  $("ki-name").value = "";
  $("ki-algorithm").value = "gpg";
  fillGroupSelect("ki-group", state.isAdmin ? null : state.groups[0].id);
  $("ki-pub").value = "";
  $("ki-priv").value = "";
  $("ki-passphrase").value = "";
  $("ki-passphrase").type = "password";
  $("ki-passphrase-reveal").textContent = "显示";
  // 默认只有用户填了私钥时才显示口令行；切换算法也会重置显示
  applyImportPassphraseUI($("ki-algorithm").value);
  $("ki-error").textContent = "";
  $("keyimport-modal").classList.remove("hidden");
  $("ki-name").focus();
}

function applyImportPassphraseUI(algorithm) {
  // 仅 GPG 私钥可能带口令；SM2 自生成的密钥本身无口令。
  // UI 显示规则：只要用户在「私钥」框里粘贴了内容，就把口令行展开供选择填写。
  const hasPriv = ($("ki-priv") && $("ki-priv").value.trim().length) > 0;
  const show = algorithm === "gpg" && hasPriv;
  ["ki-passphrase-label", "ki-passphrase-row"].forEach((id) => {
    const el = document.getElementById(id);
    if (el) el.classList.toggle("hidden", !show);
  });
}

function closeKeyImport() { $("keyimport-modal").classList.add("hidden"); }

async function saveKeyImport() {
  $("ki-error").textContent = "";
  const name = $("ki-name").value.trim();
  const algorithm = $("ki-algorithm").value;
  const groupId = Number($("ki-group").value);
  const publicKey = $("ki-pub").value;
  const privateKey = $("ki-priv").value;
  const privatePassphrase = $("ki-passphrase").value;
  if (!name) return ($("ki-error").textContent = "请输入密钥名称");
  if (!publicKey) return ($("ki-error").textContent = "请粘贴公钥内容");
  if (!groupId) return ($("ki-error").textContent = "请选择所属分组");
  showWait("正在校验并导入密钥…");
  try {
    await api("/api/orgkeys/import", {
      method: "POST",
      body: JSON.stringify({
        name, algorithm, group_id: groupId,
        public_key: publicKey, private_key: privateKey,
        private_passphrase: privatePassphrase || "",
      }),
    });
    showToast(privateKey ? "已导入公钥 + 私钥" : "已导入公钥（无私钥）");
    closeKeyImport();
    loadOrgKeys();
  } catch (e) {
    $("ki-error").textContent = e.message;
    showError(e.message || "导入失败");
  } finally {
    hideWait();
  }
}

async function exportOrgKey(id, kind) {
  const entry = keyState.entries.find((k) => k.id === id);
  const defaultName = entry ? entry.name : "key";
  try {
    const { blob, disposition } = await apiBlob("/api/orgkeys/" + id + "/export?kind=" + kind);
    const suffix = kind === "public" ? "_pub" : "_priv";
    const ext = entry && entry.algorithm === "gpg" ? ".asc" : ".key";
    triggerDownload(blob, filenameFromDisposition(disposition, defaultName + suffix + ext));
    showToast(kind === "public" ? "公钥已导出" : "⚠ 私钥已导出，请妥善保管");
  } catch (e) {
    showToast("导出失败：" + e.message);
  }
}

async function deleteOrgKey(id) {
  // 复用与密码删除一致的二次确认流程
  doDeleteKey(id);
}

function switchTab(tab) {
  document.querySelectorAll(".tab").forEach((b) => b.classList.toggle("active", b.dataset.tab === tab));
  $("pw-panel").classList.toggle("hidden", tab !== "pw");
  $("key-panel").classList.toggle("hidden", tab !== "key");
  if (tab === "key") {
    loadOrgKeys();
  }
}

/* ---------- 系统管理（管理员） ---------- */
let auditFilter = "all";

function switchSub(sub) {
  document.querySelectorAll(".subtab").forEach((b) => b.classList.toggle("active", b.dataset.sub === sub));
  $("admin-users-sec").classList.toggle("hidden", sub !== "users");
  $("admin-groups-sec").classList.toggle("hidden", sub !== "groups");
  $("admin-audit-sec").classList.toggle("hidden", sub !== "audit");
  if (sub === "audit") loadAdminAudit();
}

async function loadAdminAudit() {
  const q = auditFilter && auditFilter !== "all" ? ("?action=" + encodeURIComponent(auditFilter)) : "";
  try {
    const rows = await api("/api/admin/audit" + q);
    const tbody = $("admin-audit-tbody");
    tbody.innerHTML = "";
    if (!rows.length) {
      tbody.innerHTML = `<tr><td colspan="7" style="color:#6b7280">暂无审计记录</td></tr>`;
      return;
    }
    for (const r of rows) {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${fmtTime(r.changed_at)}</td>
        <td class="act-${r.action}">${HISTORY_ACTION_LABELS[r.action] || r.action}</td>
        <td>${esc(r.username || "")}</td>
        <td>${esc(r.title || "")}</td>
        <td>${esc(r.group_name || "—")}</td>
        <td>${esc(r.changed_by || "")}</td>
        <td>${esc(humanizeComment(r.comment || ""))}</td>`;
      tbody.appendChild(tr);
    }
  } catch (e) {
    showToast("加载审计日志失败：" + e.message);
  }
}

async function openAdmin() {
  try {
    await Promise.all([loadAdminUsers(), loadAdminGroups()]);
    switchSub("users");
    $("admin-modal").classList.remove("hidden");
  } catch (e) { showToast("加载管理数据失败：" + e.message); }
}

async function loadAdminUsers() {
  state.users = await api("/api/admin/users");
  const tbody = $("admin-users-tbody");
  tbody.innerHTML = "";
  if (!state.users.length) {
    tbody.innerHTML = `<tr><td colspan="4" style="color:#6b7280">暂无用户</td></tr>`;
    return;
  }
  for (const u of state.users) {
    const tr = document.createElement("tr");
    const gnames = u.groups.map((g) => esc(g.name)).join("、") || "—";
    tr.innerHTML = `
      <td>${esc(u.username)}</td>
      <td>${u.is_admin ? "是" : "否"}</td>
      <td>${gnames}</td>
      <td><div class="ops">
        <button class="btn ghost small" data-uact="edit" data-id="${u.id}">编辑</button>
        <button class="btn danger small" data-uact="del" data-id="${u.id}">删除</button>
      </div></td>`;
    tbody.appendChild(tr);
  }
}

async function loadAdminGroups() {
  const groups = await api("/api/admin/groups");
  const tbody = $("admin-groups-tbody");
  tbody.innerHTML = "";
  if (!groups.length) {
    tbody.innerHTML = `<tr><td colspan="4" style="color:#6b7280">暂无分组</td></tr>`;
    return;
  }
  for (const g of groups) {
    const tr = document.createElement("tr");
    const mnames = g.members.map((m) => esc(m.username)).join("、") || "—";
    tr.innerHTML = `
      <td>${esc(g.name)}</td>
      <td>${g.member_count}</td>
      <td>${mnames}</td>
      <td><div class="ops">
        <button class="btn ghost small" data-gact="edit" data-id="${g.id}">编辑</button>
        <button class="btn danger small" data-gact="del" data-id="${g.id}">删除</button>
      </div></td>`;
    tbody.appendChild(tr);
  }
}

/* ----- 用户编辑 ----- */
let editingUserId = null;

function fillGroupChecks(containerId, selectedIds) {
  const box = $(containerId);
  box.innerHTML = "";
  if (!state.groups.length) {
    box.innerHTML = `<span style="color:#6b7280">暂无可分配的分组</span>`;
    return;
  }
  for (const g of state.groups) {
    const id = "grp-" + g.id;
    const label = document.createElement("label");
    label.className = "checkbox-item";
    label.innerHTML = `<input type="checkbox" id="${id}" value="${g.id}" ${selectedIds && selectedIds.includes(g.id) ? "checked" : ""}/> ${esc(g.name)}`;
    box.appendChild(label);
  }
}

function checkedGroupIds() {
  return Array.from(document.querySelectorAll("#u-groups input[type=checkbox]:checked")).map((c) => Number(c.value));
}

function openUserAdd() {
  editingUserId = null;
  $("user-modal-title").textContent = "新增用户";
  $("user-avatar").textContent = "＋";
  $("user-role-badge").classList.add("hidden");
  $("u-username").value = "";
  $("u-username").disabled = false;
  $("u-pwd-label").textContent = "密码 *";
  $("u-password").value = "";
  $("u-password").type = "password";
  $("u-pwd-reveal").textContent = "显示";
  $("u-isadmin").checked = false;
  fillGroupChecks("u-groups", []);
  $("user-error").textContent = "";
  $("user-modal").classList.remove("hidden");
}

async function openUserEdit(id) {
  const u = state.users.find((x) => x.id === id);
  if (!u) return;
  editingUserId = id;
  $("user-modal-title").textContent = "编辑用户";
  $("user-avatar").textContent = (u.username || "U").slice(0, 1).toUpperCase();
  $("user-role-badge").classList.toggle("hidden", !u.is_admin);
  $("u-username").value = u.username;
  $("u-username").disabled = true; // 用户名不可改
  $("u-pwd-label").textContent = "密码（留空则保持不变）";
  $("u-password").value = "";
  $("u-password").type = "password";
  $("u-pwd-reveal").textContent = "显示";
  $("u-isadmin").checked = u.is_admin;
  fillGroupChecks("u-groups", u.groups.map((g) => g.id));
  $("user-error").textContent = "";
  $("user-modal").classList.remove("hidden");
}

async function saveUser() {
  $("user-error").textContent = "";
  const username = $("u-username").value.trim();
  const password = $("u-password").value;
  const isAdmin = $("u-isadmin").checked;
  const groupIds = checkedGroupIds();
  if (!username) return ($("user-error").textContent = "请输入用户名");
  if (editingUserId == null && !password) return ($("user-error").textContent = "请输入密码");

  const payload = { username, is_admin: isAdmin, group_ids: groupIds };
  if (password) payload.password = password;

  try {
    if (editingUserId == null) {
      await api("/api/admin/users", { method: "POST", body: JSON.stringify(payload) });
      showToast("已创建用户");
    } else {
      await api("/api/admin/users/" + editingUserId, { method: "PUT", body: JSON.stringify(payload) });
      showToast("已更新用户");
    }
    $("user-modal").classList.add("hidden");
    await loadAdminUsers();
    await refreshMe(); // 管理员分组列表可能变化
  } catch (e) {
    $("user-error").textContent = e.message;
  }
}

async function deleteUser(id) {
  if (!confirm("确认删除该用户？该用户的会话将失效。")) return;
  try {
    await api("/api/admin/users/" + id, { method: "DELETE" });
    showToast("已删除用户");
    await loadAdminUsers();
  } catch (e) {
    showToast("删除失败：" + e.message);
  }
}

/* ----- 自助修改登录密码（所有登录用户可用）----- */
function openChangePw() {
  $("cpw-current").value = "";
  $("cpw-new").value = "";
  $("cpw-confirm").value = "";
  $("cpw-current").type = "password";
  $("cpw-new").type = "password";
  $("cpw-current-reveal").textContent = "显示";
  $("cpw-new-reveal").textContent = "显示";
  $("cpw-error").textContent = "";
  $("changepw-modal").classList.remove("hidden");
  $("cpw-current").focus();
}
function closeChangePw() { $("changepw-modal").classList.add("hidden"); }

async function doChangePw() {
  const cur = $("cpw-current").value;
  const npw = $("cpw-new").value;
  const confirm = $("cpw-confirm").value;
  $("cpw-error").textContent = "";
  if (!cur) return ($("cpw-error").textContent = "请输入当前密码");
  if (npw.length < 8) return ($("cpw-error").textContent = "新密码至少 8 位");
  if (npw !== confirm) return ($("cpw-error").textContent = "两次输入的新密码不一致");
  showWait("正在验证并修改密码…");
  try {
    const begin = await api("/api/auth/change-password/begin", {
      method: "POST",
      body: JSON.stringify({}),
    });
    let payload;
    if (begin.mode === "scram" && begin.salt && begin.nonce) {
      // SCRAM-SM3：T = SM3(current || salt)；proof = SM3(T || nonce)
      const saltBytes = hexToBytes(begin.salt);
      const nonceBytes = hexToBytes(begin.nonce);
      const pwBytes = new TextEncoder().encode(cur);
      const tInput = new Uint8Array(pwBytes.length + saltBytes.length);
      tInput.set(pwBytes, 0);
      tInput.set(saltBytes, pwBytes.length);
      const verifierBytes = sm3Bytes(tInput);
      const proofInput = new Uint8Array(verifierBytes.length + nonceBytes.length);
      proofInput.set(verifierBytes, 0);
      proofInput.set(nonceBytes, verifierBytes.length);
      const proofBytes = sm3Bytes(proofInput);
      const proofHex = Array.from(proofBytes, (b) => b.toString(16).padStart(2, "0")).join("");
      payload = { nonce: begin.nonce, proof: proofHex, new_password: npw };
    } else {
      // legacy 兜底：未启用 SCRAM 的账号用明文当前密码校验
      payload = { current_password: cur, new_password: npw };
    }
    await api("/api/auth/change-password/verify", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    hideWait();
    closeChangePw();
    showToast("登录密码已修改");
  } catch (e) {
    hideWait();
    $("cpw-error").textContent = e.message || "修改失败";
  }
}

/* ----- 分组编辑 ----- */
let editingGroupId = null;

function fillMemberChecks(containerId, selectedIds) {
  const box = $(containerId);
  box.innerHTML = "";
  if (!state.users.length) {
    box.innerHTML = `<span style="color:#6b7280">暂无可加入的用户</span>`;
    return;
  }
  for (const u of state.users) {
    const id = "mem-" + u.id;
    const label = document.createElement("label");
    label.className = "checkbox-item";
    label.innerHTML = `<input type="checkbox" id="${id}" value="${u.id}" ${selectedIds && selectedIds.includes(u.id) ? "checked" : ""}/> ${esc(u.username)}`;
    box.appendChild(label);
  }
}

function checkedMemberIds() {
  return Array.from(document.querySelectorAll("#g-members input[type=checkbox]:checked")).map((c) => Number(c.value));
}

function openGroupAdd() {
  editingGroupId = null;
  $("group-modal-title").textContent = "新增分组";
  $("g-name").value = "";
  $("g-desc").value = "";
  fillMemberChecks("g-members", []);
  $("group-error").textContent = "";
  $("group-modal").classList.remove("hidden");
}

async function openGroupEdit(id) {
  const groups = await api("/api/admin/groups");
  const g = groups.find((x) => x.id === id);
  if (!g) return;
  editingGroupId = id;
  $("group-modal-title").textContent = "编辑分组：" + g.name;
  $("g-name").value = g.name;
  $("g-desc").value = g.description || "";
  fillMemberChecks("g-members", g.members.map((m) => m.id));
  $("group-error").textContent = "";
  $("group-modal").classList.remove("hidden");
}

async function saveGroup() {
  $("group-error").textContent = "";
  const name = $("g-name").value.trim();
  const description = $("g-desc").value;
  const memberIds = checkedMemberIds();
  if (!name) return ($("group-error").textContent = "请输入分组名称");

  const payload = { name, description, member_ids: memberIds };
  try {
    if (editingGroupId == null) {
      await api("/api/admin/groups", { method: "POST", body: JSON.stringify(payload) });
      showToast("已创建分组");
    } else {
      await api("/api/admin/groups/" + editingGroupId, { method: "PUT", body: JSON.stringify(payload) });
      showToast("已更新分组");
    }
    $("group-modal").classList.add("hidden");
    await loadAdminGroups();
    await refreshMe();
  } catch (e) {
    $("group-error").textContent = e.message;
  }
}

async function deleteGroup(id) {
  if (!confirm("确认删除该分组？若分组仍绑定数据将被阻止。")) return;
  try {
    await api("/api/admin/groups/" + id, { method: "DELETE" });
    showToast("已删除分组");
    await loadAdminGroups();
    await refreshMe();
  } catch (e) {
    showToast("删除失败：" + e.message);
  }
}

/* ---------- 事件绑定 ---------- */
function bind() {
  $("login-form").addEventListener("submit", doLogin);
  $("logout-btn").addEventListener("click", doLogout);
  $("add-btn").addEventListener("click", openAdd);
  $("search-input").addEventListener("input", renderTable);
  // 页签切换
  document.querySelectorAll(".tab").forEach((b) =>
    b.addEventListener("click", () => switchTab(b.dataset.tab))
  );
  $("form-cancel").addEventListener("click", closeForm);
  $("form-save").addEventListener("click", saveForm);
  $("f-reveal").addEventListener("click", () => {
    const inp = $("f-secret");
    if (inp.type === "password") { inp.type = "text"; $("f-reveal").textContent = "隐藏"; }
    else { inp.type = "password"; $("f-reveal").textContent = "显示"; }
  });
  $("f-gen").addEventListener("click", genRandom);
  $("f-algorithm").addEventListener("change", applyAlgoUI);
  $("f-group").addEventListener("change", () => {
    if ($("f-algorithm").value !== "symmetric") loadOrgkeysForSelect();
  });
  $("view-close").addEventListener("click", () => $("view-modal").classList.add("hidden"));
  $("view-unlock").addEventListener("click", viewUnlock);
  $("view-entry-password").addEventListener("keydown", (e) => { if (e.key === "Enter") viewUnlock(); });
  $("view-copy").addEventListener("click", copySecret);
  $("history-close").addEventListener("click", () => $("history-modal").classList.add("hidden"));

  $("pw-tbody").addEventListener("click", (ev) => {
    const btn = ev.target.closest("button[data-act]");
    if (!btn) return;
    const id = Number(btn.dataset.id);
    const act = btn.dataset.act;
    if (act === "view") openView(id);
    else if (act === "edit") openEdit(id);
    else if (act === "hist") openHistory(id);
    else if (act === "del") doDelete(id);
  });
  // 行内勾选框（批量导出）
  $("pw-tbody").addEventListener("change", onRowSelect);
  // 工具栏「全选」
  $("select-all").addEventListener("change", onSelectAll);

  // 新增 / 编辑：解密密码明文显示切换
  $("f-entry-reveal").addEventListener("click", () => {
    const inp = $("f-entry-password");
    if (inp.type === "password") { inp.type = "text"; $("f-entry-reveal").textContent = "隐藏"; }
    else { inp.type = "password"; $("f-entry-reveal").textContent = "显示"; }
  });
  // 编辑解锁：输入当前解密密码后才能编辑
  $("form-unlock").addEventListener("click", unlockEdit);
  $("form-lock-password").addEventListener("keydown", (e) => { if (e.key === "Enter") unlockEdit(); });

  // 批量导出
  $("export-btn").addEventListener("click", openExport);
  $("export-cancel").addEventListener("click", () => $("export-modal").classList.add("hidden"));
  $("export-go").addEventListener("click", doExport);
  // 「统一密码」变化时，把仍为空的逐项密码框填上（用户体验更顺）
  $("export-master-pw").addEventListener("input", syncMasterToPerRow);

  // 批量导入密码
  $("import-btn").addEventListener("click", openImport);
  $("pw-import-cancel").addEventListener("click", closeImport);
  $("pw-import-go").addEventListener("click", doPasswordImport);
  $("pw-import-file").addEventListener("change", onImportFileChange);
  $("pw-import-algorithm").addEventListener("change", pwImportAlgoChange);
  $("pw-import-pw-reveal").addEventListener("click", pwImportPwReveal);
  $("pw-import-tpl-xlsx").addEventListener("click", () => downloadPasswordTemplate("xlsx"));
  $("pw-import-tpl-csv").addEventListener("click", () => downloadPasswordTemplate("csv"));

  // 系统管理
  $("admin-btn").addEventListener("click", openAdmin);
  $("admin-close").addEventListener("click", () => {
    $("admin-modal").classList.add("hidden");
    loadEntries();
  });
  document.querySelectorAll(".subtab").forEach((b) =>
    b.addEventListener("click", () => switchSub(b.dataset.sub))
  );
  // 审计日志：类型筛选（全部 / 新增 / 修改 / 删除）
  document.querySelectorAll("#audit-filter .seg").forEach((b) =>
    b.addEventListener("click", () => {
      document.querySelectorAll("#audit-filter .seg").forEach((x) => x.classList.toggle("active", x === b));
      auditFilter = b.dataset.act;
      loadAdminAudit();
    })
  );
  // 删除两步确认
  $("del-confirm-cancel").addEventListener("click", cancelDel);
  $("del-confirm-go").addEventListener("click", showDelTypeStep);
  $("del-type-cancel").addEventListener("click", cancelDel);
  $("del-type-confirm").addEventListener("click", confirmDelTyped);
  $("del-type-input").addEventListener("input", onDelTypeInput);
  $("del-type-input").addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !$("del-type-confirm").disabled) confirmDelTyped();
  });
  $("add-user-btn").addEventListener("click", openUserAdd);
  $("add-group-btn").addEventListener("click", openGroupAdd);
  $("user-cancel").addEventListener("click", () => $("user-modal").classList.add("hidden"));
  $("user-save").addEventListener("click", saveUser);
  // 编辑用户弹窗内的「密码显示」切换
  $("u-pwd-reveal").addEventListener("click", () => {
    const inp = $("u-password");
    const show = inp.type === "password";
    inp.type = show ? "text" : "password";
    $("u-pwd-reveal").textContent = show ? "隐藏" : "显示";
  });
  $("group-cancel").addEventListener("click", () => $("group-modal").classList.add("hidden"));
  $("group-save").addEventListener("click", saveGroup);

  // 自助修改密码（所有登录用户可用）
  $("change-pw-btn").addEventListener("click", openChangePw);
  $("cpw-cancel").addEventListener("click", closeChangePw);
  $("cpw-save").addEventListener("click", doChangePw);
  $("cpw-current-reveal").addEventListener("click", () => {
    const inp = $("cpw-current");
    const show = inp.type === "password";
    inp.type = show ? "text" : "password";
    $("cpw-current-reveal").textContent = show ? "隐藏" : "显示";
  });
  $("cpw-new-reveal").addEventListener("click", () => {
    const inp = $("cpw-new");
    const show = inp.type === "password";
    inp.type = show ? "text" : "password";
    $("cpw-new-reveal").textContent = show ? "隐藏" : "显示";
  });

  // 批量新增用户（点「批量新增」按钮 → 弹窗 → 选文件 → 点「开始导入」）
  $("batch-user-btn").addEventListener("click", openUserBatch);
  $("user-batch-cancel").addEventListener("click", closeUserBatch);
  $("user-batch-go").addEventListener("click", doUserBatchUpload);
  $("user-batch-file").addEventListener("change", (ev) => {
    $("user-batch-go").disabled = !(ev.target.files && ev.target.files.length > 0);
    // 重置之前的回执，避免重复显示上一份的结果
    $("user-batch-summary").classList.add("hidden");
    $("user-batch-results").classList.add("hidden");
    $("user-batch-results").innerHTML = "";
    $("user-batch-error").textContent = "";
  });
  // 模板下载：用 fetch + blob 把后端响应落盘（保留 Bearer token），并指定浏览器默认文件名
  $("user-batch-tpl-xlsx").addEventListener("click", () => downloadUserTemplate("xlsx"));
  $("user-batch-tpl-csv").addEventListener("click", () => downloadUserTemplate("csv"));

  // 密钥库
  $("key-gen-btn").addEventListener("click", openKeyGen);
  $("kg-cancel").addEventListener("click", closeKeyGen);
  $("kg-save").addEventListener("click", saveKeyGen);
  $("key-import-btn").addEventListener("click", openKeyImport);
  $("ki-cancel").addEventListener("click", closeKeyImport);
  $("ki-save").addEventListener("click", saveKeyImport);
  // 导入密钥的「私钥口令」只在 GPG + 用户填了私钥时才出现；监听私钥框 / 算法切换
  $("ki-algorithm").addEventListener("change", () => applyImportPassphraseUI($("ki-algorithm").value));
  $("ki-priv").addEventListener("input", () => applyImportPassphraseUI($("ki-algorithm").value));
  $("ki-passphrase-reveal").addEventListener("click", () => {
    const inp = $("ki-passphrase");
    const show = inp.type === "password";
    inp.type = show ? "text" : "password";
    $("ki-passphrase-reveal").textContent = show ? "隐藏" : "显示";
  });
  $("key-group-filter").addEventListener("change", renderKeyTable);
  $("key-search").addEventListener("input", renderKeyTable);
  $("key-tbody").addEventListener("click", (ev) => {
    const btn = ev.target.closest("button[data-kact]");
    if (!btn) return;
    const id = Number(btn.dataset.id);
    const act = btn.dataset.kact;
    if (act === "pub") exportOrgKey(id, "public");
    else if (act === "priv") exportOrgKey(id, "private");
    else if (act === "del") deleteOrgKey(id);
  });
  $("admin-users-tbody").addEventListener("click", (ev) => {
    const btn = ev.target.closest("button[data-uact]");
    if (!btn) return;
    const id = Number(btn.dataset.id);
    if (btn.dataset.uact === "edit") openUserEdit(id);
    else if (btn.dataset.uact === "del") deleteUser(id);
  });
  $("admin-groups-tbody").addEventListener("click", (ev) => {
    const btn = ev.target.closest("button[data-gact]");
    if (!btn) return;
    const id = Number(btn.dataset.id);
    if (btn.dataset.gact === "edit") openGroupEdit(id);
    else if (btn.dataset.gact === "del") deleteGroup(id);
  });
}

async function downloadUserTemplate(fmt) {
  try {
    const resp = await fetch(`/api/admin/users/template?fmt=${fmt}`, {
      headers: { Authorization: "Bearer " + state.token },
    });
    if (!resp.ok) throw new Error("模板下载失败 (" + resp.status + ")");
    const blob = await resp.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `用户批量导入模板.${fmt}`;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { document.body.removeChild(a); URL.revokeObjectURL(url); }, 100);
  } catch (e) {
    showError(e.message || "下载模板失败");
  }
}

/* ---------- 批量新增用户 ---------- */
function openUserBatch() {
  $("user-batch-file").value = "";     // 重置文件选择器，确保重复上传同一文件时能触发 change
  $("user-batch-summary").classList.add("hidden");
  $("user-batch-results").classList.add("hidden");
  $("user-batch-results").innerHTML = "";
  $("user-batch-error").textContent = "";
  $("user-batch-go").disabled = true;
  $("user-batch-modal").classList.remove("hidden");
}

function closeUserBatch() { $("user-batch-modal").classList.add("hidden"); }

async function doUserBatchUpload() {
  const f = $("user-batch-file").files[0];
  if (!f) {
    $("user-batch-error").textContent = "请先选择一个 .xlsx 或 .csv 文件";
    return;
  }
  $("user-batch-error").textContent = "";
  showWait("正在解析并批量新增用户…");
  try {
    const fd = new FormData();
    fd.append("file", f, f.name);
    const resp = await fetch("/api/admin/users/batch", {
      method: "POST",
      headers: { Authorization: "Bearer " + state.token },
      body: fd,
    });
    let body = null;
    try { body = await resp.json(); } catch (_) { /* not json */ }
    if (!resp.ok) {
      throw new Error((body && (body.detail || body.message)) || ("上传失败 (" + resp.status + ")"));
    }
    renderUserBatchResult(body || {});
    if (body && (body.created || body.errored)) {
      loadAdminUsers().catch(() => {});
    }
  } catch (e) {
    $("user-batch-error").textContent = e.message || String(e);
    showError($("user-batch-error").textContent);
  } finally {
    hideWait();
  }
}

function renderUserBatchResult(data) {
  // 摘要
  $("user-batch-total").textContent = data.total || 0;
  $("user-batch-created").textContent = data.created || 0;
  $("user-batch-skipped").textContent = data.skipped || 0;
  $("user-batch-errored").textContent = data.errored || 0;
  $("user-batch-summary").classList.remove("hidden");

  // 详细回执表
  const rows = (data.rows || []).map((r) => {
    const cls = r.status === "created" ? "exp-pill-ok"
                : r.status === "skipped" ? "exp-pill-warn"
                : "exp-pill-err";
    const label = r.status === "created" ? "✓ 成功"
                : r.status === "skipped" ? "⚠ 跳过"
                : "✗ 失败";
    return `<tr>
      <td style="padding:4px 8px;color:#6b7280">${r.row}</td>
      <td style="padding:4px 8px"><code>${esc(r.username || "(空)")}</code></td>
      <td style="padding:4px 8px"><span class="exp-pill ${cls}">${label}</span></td>
      <td style="padding:4px 8px;color:#4b5563">${esc(r.message || "")}</td>
    </tr>`;
  }).join("");
  const table = `<table style="width:100%;border-collapse:collapse;font-size:13px">
    <thead><tr style="background:#f9fafb;color:#6b7280">
      <th style="padding:6px 8px;text-align:left;width:48px">行</th>
      <th style="padding:6px 8px;text-align:left">用户名</th>
      <th style="padding:6px 8px;text-align:left;width:88px">状态</th>
      <th style="padding:6px 8px;text-align:left">说明</th>
    </tr></thead>
    <tbody>${rows || '<tr><td colspan="4" style="padding:12px;text-align:center;color:#9ca3af">没有可显示的行</td></tr>'}</tbody>
  </table>`;
  $("user-batch-results").innerHTML = table;
  $("user-batch-results").classList.remove("hidden");
}

/* ---------- 启动 ---------- */
bind();
if (state.token) {
  loadMe().then((ok) => {
    if (ok) enterApp();
    else { $("login-view").classList.remove("hidden"); }
  });
} else {
  $("login-view").classList.remove("hidden");
}
