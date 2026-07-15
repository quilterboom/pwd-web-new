import { reactive } from 'vue'
import { api, getToken, setToken, setUser, getUser } from './api/http'
import { login as apiLogin, me as apiMe, logout as apiLogout } from './api/auth'

// 便于组件从 store 统一引用这些 HTTP 辅助函数
export { api, apiBlob, triggerDownload, filenameFromDisposition } from './api/http'

export const state = reactive({
  token: getToken(),
  user: getUser(),
  isAdmin: false,
  isGlobalAdmin: false, // 是否超级管理员（is_admin 且未限定管理分组）；分组管理员为 false
  groups: [], // 当前用户可见分组
  users: [], // 管理员视角下的全部用户
  entries: [], // 密码列表
  keys: [], // 组织密钥库
  selectedIds: [], // 批量导出已勾选的密码 id
  selectedKeyIds: [], // 密钥库批量操作已勾选的密钥 id（与密码勾选隔离，避免跨页串号）
  currentTab: 'pw', // 'pw' | 'key'
  keysStatus: '', // 服务端密钥就绪状态文本
  wait: { show: false, text: '正在处理…' },
  toast: { show: false, text: '', error: false },
  // 当前登录用户被允许的操作 key 清单；null/undefined 表示「全部可用」（管理员或未被授权过）
  permissions: null,
  // 全局删除两步确认
  deleteTarget: null, // { type:'pw'|'key', id, name }
})

let toastTimer = null
let waitTimer = null

export function showToast(text, isError = false) {
  state.toast.text = text
  state.toast.error = !!isError
  state.toast.show = true
  clearTimeout(toastTimer)
  toastTimer = setTimeout(() => (state.toast.show = false), isError ? 5000 : 2200)
}

export function showError(text) {
  showToast('❌ ' + text, true)
}

export function showWait(text) {
  state.wait.text = text || '正在处理…'
  state.wait.show = true
  clearTimeout(waitTimer)
  waitTimer = setTimeout(() => (state.wait.show = false), 30000)
}
export function hideWait() {
  state.wait.show = false
  clearTimeout(waitTimer)
}

export function isAuthErr(e) {
  return String((e && e.message) || '').includes('401') || String((e && e.message) || '').includes('令牌')
}

export async function doLogin(username, password) {
  const token = await apiLogin(username, password)
  state.token = token
  setToken(token)
  await refreshMe()
  return token
}

export function doLogout() {
  // 先通知服务端吊销当前令牌（best-effort，失败不影响本地登出），实现服务端强制失效
  if (state.token) apiLogout()
  state.token = ''
  state.user = ''
  state.isAdmin = false
  state.isGlobalAdmin = false
  state.groups = []
  state.entries = []
  state.keys = []
  state.selectedIds = []
  state.selectedKeyIds = []
  setToken('')
  setUser('')
}

/* ---------- 空闲超时自动退出 ----------
 * 登录态下若连续 IDLE_TIMEOUT_MS（默认 1 分钟）无任何用户操作，自动取消登录状态。
 * 监听全局活动事件，任一活动即刷新倒计时；倒计时归零则清登录态并提示。
 * 仅在已登录（state.token 存在）时生效；登出后定时器与监听自动失效。
 */
const IDLE_TIMEOUT_MS = 60 * 1000 // 1 分钟无操作即登出
const IDLE_RESET_THROTTLE_MS = 3000 // 活动重置节流，避免 mousemove 高频抖动
let idleTimer = null
let idleBound = false
let lastActivityTs = 0

function triggerIdleLogout() {
  if (!state.token) return
  doLogout()
  showToast('由于 1 分钟无操作，已自动退出登录', true)
}

function resetIdleTimer() {
  if (!state.token) return
  if (idleTimer) clearTimeout(idleTimer)
  idleTimer = setTimeout(triggerIdleLogout, IDLE_TIMEOUT_MS)
}

function onActivity() {
  if (!state.token) return
  const now = Date.now()
  if (now - lastActivityTs < IDLE_RESET_THROTTLE_MS) return
  lastActivityTs = now
  resetIdleTimer()
}

export function startIdleMonitor() {
  // 幂等：只绑定一次全局监听；每次调用都会刷新倒计时（登录成功时调用以重置窗口）
  if (!idleBound) {
    idleBound = true
    for (const ev of ['mousemove', 'mousedown', 'keydown', 'touchstart', 'scroll', 'click', 'wheel']) {
      window.addEventListener(ev, onActivity, { passive: true })
    }
  }
  resetIdleTimer()
}

export async function refreshMe() {
  const m = await apiMe()
  state.user = m.username
  state.isAdmin = !!m.is_admin
  state.isGlobalAdmin = !!m.is_global_admin
  state.groups = m.groups || []
  state.permissions = m.permissions  // null=全部可用；数组=仅清单内可用
  setUser(m.username)
}

// 操作授权判断：permissions 为 null/undefined 表示全部可用；否则仅清单内可用。
// 注意：管理员在 /me 中永远返回 permissions=null（后端绕过权限限制），故管理员一律放行。
export function can(key) {
  const p = state.permissions
  if (p === null || p === undefined) return true
  return p.includes(key)
}

// 启动：若本地有 token，尝试恢复会话；失败则回登录页
export async function bootstrap() {
  if (!state.token) return false
  try {
    await refreshMe()
    return true
  } catch (e) {
    state.token = ''
    setToken('')
    return false
  }
}

export async function loadKeysStatus() {
  try {
    const s = await api('/api/keys/status')
    const gpg = s.gpg ? '<span class="ok">● GPG 就绪</span>' : '<span class="no">● GPG 缺失</span>'
    const sm2 = s.sm2 ? '<span class="ok">● SM2 就绪</span>' : '<span class="no">● SM2 缺失</span>'
    state.keysStatus = `服务端密钥：${gpg}　${sm2}`
    return s
  } catch (e) {
    state.keysStatus = '密钥状态获取失败'
    return null
  }
}

export async function loadEntries() {
  try {
    state.entries = await api('/api/passwords')
    // 清理已不存在的选中项
    state.selectedIds = state.selectedIds.filter((id) => state.entries.some((e) => e.id === id))
    return state.entries
  } catch (e) {
    if (isAuthErr(e)) doLogout()
    else showToast('加载失败：' + e.message)
  }
}

export async function loadOrgKeys() {
  try {
    state.keys = await api('/api/orgkeys')
    return state.keys
  } catch (e) {
    if (isAuthErr(e)) doLogout()
    else showToast('加载密钥库失败：' + e.message)
  }
}

/* ---------- 批量导出勾选 ---------- */
export function isSelected(id) {
  return state.selectedIds.includes(id)
}
export function toggleSelect(id) {
  const i = state.selectedIds.indexOf(id)
  if (i >= 0) state.selectedIds.splice(i, 1)
  else state.selectedIds.push(id)
}
export function setSelection(ids) {
  state.selectedIds = ids
}
export function clearSelection() {
  state.selectedIds = []
}

/* ---------- 密钥库批量勾选（与密码勾选隔离） ---------- */
export function isKeySelected(id) {
  return state.selectedKeyIds.includes(id)
}
export function toggleKeySelect(id) {
  const i = state.selectedKeyIds.indexOf(id)
  if (i >= 0) state.selectedKeyIds.splice(i, 1)
  else state.selectedKeyIds.push(id)
}
export function setKeySelection(ids) {
  state.selectedKeyIds = ids
}
export function clearKeySelection() {
  state.selectedKeyIds = []
}

/* ---------- 删除两步确认 ---------- */
export function requestDelete(type, id, name) {
  state.deleteTarget = { type, id, name }
}
// 批量删除：ids 为待删 id 数组；确认弹窗据此显示「N 个」并要求键入验证码
export function requestBatchDelete(type, ids, name) {
  state.deleteTarget = { type, ids, count: ids.length, name: name || `${ids.length} 项` }
}
export function closeDelete() {
  state.deleteTarget = null
}
export async function confirmDelete() {
  const t = state.deleteTarget
  if (!t) return
  state.deleteTarget = null
  try {
    // 批量删除分支
    if (t.ids && t.ids.length) {
      const body = JSON.stringify({ ids: t.ids })
      if (t.type === 'key') {
        const r = await api('/api/orgkeys/batch-delete', { method: 'POST', body })
        clearKeySelection()
        showToast(
          `已批量删除 ${r.deleted} 个密钥（已记入审计日志）` +
            (r.skipped ? `，${r.skipped} 个跳过` : '')
        )
        await loadOrgKeys()
      } else {
        const r = await api('/api/passwords/batch-delete', { method: 'POST', body })
        clearSelection()
        showToast(
          `已批量删除 ${r.deleted} 个密码（已记入审计日志）` +
            (r.skipped ? `，${r.skipped} 个跳过` : '')
        )
        await loadEntries()
      }
      return
    }
    if (t.type === 'key') {
      await api('/api/orgkeys/' + t.id, { method: 'DELETE' })
      showToast('已删除密钥（已记入审计日志）')
      await loadOrgKeys()
    } else {
      await api('/api/passwords/' + t.id, { method: 'DELETE' })
      showToast('已删除密码（已记入审计日志）')
      await loadEntries()
    }
  } catch (e) {
    showToast('删除失败：' + e.message)
  }
}
