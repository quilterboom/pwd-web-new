import { reactive } from 'vue'
import { api, getToken, setToken, setUser, getUser } from './api/http'
import { login as apiLogin, me as apiMe } from './api/auth'

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
  currentTab: 'pw', // 'pw' | 'key'
  keysStatus: '', // 服务端密钥就绪状态文本
  wait: { show: false, text: '正在处理…' },
  toast: { show: false, text: '', error: false },
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
  state.token = ''
  state.user = ''
  state.isAdmin = false
  state.isGlobalAdmin = false
  state.groups = []
  state.entries = []
  state.keys = []
  state.selectedIds = []
  setToken('')
  setUser('')
}

export async function refreshMe() {
  const m = await apiMe()
  state.user = m.username
  state.isAdmin = !!m.is_admin
  state.isGlobalAdmin = !!m.is_global_admin
  state.groups = m.groups || []
  setUser(m.username)
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

/* ---------- 删除两步确认 ---------- */
export function requestDelete(type, id, name) {
  state.deleteTarget = { type, id, name }
}
export function closeDelete() {
  state.deleteTarget = null
}
export async function confirmDelete() {
  const t = state.deleteTarget
  if (!t) return
  state.deleteTarget = null
  try {
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
