// 与后端通信的统一封装：自动附带 Bearer Token，JSON 解析失败也尽量抛出可读错误。
const TOKEN_KEY = 'password_manager_token'
const USER_KEY = 'password_manager_user'

export function getToken() {
  return localStorage.getItem(TOKEN_KEY) || ''
}

// 401 统一处理器：任意请求返回 401（登录超时/令牌失效）时由 store 注册此回调，
// 负责清除本地登录态并跳回登录页，避免用户手动刷新。
let unauthorizedHandler = null
export function setUnauthorizedHandler(fn) {
  unauthorizedHandler = fn
}
function fireUnauthorized() {
  if (unauthorizedHandler) unauthorizedHandler()
}
export function setToken(t) {
  if (t) localStorage.setItem(TOKEN_KEY, t)
  else localStorage.removeItem(TOKEN_KEY)
}
export function getUser() {
  return localStorage.getItem(USER_KEY) || ''
}
export function setUser(u) {
  if (u) localStorage.setItem(USER_KEY, u)
  else localStorage.removeItem(USER_KEY)
}

export async function api(path, opts = {}) {
  const headers = Object.assign({}, opts.headers || {})
  const token = getToken()
  if (token) headers['Authorization'] = 'Bearer ' + token
  if (opts.body && !(opts.body instanceof FormData)) headers['Content-Type'] = 'application/json'
  const res = await fetch(path, Object.assign({}, opts, { headers }))
  let data = null
  try {
    data = await res.json()
  } catch (e) {
    /* 空响应体或非 JSON */
  }
  if (!res.ok) {
    const msg = (data && (data.detail || data.message)) || '请求失败 (' + res.status + ')'
    const e = new Error(typeof msg === 'string' ? msg : JSON.stringify(msg))
    e.status = res.status
    if (res.status === 401) fireUnauthorized()
    throw e
  }
  return data
}

// 下载二进制（文件）：返回 { blob, disposition }，非 JSON 响应也按 Content-Type 处理，
// 避免对非 JSON body 盲目 res.json() 导致 "body stream already read"。
export async function apiBlob(path, opts = {}) {
  const headers = Object.assign({}, opts.headers || {})
  const token = getToken()
  if (token) headers['Authorization'] = 'Bearer ' + token
  const res = await fetch(path, Object.assign({}, opts, { headers }))
  const ct = (res.headers.get('Content-Type') || '').toLowerCase()
  if (!res.ok) {
    let detail = null
    if (ct.includes('json')) {
      try {
        detail = await res.json()
      } catch (e) {}
      const msg = (detail && (detail.detail || detail.message)) || '下载失败 (' + res.status + ')'
      if (res.status === 401) fireUnauthorized()
      throw new Error(typeof msg === 'string' ? msg : JSON.stringify(msg))
    }
    if (res.status === 401) fireUnauthorized()
    throw new Error('下载失败 (' + res.status + ')')
  }
  return { blob: await res.blob(), disposition: res.headers.get('Content-Disposition') }
}

export function filenameFromDisposition(disp, fallback) {
  if (!disp) return fallback
  const star = disp.match(/filename\*=UTF-8''([^;]+)/i)
  if (star) {
    try {
      return decodeURIComponent(star[1])
    } catch (e) {}
  }
  const m = disp.match(/filename="?([^";]+)"?/i)
  if (m) return m[1]
  return fallback
}

export function triggerDownload(blob, filename) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}
