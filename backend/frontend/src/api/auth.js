import { api } from './http'
import { scramProof } from '../crypto/sm3'

// 登录：优先走 SCRAM-SM3 挑战-响应（密码不以明文传输）。
// 对历史未迁移账号，后端 /login/begin 返回 409，此时回退到明文 /login 完成一次性迁移。
export async function login(username, password) {
  try {
    const chal = await api('/api/auth/login/begin', {
      method: 'POST',
      body: JSON.stringify({ username }),
    })
    const proof = scramProof(password, chal.salt, chal.nonce)
    const data = await api('/api/auth/login/verify', {
      method: 'POST',
      body: JSON.stringify({ username, nonce: chal.nonce, proof }),
    })
    return data.access_token
  } catch (err) {
    if (err.status === 409 || String(err.message).includes('409')) {
      const data = await api('/api/auth/login', {
        method: 'POST',
        body: JSON.stringify({ username, password }),
      })
      return data.access_token
    }
    throw err
  }
}

export async function me() {
  return api('/api/auth/me')
}

// 自助注册：用户名 + 密码。受后端 ALLOW_REGISTRATION 开关控制（未开放返回 403）。
export async function register(username, password) {
  return api('/api/auth/register', {
    method: 'POST',
    body: JSON.stringify({ username, password }),
  })
}

// 公开：查询当前是否开放自助注册（登录页据此决定是否显示「注册」入口）。
export async function registerStatus() {
  return api('/api/auth/register/status')
}

// 授权管理：操作目录（按页面分组），供授权页渲染勾选框。
export async function permissionsCatalog() {
  return api('/api/auth/permissions/catalog')
}

// 授权管理（超管）：读取/设置/重置 指定用户的操作权限。
export async function getUserPermissions(uid) {
  return api(`/api/admin/permissions/users/${uid}`)
}
export async function setUserPermissions(uid, permissions) {
  return api(`/api/admin/permissions/users/${uid}`, {
    method: 'PUT',
    body: JSON.stringify({ permissions }),
  })
}
export async function resetUserPermissions(uid) {
  return api(`/api/admin/permissions/users/${uid}`, { method: 'DELETE' })
}

// 自助改密：SCRAM-SM3 优先，legacy 账号用 current_password 明文兜底。
export async function changePassword(current, next) {
  const begin = await api('/api/auth/change-password/begin', { method: 'POST', body: '{}' })
  let payload
  if (begin.mode === 'scram' && begin.salt && begin.nonce) {
    const proof = scramProof(current, begin.salt, begin.nonce)
    payload = { nonce: begin.nonce, proof, new_password: next }
  } else {
    payload = { current_password: current, new_password: next }
  }
  return api('/api/auth/change-password/verify', {
    method: 'POST',
    body: JSON.stringify(payload),
  })
}

// 服务端登出：吊销当前令牌对应的会话，使其立即失效（即便被截获也无法再用）。
// 空闲自动登出与手动退出都应调用，以实现「服务端强制失效」。
export async function logout() {
  try {
    await api('/api/auth/logout', { method: 'POST' })
  } catch (e) {
    // 令牌可能已失效（如空闲超时后被服务端吊销），忽略错误，本地照常清状态
  }
}
