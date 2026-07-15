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
