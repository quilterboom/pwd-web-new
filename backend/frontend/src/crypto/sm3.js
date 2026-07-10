// SM3 哈希实现（GM/T 0003-2012），移植自原 app.js，纯函数无依赖。
// 登录 SCRAM-SM3 挑战-响应与自助改密都需要它来计算 verifier / proof。

function _rotl32(x, n) {
  x = x >>> 0
  n = n % 32
  return ((x << n) | (x >>> (32 - n))) >>> 0
}
function _sm3P0(x) {
  return (x ^ _rotl32(x, 9) ^ _rotl32(x, 17)) >>> 0
}
function _sm3P1(x) {
  return (x ^ _rotl32(x, 15) ^ _rotl32(x, 23)) >>> 0
}
function _sm3FF(j, x, y, z) {
  if (j < 16) return (x ^ y ^ z) >>> 0
  return (x & y) | (x & z) | (y & z)
}
function _sm3GG(j, x, y, z) {
  if (j < 16) return (x ^ y ^ z) >>> 0
  return (x & y | (~x >>> 0) & z) >>> 0
}
function _sm3Tj(j) {
  return j < 16 ? 0x79cc4519 : 0x7a879d8a
}

function _sm3compress(v, block) {
  const W = new Array(68)
  for (let i = 0; i < 16; i++) {
    W[i] = ((block[i * 4] << 24) | (block[i * 4 + 1] << 16) | (block[i * 4 + 2] << 8) | block[i * 4 + 3]) >>> 0
  }
  for (let i = 16; i < 68; i++) {
    W[i] = (_sm3P1(((W[i - 16] ^ W[i - 9] ^ _rotl32(W[i - 3], 15)) >>> 0)) ^ _rotl32(W[i - 13], 7) ^ W[i - 6]) >>> 0
  }
  const Wp = new Array(64)
  for (let i = 0; i < 64; i++) Wp[i] = (W[i] ^ W[i + 4]) >>> 0

  let A = v[0] >>> 0, B = v[1] >>> 0, C = v[2] >>> 0, D = v[3] >>> 0
  let E = v[4] >>> 0, F = v[5] >>> 0, G = v[6] >>> 0, H = v[7] >>> 0
  for (let j = 0; j < 64; j++) {
    const A12 = _rotl32(A, 12)
    const SS1 = _rotl32(((A12 + E + _rotl32(_sm3Tj(j), j % 32)) >>> 0), 7)
    const SS2 = (SS1 ^ A12) >>> 0
    const TT1 = (_sm3FF(j, A, B, C) + D + SS2 + Wp[j]) >>> 0
    const TT2 = (_sm3GG(j, E, F, G) + H + SS1 + W[j]) >>> 0
    D = C; C = _rotl32(B, 9); B = A; A = TT1
    H = G; G = _rotl32(F, 19); F = E; E = _sm3P0(TT2)
  }
  v[0] = (v[0] ^ A) >>> 0; v[1] = (v[1] ^ B) >>> 0
  v[2] = (v[2] ^ C) >>> 0; v[3] = (v[3] ^ D) >>> 0
  v[4] = (v[4] ^ E) >>> 0; v[5] = (v[5] ^ F) >>> 0
  v[6] = (v[6] ^ G) >>> 0; v[7] = (v[7] ^ H) >>> 0
}

const _SM3_IV = [0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e]

export function sm3Bytes(bytes) {
  const len = bytes.length
  const bufLen = (((len + 1 + 8 + 63) >> 6) << 6)
  const buf = new Uint8Array(bufLen)
  buf.set(bytes)
  buf[len] = 0x80
  let bitLen = BigInt(len) * 8n
  for (let i = 0; i < 8; i++) {
    buf[bufLen - 1 - i] = Number(bitLen & 0xffn)
    bitLen >>= 8n
  }
  const v = _SM3_IV.slice()
  for (let off = 0; off < bufLen; off += 64) {
    _sm3compress(v, buf.subarray(off, off + 64))
  }
  const out = new Uint8Array(32)
  for (let i = 0; i < 8; i++) {
    out[i * 4] = (v[i] >>> 24) & 0xff
    out[i * 4 + 1] = (v[i] >>> 16) & 0xff
    out[i * 4 + 2] = (v[i] >>> 8) & 0xff
    out[i * 4 + 3] = v[i] & 0xff
  }
  return out
}

export function sm3Hex(s) {
  const bytes = new TextEncoder().encode(s || '')
  return Array.from(sm3Bytes(bytes), (b) => b.toString(16).padStart(2, '0')).join('')
}

export function bytesToHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
}

export function hexToBytes(hex) {
  const n = (hex || '').length
  if (n % 2 !== 0) return new Uint8Array(0)
  const out = new Uint8Array(n / 2)
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substr(i * 2, 2), 16) || 0
  }
  return out
}

// SCRAM-SM3 计算：T = SM3(password || salt)；proof = SM3(T || nonce)
export function scramProof(password, saltHex, nonceHex) {
  const saltBytes = hexToBytes(saltHex)
  const nonceBytes = hexToBytes(nonceHex)
  const pwBytes = new TextEncoder().encode(password)
  const tInput = new Uint8Array(pwBytes.length + saltBytes.length)
  tInput.set(pwBytes, 0)
  tInput.set(saltBytes, pwBytes.length)
  const verifier = sm3Bytes(tInput)
  const proofInput = new Uint8Array(verifier.length + nonceBytes.length)
  proofInput.set(verifier, 0)
  proofInput.set(nonceBytes, verifier.length)
  return bytesToHex(sm3Bytes(proofInput))
}
