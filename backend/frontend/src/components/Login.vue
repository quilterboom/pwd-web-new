<script setup>
import { ref, onMounted } from 'vue'
import { doLogin, showToast } from '../store'
import { register as apiRegister, registerStatus } from '../api/auth'

const emit = defineEmits(['logged-in'])

const mode = ref('login') // 'login' | 'register'
// 是否开放自助注册（由后端公开端点探测；默认 false，防误展示一个必然 403 的入口）
const allowRegister = ref(false)

// 登录字段
const username = ref('')
const password = ref('')
// 注册字段
const regUsername = ref('')
const regPassword = ref('')
const regConfirm = ref('')

const error = ref('')
const loading = ref(false)

// 登录页加载即查询注册开关，决定「注册」入口是否展示
onMounted(async () => {
  try {
    const r = await registerStatus()
    allowRegister.value = !!r.allow_registration
  } catch {
    allowRegister.value = false
  }
})

async function onSubmit() {
  error.value = ''
  if (mode.value === 'login') {
    if (!username.value.trim() || !password.value) {
      error.value = '请输入用户名和密码'
      return
    }
    loading.value = true
    try {
      await doLogin(username.value.trim(), password.value)
      emit('logged-in')
    } catch (err) {
      error.value = err.message || '登录失败'
    } finally {
      loading.value = false
    }
  } else {
    await onRegister()
  }
}

async function onRegister() {
  error.value = ''
  const u = regUsername.value.trim()
  const p = regPassword.value
  if (!u || !p) {
    error.value = '请输入用户名和密码'
    return
  }
  if (p !== regConfirm.value) {
    error.value = '两次输入的密码不一致'
    return
  }
  loading.value = true
  try {
    const r = await apiRegister(u, p)
    showToast(r.message || '注册成功，请登录')
    // 回到登录并预填用户名，方便直接登录
    mode.value = 'login'
    username.value = u
    regUsername.value = ''
    regPassword.value = ''
    regConfirm.value = ''
  } catch (err) {
    error.value = err.message || '注册失败'
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <div class="login-wrap">
    <form class="card login-card" @submit.prevent="onSubmit">
      <h1>🔐 密码管理</h1>
      <p class="subtitle">服务端 GPG / SM2 加解密密码管理器</p>

      <template v-if="mode === 'login'">
        <label>用户名</label>
        <input v-model="username" type="text" autocomplete="username" required />
        <label>密码</label>
        <input v-model="password" type="password" autocomplete="current-password" required />
        <button type="submit" class="btn primary" :disabled="loading">登录</button>
        <div class="switch-row" v-if="allowRegister">
          <span>还没有账号？</span>
          <a href="#" @click.prevent="mode = 'register'">注册</a>
        </div>
      </template>

      <template v-else>
        <h2 class="form-title">注册新账号</h2>
        <label>用户名</label>
        <input v-model="regUsername" type="text" autocomplete="username" required />
        <label>密码（至少 8 位）</label>
        <input v-model="regPassword" type="password" autocomplete="new-password" required />
        <label>确认密码</label>
        <input v-model="regConfirm" type="password" autocomplete="new-password" required />
        <button type="submit" class="btn primary" :disabled="loading">注册</button>
        <div class="switch-row">
          <span>已有账号？</span>
          <a href="#" @click.prevent="mode = 'login'">去登录</a>
        </div>
      </template>

      <div v-if="error" class="error">{{ error }}</div>
    </form>
  </div>
</template>

<style scoped>
.switch-row {
  margin-top: 14px;
  text-align: center;
  font-size: 13px;
  color: #6b7280;
}
.switch-row a {
  color: #2563eb;
  text-decoration: none;
  font-weight: 600;
  margin-left: 4px;
}
.switch-row a:hover {
  text-decoration: underline;
}
.form-title {
  margin: 0 0 6px;
  font-size: 18px;
  font-weight: 600;
}
</style>
