<script setup>
import { ref } from 'vue'
import { doLogin, showToast } from '../store'

const emit = defineEmits(['logged-in'])

const username = ref('')
const password = ref('')
const error = ref('')
const loading = ref(false)

async function onSubmit() {
  error.value = ''
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
}
</script>

<template>
  <div class="login-wrap">
    <form class="card login-card" @submit.prevent="onSubmit">
      <h1>🔐 密码管理</h1>
      <p class="subtitle">服务端 GPG / SM2 加解密密码管理器</p>
      <label>用户名</label>
      <input v-model="username" type="text" autocomplete="username" required />
      <label>密码</label>
      <input v-model="password" type="password" autocomplete="current-password" required />
      <button type="submit" class="btn primary" :disabled="loading">登录</button>
      <div v-if="error" class="error">{{ error }}</div>
    </form>
  </div>
</template>
