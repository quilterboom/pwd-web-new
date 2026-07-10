<script setup>
import { ref } from 'vue'
import { changePassword } from '../api/auth'
import { showWait, hideWait, showToast } from '../store'

const emit = defineEmits(['close'])

const current = ref('')
const next = ref('')
const confirm = ref('')
const showCur = ref(false)
const showNew = ref(false)
const error = ref('')

function toggleCur() {
  showCur.value = !showCur.value
}
function toggleNew() {
  showNew.value = !showNew.value
}

async function save() {
  error.value = ''
  if (!current.value) return (error.value = '请输入当前密码')
  if (next.value.length < 8) return (error.value = '新密码至少 8 位')
  if (next.value !== confirm.value) return (error.value = '两次输入的新密码不一致')
  showWait('正在验证并修改密码…')
  try {
    await changePassword(current.value, next.value)
    hideWait()
    emit('close')
    showToast('登录密码已修改')
  } catch (e) {
    hideWait()
    error.value = e.message || '修改失败'
  }
}
</script>

<template>
  <div class="modal">
    <div class="modal-card">
      <button class="modal-close" type="button" aria-label="关闭" title="关闭" @click="emit('close')">✕</button>
      <h2>修改登录密码</h2>
      <p class="modal-sub">为保障账户安全，请先验证当前密码，再设置新密码。</p>
      <label>当前密码 *</label>
      <div class="secret-row">
        <input v-model="current" :type="showCur ? 'text' : 'password'" autocomplete="current-password" />
        <button type="button" class="btn ghost small" @click="toggleCur">显示</button>
      </div>
      <label>新密码 * <span class="hint">至少 8 位</span></label>
      <div class="secret-row">
        <input v-model="next" :type="showNew ? 'text' : 'password'" autocomplete="new-password" />
        <button type="button" class="btn ghost small" @click="toggleNew">显示</button>
      </div>
      <label>确认新密码 *</label>
      <input v-model="confirm" type="password" autocomplete="new-password" />
      <div v-if="error" class="error">{{ error }}</div>
      <div class="modal-actions">
        <button class="btn ghost" @click="emit('close')">取消</button>
        <button class="btn primary" @click="save">保存</button>
      </div>
    </div>
  </div>
</template>
