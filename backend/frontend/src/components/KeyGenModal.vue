<script setup>
import { ref } from 'vue'
import { state, api, showWait, hideWait, showToast } from '../store'

const emit = defineEmits(['close', 'saved'])

const name = ref('')
const algorithm = ref('gpg')
const groupId = ref(state.groups.length ? String(state.groups[0].id) : '')
const error = ref('')

async function save() {
  error.value = ''
  if (!name.value.trim()) return (error.value = '请输入密钥名称')
  if (!groupId.value) return (error.value = '请选择所属分组')
  showWait('正在生成密钥对…')
  try {
    await api('/api/orgkeys/generate', {
      method: 'POST',
      body: JSON.stringify({ name: name.value.trim(), algorithm: algorithm.value, group_id: Number(groupId.value) }),
    })
    showToast('已生成并保存密钥对')
    emit('saved')
    emit('close')
  } catch (e) {
    error.value = e.message
  } finally {
    hideWait()
  }
}
</script>

<template>
  <div class="modal">
    <div class="modal-card">
      <button class="modal-close" type="button" aria-label="关闭" title="关闭" @click="emit('close')">✕</button>
      <h2>生成新密钥</h2>
      <label>密钥名称 *</label>
      <input v-model="name" type="text" placeholder="如：研发中心 GPG 主密钥" />
      <label>加密算法 *</label>
      <select v-model="algorithm">
        <option value="gpg">GPG (OpenPGP, RSA-2048)</option>
        <option value="sm2">SM2 (国密)</option>
      </select>
      <label>所属分组 *</label>
      <select v-model="groupId">
        <option v-if="!state.groups.length" value="">（无可用分组，请联系管理员）</option>
        <option v-for="g in state.groups" :key="g.id" :value="String(g.id)">{{ g.name }}</option>
      </select>
      <p class="hint" style="margin:8px 0 0;color:#6b7280;font-size:13px;line-height:1.6">
        生成后将同时保存<strong>公钥 + 私钥</strong>到本服务。请妥善保管，可用「导出私钥」获取完整密钥。
      </p>
      <div class="modal-actions">
        <button class="btn ghost" @click="emit('close')">取消</button>
        <button class="btn primary" @click="save">生成</button>
      </div>
      <div v-if="error" class="error">{{ error }}</div>
    </div>
  </div>
</template>
