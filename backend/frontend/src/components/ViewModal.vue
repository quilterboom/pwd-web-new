<script setup>
import { computed, onMounted, ref } from 'vue'
import { state, api, showWait, hideWait, showToast, showError } from '../store'
import { algoBadge, groupName, fmtTime } from '../utils'

const props = defineProps({ id: { type: Number, required: true } })
const emit = defineEmits(['close'])

const entry = computed(() => state.entries.find((e) => e.id === props.id))
const secret = ref('')
const locked = ref(false)
const lockError = ref('')
const lockPassword = ref('')

async function fetchSecret(pw) {
  const full = await api('/api/passwords/' + props.id + '/unlock', {
    method: 'POST',
    body: JSON.stringify({ entry_password: pw || '' }),
  })
  secret.value = full.secret
}

onMounted(async () => {
  if (!entry.value) return
  if (entry.value.needs_password) {
    locked.value = true
  } else {
    showWait('正在解密…')
    try {
      await fetchSecret('')
    } catch (e) {
      showToast('加载失败：' + e.message)
    } finally {
      hideWait()
    }
  }
})

async function viewUnlock() {
  const pw = lockPassword.value
  if (!pw) {
    lockError.value = '请输入解密密码'
    return
  }
  showWait('正在解密…')
  try {
    await fetchSecret(pw)
    locked.value = false
    lockError.value = ''
  } catch (e) {
    lockError.value = e.message
  } finally {
    hideWait()
  }
}

function copySecret() {
  navigator.clipboard.writeText(secret.value).then(
    () => showToast('已复制到剪贴板'),
    () => showToast('复制失败')
  )
}
</script>

<template>
  <div class="modal">
    <div class="modal-card">
      <button class="modal-close" type="button" aria-label="关闭" title="关闭" @click="emit('close')">✕</button>
      <h2>查看：{{ entry ? entry.username : '' }}</h2>
      <div class="kv"><span>账号</span><b>{{ entry ? entry.username : '—' }}</b></div>
      <div class="kv" v-if="entry">
        <span>加密方式</span>
        <b>
          <span class="badge" :class="algoBadge(entry.algorithm).cls">{{ algoBadge(entry.algorithm).label }}</span>
          <span v-if="entry.key_name" style="color:#6b7280;font-size:13px"> 🔑 {{ entry.key_name }}</span>
        </b>
      </div>
      <div class="kv" v-if="entry"><span>分组</span><b>{{ groupName(state.groups, entry.group_id) }}</b></div>

      <div v-if="locked" style="margin:10px 0">
        <p class="lock-hint">🔒 该密码由「解密密码」保护，输入后才能查看。</p>
        <div class="secret-row">
          <input v-model="lockPassword" type="password" placeholder="输入条目密码" @keyup.enter="viewUnlock" />
          <button class="btn primary small" @click="viewUnlock">解密查看</button>
        </div>
        <div v-if="lockError" class="error">{{ lockError }}</div>
      </div>

      <div class="kv" v-if="!locked">
        <span>密码明文</span>
        <div class="secret-box">
          <code>{{ secret }}</code>
          <button class="btn ghost small" @click="copySecret">复制</button>
        </div>
      </div>
      <div class="kv" v-if="entry"><span>备注</span><b>{{ entry.notes || '—' }}</b></div>

      <div class="modal-actions">
        <button class="btn ghost" @click="emit('close')">关闭</button>
      </div>
    </div>
  </div>
</template>
