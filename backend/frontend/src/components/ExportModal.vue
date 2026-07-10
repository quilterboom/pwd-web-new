<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { state, api, showWait, hideWait, showToast, showError } from '../store'
import { apiBlob, triggerDownload, filenameFromDisposition } from '../api/http'
import { algoText } from '../utils'

const emit = defineEmits(['close'])

const selectedEntries = computed(() =>
  state.selectedIds.map((id) => state.entries.find((e) => e.id === id)).filter(Boolean)
)
const masterPw = ref('')
const perRow = reactive({})
const error = ref('')

onMounted(() => {
  for (const e of selectedEntries.value) perRow[e.id] = ''
})

function syncMaster() {
  const m = masterPw.value
  for (const e of selectedEntries.value) {
    if (m) perRow[e.id] = m
    else perRow[e.id] = ''
  }
}

async function doExport() {
  error.value = ''
  const ids = state.selectedIds.slice()
  const passwords = {}
  for (const id of ids) passwords[id] = perRow[id] || masterPw.value
  showWait('正在导出…')
  try {
    const res = await fetch('/api/passwords/export', {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + state.token, 'Content-Type': 'application/json' },
      body: JSON.stringify({ ids, passwords, format: 'xlsx', plaintext: true }),
    })
    if (!res.ok) {
      let detail = null
      try {
        detail = await res.json()
      } catch (e) {}
      const msg = (detail && (detail.detail || detail.message)) || '导出失败 (' + res.status + ')'
      throw new Error(typeof msg === 'string' ? msg : JSON.stringify(msg))
    }
    const blob = await res.blob()
    const disp = res.headers.get('Content-Disposition')
    triggerDownload(blob, filenameFromDisposition(disp, 'password_export.xlsx'))
    showToast('已导出 ' + ids.length + ' 条')
    emit('close')
  } catch (e) {
    error.value = e.message
  } finally {
    hideWait()
  }
}
</script>

<template>
  <div class="modal" @click.self="emit('close')">
    <div class="modal-card modal-card-export">
      <div class="modal-head">
        <h2>📤 批量导出密码</h2>
        <p class="modal-sub">将所选密码以明文形式导出，请妥善保管导出文件。</p>
      </div>

      <div class="exp-summary">
        <div class="exp-summary-num"><b>{{ selectedEntries.length }}</b></div>
        <div class="exp-summary-label">已选密码条目</div>
      </div>

      <div class="exp-section">
        <div class="exp-section-title">导出格式</div>
        <p class="modal-sub">导出为 <b>Excel (.xlsx)</b> 文件。</p>
      </div>

      <div class="exp-section">
        <div class="exp-section-title">统一解密密码 <span class="hint">（可选；留空则逐项填写）</span></div>
        <input v-model="masterPw" type="password" autocomplete="off" placeholder="所有条目使用同一密码时填这里" @input="syncMaster" />
      </div>

      <div class="exp-section">
        <div class="exp-section-title">
          逐项解密密码
          <span class="hint">（每条目独立填写；留空条目将沿用上方的统一密码）</span>
        </div>
        <div class="exp-list">
          <div v-for="e in selectedEntries" :key="e.id" class="exp-row">
            <div class="exp-row-info">
              <div class="exp-row-name" :title="e.username">{{ e.username }}</div>
              <div class="exp-row-algo">{{ algoText(e.algorithm) }}</div>
            </div>
            <input type="password" v-model="perRow[e.id]" :placeholder="e.username ? '该条目解密密码' : ''" autocomplete="off" />
          </div>
        </div>
      </div>

      <div v-if="error" class="error">{{ error }}</div>
      <div class="modal-actions">
        <button class="btn ghost" @click="emit('close')">取消</button>
        <button class="btn primary" @click="doExport">📥 导出并下载</button>
      </div>
    </div>
  </div>
</template>
