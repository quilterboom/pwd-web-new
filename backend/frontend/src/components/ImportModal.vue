<script setup>
import { onMounted, ref } from 'vue'
import { state, api, showWait, hideWait, showToast, showError } from '../store'
import { algoText } from '../utils'

const emit = defineEmits(['close', 'imported'])

const fileEl = ref(null)
const fileName = ref('')
const algorithm = ref('symmetric')
const entryPw = ref('')
const showEntry = ref(false)
const orgkeyOptions = ref([])
const orgkeyId = ref('')
const error = ref('')
const summary = ref(null)
const results = ref([])
const canGo = ref(false)

onMounted(() => loadOrgkeys())

async function loadOrgkeys() {
  orgkeyOptions.value = []
  orgkeyId.value = ''
  if (algorithm.value === 'symmetric') return
  try {
    const rows = await api(`/api/orgkeys?algorithm=${algorithm.value}`)
    orgkeyOptions.value = rows
  } catch (e) {
    orgkeyOptions.value = []
  }
}

function onAlgoChange() {
  loadOrgkeys()
}
function toggleEntry() {
  showEntry.value = !showEntry.value
}
function onFileChange(e) {
  const f = e.target.files && e.target.files[0]
  fileName.value = f ? f.name : ''
  canGo.value = !!(f && f.name.toLowerCase().endsWith('.xlsx'))
  summary.value = null
  results.value = []
  error.value = ''
}

async function downloadTemplate() {
  try {
    const resp = await fetch('/api/passwords/template?fmt=xlsx', {
      headers: { Authorization: 'Bearer ' + state.token },
    })
    if (!resp.ok) throw new Error('模板下载失败 (' + resp.status + ')')
    const blob = await resp.blob()
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = '密码批量导入模板.xlsx'
    document.body.appendChild(a)
    a.click()
    a.remove()
    setTimeout(() => URL.revokeObjectURL(url), 1000)
  } catch (e) {
    showError('模板下载失败：' + e.message)
  }
}

async function doImport() {
  const f = fileEl.value && fileEl.value.files[0]
  if (!f) {
    error.value = '请先选择要导入的文件'
    return
  }
  if (!f.name.toLowerCase().endsWith('.xlsx')) {
    error.value = '仅支持 .xlsx（Excel）文件'
    return
  }
  if (!entryPw.value) {
    error.value = '请先填写「加密密码（解密密码）」'
    return
  }
  const fd = new FormData()
  fd.append('file', f)
  fd.append('algorithm', algorithm.value)
  fd.append('entry_password', entryPw.value)
  if (orgkeyId.value) fd.append('orgkey_id', String(orgkeyId.value))

  error.value = ''
  showWait('正在导入…')
  try {
    const res = await fetch('/api/passwords/import', {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + state.token },
      body: fd,
    })
    const data = await res.json().catch(() => null)
    if (!res.ok) {
      const msg = (data && (data.detail || data.message)) || '导入失败 (' + res.status + ')'
      throw new Error(typeof msg === 'string' ? msg : JSON.stringify(msg))
    }
    summary.value = data
    results.value = data.rows || []
    showToast(`导入完成：成功 ${data.created}，失败 ${data.errored}，跳过 ${data.skipped}`)
    emit('imported')
  } catch (e) {
    error.value = e.message
  } finally {
    hideWait()
  }
}
</script>

<template>
  <div class="modal">
    <div class="modal-card modal-card-wide">
      <button class="modal-close" type="button" aria-label="关闭" title="关闭" @click="emit('close')">✕</button>
      <div class="modal-head">
        <h2>📥 批量导入密码</h2>
        <p class="modal-sub">下载模板 → 填写后上传；加密方式 / 加密密码 / 密钥在本页统一选择，对所有行生效。</p>
      </div>

      <div class="exp-section">
        <div class="exp-section-title">1. 下载导入模板</div>
        <button type="button" class="seg-link" @click="downloadTemplate">📄 Excel 模板</button>
      </div>

      <div class="exp-section">
        <div class="exp-section-title">2. 选择文件（仅支持 .xlsx）</div>
        <input ref="fileEl" type="file" accept=".xlsx" @change="onFileChange" />
      </div>

      <div class="exp-section">
        <div class="exp-section-title">3. 统一加密设置（对本次导入的所有行生效）</div>
        <label>加密方式 *</label>
        <select v-model="algorithm" @change="onAlgoChange">
          <option value="symmetric">对称加密（条目密码，零知识）</option>
          <option value="gpg">GPG 加密</option>
          <option value="sm2">SM2 加密（国密）</option>
        </select>
        <label>加密密码（解密密码） * <span class="hint">用于解锁本批导入的条目，并非「密码明文」本身</span></label>
        <div class="secret-row">
          <input v-model="entryPw" :type="showEntry ? 'text' : 'password'" autocomplete="new-password" />
          <button type="button" class="btn ghost small" @click="toggleEntry">显示</button>
        </div>
        <label v-if="algorithm !== 'symmetric'">
          加密密钥（仅 gpg / sm2；留空则用服务端默认密钥）
          <span class="hint">所选密钥的分组须与每一行「所属分组」一致，否则该行报错</span>
        </label>
        <select v-if="algorithm !== 'symmetric'" v-model="orgkeyId">
          <option value="">（默认：服务端密钥）</option>
          <option v-for="k in orgkeyOptions" :key="k.id" :value="k.id">
            {{ k.name }} · {{ k.group_name || '' }} {{ k.has_private ? '（含私钥）' : '（仅公钥）' }}
          </option>
        </select>
      </div>

      <div v-if="error" class="error">{{ error }}</div>

      <div v-if="summary" class="exp-summary">
        <div class="exp-summary-num"><b>{{ summary.total }}</b></div>
        <div class="exp-summary-label">已处理行数</div>
        <div class="exp-summary-meta">
          <span class="exp-pill exp-pill-ok">✓ 成功 <b>{{ summary.created }}</b></span>
          <span class="exp-pill exp-pill-warn">⚠ 跳过 <b>{{ summary.skipped }}</b></span>
          <span class="exp-pill exp-pill-err">✗ 失败 <b>{{ summary.errored }}</b></span>
        </div>
      </div>
      <div v-if="results.length" class="exp-list">
        <div v-for="r in results" :key="r.row" class="exp-row">
          <div class="exp-row-info">
            <div class="exp-row-name">第 {{ r.row }} 行 · {{ r.username || '(空)' }}</div>
            <div class="exp-row-algo">{{ r.message || '' }}</div>
          </div>
          <span class="exp-pill" :class="r.status === 'created' ? 'exp-pill-ok' : (r.status === 'skipped' ? 'exp-pill-warn' : 'exp-pill-err')">
            {{ r.status === 'created' ? '成功' : (r.status === 'skipped' ? '跳过' : '失败') }}
          </span>
        </div>
      </div>

      <div class="modal-actions">
        <button class="btn ghost" @click="emit('close')">取消</button>
        <button class="btn primary" :disabled="!canGo" @click="doImport">📥 开始导入</button>
      </div>
    </div>
  </div>
</template>
