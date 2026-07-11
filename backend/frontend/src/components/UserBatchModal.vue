<script setup>
import { ref } from 'vue'
import { state, showWait, hideWait, showToast, showError } from '../store'

const emit = defineEmits(['close', 'imported'])

const fileEl = ref(null)
const canGo = ref(false)
const error = ref('')
const summary = ref(null)
const results = ref([])
const groupIds = ref([])

function onFileChange(e) {
  const f = e.target.files && e.target.files[0]
  canGo.value = !!(f && f.name.toLowerCase().endsWith('.xlsx'))
  summary.value = null
  results.value = []
  error.value = ''
}

async function downloadTemplate() {
  try {
    const resp = await fetch(`/api/admin/users/template`, {
      headers: { Authorization: 'Bearer ' + state.token },
    })
    if (!resp.ok) throw new Error('模板下载失败 (' + resp.status + ')')
    const blob = await resp.blob()
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `用户批量导入模板.xlsx`
    document.body.appendChild(a)
    a.click()
    a.remove()
    setTimeout(() => URL.revokeObjectURL(url), 1000)
  } catch (e) {
    showError(e.message || '下载模板失败')
  }
}

async function upload() {
  const f = fileEl.value && fileEl.value.files[0]
  if (!f) {
    error.value = '请先选择一个 .xlsx 文件'
    return
  }
  error.value = ''
  showWait('正在解析并批量新增用户…')
  try {
    const fd = new FormData()
    fd.append('file', f, f.name)
    for (const gid of groupIds.value) fd.append('group_ids', String(gid))
    const resp = await fetch('/api/admin/users/batch', {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + state.token },
      body: fd,
    })
    let body = null
    try {
      body = await resp.json()
    } catch (_) {}
    if (!resp.ok) {
      throw new Error((body && (body.detail || body.message)) || '上传失败 (' + resp.status + ')')
    }
    summary.value = body || {}
    results.value = (body && body.rows) || []
    if (body && (body.created || body.errored)) emit('imported')
  } catch (e) {
    error.value = e.message || String(e)
    showError(error.value)
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
        <h2>📥 批量新增用户</h2>
        <p class="modal-sub">下载 Excel 模板 → 填写后上传，支持部分失败回执。</p>
      </div>
      <div class="exp-section">
        <div class="exp-section-title">下载模板</div>
        <button type="button" class="seg-link" @click="downloadTemplate()">📄 Excel (.xlsx)</button>
        <div class="hint" style="margin-top:8px;color:#6b7280;font-size:12px;line-height:1.6">
          模板内含「用户名 / 密码 / 是否管理员」三列；所属分组请在下方页面选择，无需在模板填写。示例可保留也可整行删除。
        </div>
      </div>
      <div class="exp-section">
        <div class="exp-section-title">上传文件</div>
        <input ref="fileEl" type="file" accept=".xlsx" @change="onFileChange" />
      </div>

      <div class="exp-section">
        <div class="exp-section-title">选择所属分组（可多选，留空表示不绑定任何分组）</div>
        <div style="display:flex;flex-wrap:wrap;gap:8px 16px;margin-top:6px">
          <label v-for="g in state.groups" :key="g.id" style="display:flex;align-items:center;gap:6px;font-size:13px">
            <input type="checkbox" :value="g.id" v-model="groupIds" /> {{ g.name }}
          </label>
        </div>
      </div>

      <div v-if="summary" class="exp-summary">
        <div class="exp-summary-num"><b>{{ summary.total || 0 }}</b></div>
        <div class="exp-summary-label">已处理行数</div>
        <div class="exp-summary-meta">
          <span class="exp-pill exp-pill-ok">✓ 成功 <b>{{ summary.created || 0 }}</b></span>
          <span class="exp-pill exp-pill-warn">⚠ 跳过 <b>{{ summary.skipped || 0 }}</b></span>
          <span class="exp-pill exp-pill-err">✗ 失败 <b>{{ summary.errored || 0 }}</b></span>
        </div>
      </div>
      <div v-if="results.length" style="max-height:240px;overflow:auto;border:1px solid #e5e7eb;border-radius:6px">
        <table style="width:100%;border-collapse:collapse;font-size:13px">
          <thead>
            <tr style="background:#f9fafb;color:#6b7280">
              <th style="padding:6px 8px;text-align:left;width:48px">行</th>
              <th style="padding:6px 8px;text-align:left">用户名</th>
              <th style="padding:6px 8px;text-align:left;width:88px">状态</th>
              <th style="padding:6px 8px;text-align:left">说明</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="r in results" :key="r.row">
              <td style="padding:4px 8px;color:#6b7280">{{ r.row }}</td>
              <td style="padding:4px 8px"><code>{{ r.username || '(空)' }}</code></td>
              <td style="padding:4px 8px">
                <span class="exp-pill" :class="r.status === 'created' ? 'exp-pill-ok' : (r.status === 'skipped' ? 'exp-pill-warn' : 'exp-pill-err')">
                  {{ r.status === 'created' ? '✓ 成功' : (r.status === 'skipped' ? '⚠ 跳过' : '✗ 失败') }}
                </span>
              </td>
              <td style="padding:4px 8px;color:#4b5563">{{ r.message || '' }}</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div v-if="error" class="error">{{ error }}</div>
      <div class="modal-actions">
        <button class="btn ghost" @click="emit('close')">关闭</button>
        <button class="btn primary" :disabled="!canGo" @click="upload">开始导入</button>
      </div>
    </div>
  </div>
</template>
