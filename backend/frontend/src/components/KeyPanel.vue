<script setup>
import { computed, ref } from 'vue'
import { state, loadOrgKeys, requestDelete, showToast, showError, apiBlob, triggerDownload, filenameFromDisposition } from '../store'
import { algoBadge, groupName, fmtTime } from '../utils'
import KeyGenModal from './KeyGenModal.vue'
import KeyImportModal from './KeyImportModal.vue'

const groupFilter = ref('0')
const search = ref('')
const showGen = ref(false)
const showImport = ref(false)

const filtered = computed(() => {
  let rows = state.keys
  const gid = Number(groupFilter.value || 0)
  if (gid > 0) rows = rows.filter((k) => k.group_id === gid)
  const q = search.value.trim().toLowerCase()
  if (q) rows = rows.filter((k) => (k.name + ' ' + (k.created_by || '')).toLowerCase().includes(q))
  return rows
})

async function exportKey(id, kind) {
  const entry = state.keys.find((k) => k.id === id)
  const defaultName = entry ? entry.name : 'key'
  try {
    const { blob, disposition } = await apiBlob('/api/orgkeys/' + id + '/export?kind=' + kind)
    const suffix = kind === 'public' ? '_pub' : '_priv'
    const ext = entry && entry.algorithm === 'gpg' ? '.asc' : '.key'
    triggerDownload(blob, filenameFromDisposition(disposition, defaultName + suffix + ext))
    showToast(kind === 'public' ? '公钥已导出' : '⚠ 私钥已导出，请妥善保管')
  } catch (e) {
    showToast('导出失败：' + e.message)
  }
}

function onDelete(id) {
  const k = state.keys.find((x) => x.id === id)
  requestDelete('key', id, k ? k.name : '#' + id)
}
</script>

<template>
  <section>
    <div class="section-hint">
      <div class="hint-title">🔐 组织密钥库</div>
      <div class="hint-body">
        按分组保存多对命名密钥（<b>公钥必填</b>，私钥可选）。
        用于在团队/部门内部分发加密公钥，或导入外部公钥做共享加密。<b>导出私钥请谨慎分享</b>。
      </div>
    </div>

    <div class="toolbar key-toolbar">
      <div class="toolbar-group">
        <label class="inline-label" for="key-group-filter">所属分组</label>
        <select id="key-group-filter" v-model="groupFilter">
          <option value="0">全部分组</option>
          <option v-for="g in state.groups" :key="g.id" :value="String(g.id)">{{ g.name }}</option>
        </select>
      </div>
      <div class="toolbar-group flex-grow">
        <input v-model="search" type="text" placeholder="搜索密钥名 / 创建人…" />
      </div>
      <div class="toolbar-group toolbar-actions">
        <button class="btn ghost" title="导入外部密钥（PEM / armored）" @click="showImport = true">📥 导入</button>
        <button class="btn primary" title="生成新的 GPG / SM2 密钥对" @click="showGen = true">🛠 生成</button>
      </div>
    </div>

    <table class="pw-table">
      <thead>
        <tr>
          <th>名称</th><th>算法</th><th>分组</th><th>指纹</th><th>私钥</th><th>创建时间</th><th>创建人</th><th v-if="state.isAdmin">操作</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="k in filtered" :key="k.id">
          <td>{{ k.name }}</td>
          <td><span class="badge" :class="algoBadge(k.algorithm).cls">{{ algoBadge(k.algorithm).label }}</span></td>
          <td>{{ groupName(state.groups, k.group_id) }}</td>
          <td><code style="font-size:11px">{{ k.fingerprint }}</code></td>
          <td>{{ k.has_private ? '✓ 有' : '— 无' }}</td>
          <td>{{ fmtTime(k.created_at) }}</td>
          <td>{{ k.created_by || '' }}</td>
          <td v-if="state.isAdmin">
            <div class="ops">
              <button class="btn ghost small" @click="exportKey(k.id, 'public')">导出公钥</button>
              <button v-if="k.has_private" class="btn ghost small" @click="exportKey(k.id, 'private')">导出私钥</button>
              <button class="btn danger small" @click="onDelete(k.id)">删除</button>
            </div>
          </td>
        </tr>
        <tr v-if="!filtered.length && state.keys.length">
          <td :colspan="state.isAdmin ? 8 : 7" style="color:#6b7280">无匹配结果</td>
        </tr>
      </tbody>
    </table>
    <div v-if="!state.keys.length" class="empty">该分组暂无密钥条目，点击「生成密钥」或「导入密钥」开始。</div>

    <KeyGenModal v-if="showGen" @close="showGen = false" @saved="loadOrgKeys" />
    <KeyImportModal v-if="showImport" @close="showImport = false" @saved="loadOrgKeys" />
  </section>
</template>
