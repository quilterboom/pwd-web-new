<script setup>
import { computed, ref, watch, onMounted } from 'vue'
import {
  state,
  loadOrgKeys,
  requestDelete,
  showToast,
  apiBlob,
  triggerDownload,
  filenameFromDisposition,
} from '../store'
import { api } from '../api/http'
import { algoBadge, groupName, fmtTime } from '../utils'
import KeyGenModal from './KeyGenModal.vue'
import KeyImportModal from './KeyImportModal.vue'

const groupFilter = ref('0')
const search = ref('')
const showGen = ref(false)
const showImport = ref(false)

// ── 后台分页展示（state.keys 仍保持全量，供导出 / 删除定位使用）──
const keys = ref([])
const keysTotal = ref(0)
const page = ref(1)
const pageSize = ref(10)
const pages = computed(() => Math.max(1, Math.ceil(keysTotal.value / pageSize.value)))

async function fetchKeys() {
  try {
    const qs = new URLSearchParams()
    qs.set('page', String(page.value))
    qs.set('page_size', String(pageSize.value))
    const gid = Number(groupFilter.value || 0)
    if (gid > 0) qs.set('group_id', String(gid))
    if (search.value.trim()) qs.set('q', search.value.trim())
    const resp = await api('/api/orgkeys?' + qs.toString())
    keys.value = resp.items
    keysTotal.value = resp.total
  } catch (e) {
    showToast('加载密钥库失败：' + e.message)
  }
}

function goto(delta) {
  page.value += delta
  fetchKeys()
}

// 数据变更（生成 / 导入 / 删除 / 切标签刷新全量）后刷新当前页展示
watch(
  () => state.keys,
  () => fetchKeys()
)
watch([search, groupFilter], () => {
  page.value = 1
  fetchKeys()
})
watch(pageSize, () => {
  page.value = 1
  fetchKeys()
})

onMounted(fetchKeys)

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

function onKeysSaved() {
  loadOrgKeys()
  fetchKeys()
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
        <tr v-for="k in keys" :key="k.id">
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
        <tr v-if="!keys.length && state.keys.length && groupFilter !== '0'">
          <td :colspan="state.isAdmin ? 8 : 7" style="color:#6b7280">该分组暂无密钥条目</td>
        </tr>
        <tr v-else-if="!keys.length && state.keys.length">
          <td :colspan="state.isAdmin ? 8 : 7" style="color:#6b7280">无匹配结果</td>
        </tr>
      </tbody>
    </table>

    <div class="pager" v-if="keysTotal > 0">
      <select class="pager-size" v-model="pageSize">
        <option :value="10">10 条/页</option>
        <option :value="20">20 条/页</option>
        <option :value="50">50 条/页</option>
      </select>
      <button class="btn ghost small" :disabled="page <= 1" @click="goto(-1)">‹ 上一页</button>
      <span class="pager-info">第 {{ page }} / {{ pages }} 页 · 共 {{ keysTotal }} 条</span>
      <button class="btn ghost small" :disabled="page >= pages" @click="goto(1)">下一页 ›</button>
    </div>

    <div v-if="!state.keys.length" class="empty">该分组暂无密钥条目，点击「生成密钥」或「导入密钥」开始。</div>

    <KeyGenModal v-if="showGen" @close="showGen = false" @saved="onKeysSaved" />
    <KeyImportModal v-if="showImport" @close="showImport = false" @saved="onKeysSaved" />
  </section>
</template>

<style scoped>
.pager {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-top: 14px;
  flex-wrap: wrap;
}
.pager-info {
  font-size: 13px;
  color: #6b7280;
}
.pager-size {
  padding: 5px 8px;
  border: 1px solid #d1d5db;
  border-radius: 6px;
  background: #fff;
  font-size: 13px;
  color: #111827;
}
</style>
