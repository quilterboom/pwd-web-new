<script setup>
import { computed, ref } from 'vue'
import { state, isSelected, toggleSelect, setSelection, clearSelection, loadEntries, requestDelete, showToast, showError, isAuthErr } from '../store'
import { api } from '../api/http'
import { algoBadge, groupName, fmtTime } from '../utils'
import PasswordFormModal from './PasswordFormModal.vue'
import ViewModal from './ViewModal.vue'
import HistoryModal from './HistoryModal.vue'
import ExportModal from './ExportModal.vue'
import ImportModal from './ImportModal.vue'

const search = ref('')
const showForm = ref(false)
const showView = ref(false)
const showHistory = ref(false)
const showExport = ref(false)
const showImport = ref(false)
const editingEntry = ref(null)
const viewingId = ref(null)
const historyId = ref(null)

const filtered = computed(() => {
  const q = search.value.trim().toLowerCase()
  return state.entries.filter(
    (e) =>
      !q ||
      (e.username || '').toLowerCase().includes(q) ||
      (e.key_name || '').toLowerCase().includes(q)
  )
})

const allSelected = computed(
  () => filtered.value.length > 0 && filtered.value.every((e) => isSelected(e.id))
)

function toggleAll(ev) {
  if (ev.target.checked) setSelection(filtered.value.map((e) => e.id))
  else clearSelection()
}

function openAdd() {
  editingEntry.value = null
  showForm.value = true
}
function openEdit(id) {
  editingEntry.value = state.entries.find((e) => e.id === id) || null
  showForm.value = true
}
function openView(id) {
  viewingId.value = id
  showView.value = true
}
function openHistory(id) {
  historyId.value = id
  showHistory.value = true
}
function onDeleted(id) {
  requestDelete('pw', id, (state.entries.find((e) => e.id === id) || {}).username || '#' + id)
}
function afterSaved() {
  showForm.value = false
  loadEntries()
}
function openExport() {
  if (!state.isAdmin) {
    showToast('导出功能仅管理员可用')
    return
  }
  if (!state.selectedIds.length) {
    showToast('请先勾选要导出的密码')
    return
  }
  showExport.value = true
}
</script>

<template>
  <section>
    <div class="toolbar key-toolbar">
      <div class="toolbar-group">
        <label class="checkbox-inline">
          <input type="checkbox" :checked="allSelected" @change="toggleAll" /> 全选
        </label>
        <button
          v-if="state.isAdmin"
          id="export-btn"
          class="btn ghost"
          :disabled="!state.selectedIds.length"
          title="批量导出所选密码（仅管理员）"
          @click="openExport"
        >
          📤 导出{{ state.selectedIds.length ? ' (' + state.selectedIds.length + ')' : '' }}
        </button>
        <button class="btn ghost" title="批量导入密码" @click="showImport = true">📥 导入</button>
      </div>
      <div class="toolbar-group flex-grow">
        <input id="search-input" v-model="search" type="text" placeholder="搜索账号…" />
      </div>
      <div class="toolbar-group toolbar-actions">
        <button class="btn primary" title="新增一条密码" @click="openAdd">＋ 新增</button>
      </div>
    </div>

    <div id="keys-status" class="keys-status" v-html="state.keysStatus"></div>

    <table class="pw-table">
      <thead>
        <tr>
          <th></th>
          <th>账号</th>
          <th>加密方式</th>
          <th>分组</th>
          <th>更新时间</th>
          <th>操作人</th>
          <th>操作</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="e in filtered" :key="e.id">
          <td class="col-select">
            <input type="checkbox" :checked="isSelected(e.id)" @change="toggleSelect(e.id)" />
          </td>
          <td>{{ e.username || '未填' }}</td>
          <td>
            <span class="badge" :class="algoBadge(e.algorithm).cls">{{ algoBadge(e.algorithm).label }}</span>
            <span v-if="e.needs_password" title="需输入解密密码才能查看"> 🔒</span>
            <div v-if="e.key_name" style="font-size:11px;color:#6b7280;margin-top:2px">🔑 {{ e.key_name }}</div>
          </td>
          <td>{{ groupName(state.groups, e.group_id) }}</td>
          <td>{{ fmtTime(e.updated_at) }}</td>
          <td>{{ e.updated_by || e.created_by || '' }}</td>
          <td>
            <div class="ops">
              <button class="btn ghost small" @click="openView(e.id)">查看</button>
              <button class="btn ghost small" @click="openEdit(e.id)">编辑</button>
              <button class="btn ghost small" @click="openHistory(e.id)">记录</button>
              <button class="btn danger small" @click="onDeleted(e.id)">删除</button>
            </div>
          </td>
        </tr>
        <tr v-if="!filtered.length && state.entries.length">
          <td colspan="7" style="color:#6b7280">无匹配结果</td>
        </tr>
      </tbody>
    </table>

    <div v-if="!state.entries.length" class="empty">暂无密码记录，点击右上角「新增密码」开始。</div>

    <PasswordFormModal v-if="showForm" :entry="editingEntry" @close="showForm = false" @saved="afterSaved" />
    <ViewModal v-if="showView" :id="viewingId" @close="showView = false" />
    <HistoryModal v-if="showHistory" :id="historyId" @close="showHistory = false" />
    <ExportModal v-if="showExport" @close="showExport = false" />
    <ImportModal v-if="showImport" @close="showImport = false" @imported="loadEntries" />
  </section>
</template>
