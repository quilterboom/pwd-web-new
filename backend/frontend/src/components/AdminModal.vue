<script setup>
import { computed, onMounted, ref } from 'vue'
import { state, api, refreshMe, showToast } from '../store'
import { fmtTime, HISTORY_ACTION_LABELS, humanizeComment, algoBadge, groupName } from '../utils'
import UserFormModal from './UserFormModal.vue'
import GroupFormModal from './GroupFormModal.vue'
import UserBatchModal from './UserBatchModal.vue'

const emit = defineEmits(['close'])

const subtab = ref('users')
const users = ref([])
const groups = ref([])
const audit = ref([])
const auditFilter = ref('all')

const userSearch = ref('')
const groupSearch = ref('')
const auditSearch = ref('')

const filteredUsers = computed(() => {
  const q = userSearch.value.trim().toLowerCase()
  if (!q) return users.value
  return users.value.filter(
    (u) =>
      u.username.toLowerCase().includes(q) ||
      (u.groups || []).some((g) => g.name.toLowerCase().includes(q)) ||
      (u.admin_groups || []).some((g) => g.name.toLowerCase().includes(q))
  )
})
const filteredGroups = computed(() => {
  const q = groupSearch.value.trim().toLowerCase()
  if (!q) return groups.value
  return groups.value.filter(
    (g) =>
      g.name.toLowerCase().includes(q) ||
      (g.members || []).some((m) => m.username.toLowerCase().includes(q))
  )
})
const filteredAudit = computed(() => {
  const q = auditSearch.value.trim().toLowerCase()
  if (!q) return audit.value
  return audit.value.filter((r) =>
    [r.username, r.title, r.group_name, r.changed_by, humanizeComment(r.comment || '')]
      .filter(Boolean)
      .some((f) => f.toLowerCase().includes(q))
  )
})

const showUserForm = ref(false)
const showGroupForm = ref(false)
const showUserBatch = ref(false)
const editingUser = ref(null)
const editingGroup = ref(null)

async function loadUsers() {
  users.value = await api('/api/admin/users')
  // 同步给全局 state，供「新增/编辑分组」弹框的成员列表使用
  state.users = users.value
}
async function loadGroups() {
  groups.value = await api('/api/admin/groups')
}
async function loadAudit() {
  const q = auditFilter.value && auditFilter.value !== 'all' ? '?action=' + encodeURIComponent(auditFilter.value) : ''
  audit.value = await api('/api/admin/audit' + q)
}

async function switchSub(sub) {
  subtab.value = sub
  if (sub === 'audit') loadAudit()
}

function setAuditFilter(act, btn) {
  auditFilter.value = act
  document.querySelectorAll('#audit-filter .seg').forEach((x) => x.classList.toggle('active', x === btn))
  loadAudit()
}

onMounted(async () => {
  try {
    await Promise.all([loadUsers(), loadGroups()])
  } catch (e) {
    showToast('加载管理数据失败：' + e.message)
  }
})

async function afterUserSaved() {
  showUserForm.value = false
  await loadUsers()
  await refreshMe()
}
async function afterGroupSaved() {
  showGroupForm.value = false
  await loadGroups()
  await refreshMe()
}

async function deleteUser(id) {
  const u = users.value.find((x) => x.id === id)
  if (!window.confirm('确认删除该用户？该用户的会话将失效。')) return
  try {
    await api('/api/admin/users/' + id, { method: 'DELETE' })
    showToast('已删除用户')
    await loadUsers()
  } catch (e) {
    showToast('删除失败：' + e.message)
  }
}

async function deleteGroup(id) {
  if (!window.confirm('确认删除该分组？若分组仍绑定数据将被阻止。')) return
  try {
    await api('/api/admin/groups/' + id, { method: 'DELETE' })
    showToast('已删除分组')
    await loadGroups()
  } catch (e) {
    showToast('删除失败：' + e.message)
  }
}
</script>

<template>
  <div class="modal">
    <div class="modal-card wide">
      <button class="modal-close" type="button" aria-label="关闭" title="关闭" @click="emit('close')">✕</button>
      <h2>系统管理</h2>
      <nav class="subtabs">
        <button class="subtab" :class="{ active: subtab === 'users' }" @click="switchSub('users')">用户</button>
        <button class="subtab" :class="{ active: subtab === 'groups' }" @click="switchSub('groups')">分组</button>
        <button class="subtab" :class="{ active: subtab === 'audit' }" @click="switchSub('audit')">审计日志</button>
      </nav>

      <!-- 用户 -->
      <section v-show="subtab === 'users'">
        <div class="toolbar key-toolbar">
          <div class="toolbar-group toolbar-actions">
            <button class="btn ghost" @click="showUserBatch = true">📥 批量新增</button>
            <button class="btn primary" @click="(editingUser = null, showUserForm = true)">＋ 新增用户</button>
          </div>
          <div class="spacer"></div>
          <div class="toolbar-group">
            <input class="search-input" v-model="userSearch" type="text" placeholder="搜索用户名 / 分组…" />
          </div>
        </div>
        <table class="pw-table">
          <thead>
            <tr><th>用户名</th><th>管理员</th><th>所属分组</th><th>操作</th></tr>
          </thead>
          <tbody>
            <tr v-for="u in filteredUsers" :key="u.id">
              <td>{{ u.username }}</td>
              <td>
                <span v-if="u.is_admin">是</span>
                <span v-else>否</span>
                <div v-if="u.is_admin" class="admin-scope">
                  <template v-if="u.admin_groups && u.admin_groups.length">
                    管理：{{ u.admin_groups.map((g) => g.name).join('、') }}
                  </template>
                  <template v-else>管理：全部分组</template>
                </div>
              </td>
              <td>{{ u.groups.map((g) => g.name).join('、') || '—' }}</td>
              <td>
                <div class="ops">
                  <button class="btn ghost small" @click="(editingUser = u, showUserForm = true)">编辑</button>
                  <button class="btn danger small" @click="deleteUser(u.id)">删除</button>
                </div>
              </td>
            </tr>
            <tr v-if="!filteredUsers.length"><td colspan="4" style="color:#6b7280">无匹配的用户</td></tr>
          </tbody>
        </table>
      </section>

      <!-- 分组 -->
      <section v-show="subtab === 'groups'">
        <div class="toolbar">
          <div class="spacer"></div>
          <div class="toolbar-group">
            <input class="search-input" v-model="groupSearch" type="text" placeholder="搜索分组名 / 成员…" />
          </div>
          <button class="btn primary" @click="(editingGroup = null, showGroupForm = true)">＋ 新增分组</button>
        </div>
        <table class="pw-table">
          <thead>
            <tr><th>分组名</th><th>成员数</th><th>成员</th><th>操作</th></tr>
          </thead>
          <tbody>
            <tr v-for="g in filteredGroups" :key="g.id">
              <td>{{ g.name }}</td>
              <td>{{ g.member_count }}</td>
              <td>{{ g.members.map((m) => m.username).join('、') || '—' }}</td>
              <td>
                <div class="ops">
                  <button class="btn ghost small" @click="(editingGroup = g, showGroupForm = true)">编辑</button>
                  <button class="btn danger small" @click="deleteGroup(g.id)">删除</button>
                </div>
              </td>
            </tr>
            <tr v-if="!filteredGroups.length"><td colspan="4" style="color:#6b7280">无匹配的分组</td></tr>
          </tbody>
        </table>
      </section>

      <!-- 审计 -->
      <section v-show="subtab === 'audit'">
        <div class="toolbar">
          <div class="toolbar-group">
            <div class="seg-group" id="audit-filter" role="group" aria-label="审计类型筛选">
              <button class="seg" :class="{ active: auditFilter === 'all' }" @click="setAuditFilter('all', $event.target)">全部</button>
              <button class="seg" :class="{ active: auditFilter === 'create' }" @click="setAuditFilter('create', $event.target)">新增</button>
              <button class="seg" :class="{ active: auditFilter === 'update' }" @click="setAuditFilter('update', $event.target)">修改</button>
              <button class="seg" :class="{ active: auditFilter === 'delete' }" @click="setAuditFilter('delete', $event.target)">删除</button>
            </div>
          </div>
          <div class="spacer"></div>
          <div class="toolbar-group">
            <input class="search-input" v-model="auditSearch" type="text" placeholder="搜索账号 / 标题 / 分组 / 操作人…" />
          </div>
        </div>
        <table class="pw-table hist-table">
          <thead>
            <tr><th>时间</th><th>动作</th><th>账号</th><th>标题</th><th>分组</th><th>操作人</th><th>说明</th></tr>
          </thead>
          <tbody>
            <tr v-for="r in filteredAudit" :key="r.id">
              <td>{{ fmtTime(r.changed_at) }}</td>
              <td :class="'act-' + r.action">{{ HISTORY_ACTION_LABELS[r.action] || r.action }}</td>
              <td>{{ r.username || '' }}</td>
              <td>{{ r.title || '' }}</td>
              <td>{{ r.group_name || '—' }}</td>
              <td>{{ r.changed_by || '' }}</td>
              <td>{{ humanizeComment(r.comment || '') }}</td>
            </tr>
            <tr v-if="!filteredAudit.length"><td colspan="7" style="color:#6b7280">无匹配的审计记录</td></tr>
          </tbody>
        </table>
        <p class="audit-tip">说明：删除密码会在此生成一条「删除」记录，含操作人与账号，便于管理员审计。</p>
      </section>

      <div class="modal-actions">
        <button class="btn ghost" @click="emit('close')">关闭</button>
      </div>
    </div>

    <UserFormModal v-if="showUserForm" :user="editingUser" @close="showUserForm = false" @saved="afterUserSaved" />
    <GroupFormModal v-if="showGroupForm" :group="editingGroup" @close="showGroupForm = false" @saved="afterGroupSaved" />
    <UserBatchModal v-if="showUserBatch" @close="showUserBatch = false" @imported="loadUsers" />
  </div>
</template>
