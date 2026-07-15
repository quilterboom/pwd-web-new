<script setup>
import { computed, onMounted, ref, watch } from 'vue'
import { state, api, refreshMe, showToast, can } from '../store'
import { fmtTime, HISTORY_ACTION_LABELS, humanizeComment, algoBadge, groupName } from '../utils'
import UserFormModal from './UserFormModal.vue'
import GroupFormModal from './GroupFormModal.vue'
import UserBatchModal from './UserBatchModal.vue'
import PermPanel from './PermPanel.vue'

const emit = defineEmits(['close'])

const subtab = ref('users')
// 当前页数据（来自后台分页接口，仅本页条目）
const users = ref([])
const groups = ref([])
const audit = ref([])
const usersTotal = ref(0)
const groupsTotal = ref(0)
const auditTotal = ref(0)

const auditFilter = ref('all')

const userSearch = ref('')
const groupSearch = ref('')
const auditSearch = ref('')

// 分页状态（后台分页）。pageSize 同时驱动三个区块
const pageSize = ref(10)
const userPage = ref(1)
const groupPage = ref(1)
const auditPage = ref(1)

const showUserForm = ref(false)
const showGroupForm = ref(false)
const showUserBatch = ref(false)
const editingUser = ref(null)
const editingGroup = ref(null)

function buildQs(page, size, extra) {
  const p = new URLSearchParams()
  p.set('page', String(page))
  p.set('page_size', String(size))
  if (extra) {
    for (const [k, v] of Object.entries(extra)) {
      if (v !== '' && v != null) p.set(k, String(v))
    }
  }
  return p.toString()
}

// ── 后台分页拉取 ──
async function fetchUsers() {
  const qs = buildQs(userPage.value, pageSize.value, { q: userSearch.value.trim() })
  const resp = await api('/api/admin/users?' + qs)
  users.value = resp.items
  usersTotal.value = resp.total
}
async function fetchGroups() {
  const qs = buildQs(groupPage.value, pageSize.value, { q: groupSearch.value.trim() })
  const resp = await api('/api/admin/groups?' + qs)
  groups.value = resp.items
  groupsTotal.value = resp.total
}
async function fetchAudit() {
  const extra = {}
  if (auditFilter.value && auditFilter.value !== 'all') extra.action = auditFilter.value
  if (auditSearch.value.trim()) extra.q = auditSearch.value.trim()
  const qs = buildQs(auditPage.value, pageSize.value, extra)
  const resp = await api('/api/admin/audit?' + qs)
  audit.value = resp.items
  auditTotal.value = resp.total
}

// 全量加载（供新增 / 编辑分组弹框的成员列表、各下拉框使用；用超大 page_size 取全部）
async function loadUsers() {
  const resp = await api('/api/admin/users?page_size=5000')
  state.users = resp.items
}
async function loadGroups() {
  const resp = await api('/api/admin/groups?page_size=5000')
  state.groups = resp.items
}

async function switchSub(sub) {
  subtab.value = sub
  if (sub === 'audit') {
    auditPage.value = 1
    fetchAudit()
  }
}

function setAuditFilter(act, btn) {
  auditFilter.value = act
  document.querySelectorAll('#audit-filter .seg').forEach((x) => x.classList.toggle('active', x === btn))
  auditPage.value = 1
  fetchAudit()
}

onMounted(async () => {
  try {
    await Promise.all([fetchUsers(), fetchGroups(), loadUsers(), loadGroups()])
  } catch (e) {
    showToast('加载管理数据失败：' + e.message)
  }
  // 默认显示第一个当前用户有权限查看的子标签（避免子标签因权限被隐藏时默认空白）
  const permKey = { users: 'sys.user_manage', groups: 'sys.group_manage', audit: 'sys.audit_view', perm: null }
  const order = ['users', 'groups', 'audit', 'perm']
  const visible = order.filter((s) => (s === 'perm' ? state.isGlobalAdmin : can(permKey[s])))
  if (!visible.includes(subtab.value)) subtab.value = visible[0] || 'users'
})

async function afterUserSaved() {
  showUserForm.value = false
  await Promise.all([loadUsers(), fetchUsers()])
  await refreshMe()
}
async function afterGroupSaved() {
  showGroupForm.value = false
  await Promise.all([loadGroups(), fetchGroups()])
  await refreshMe()
}

async function deleteUser(id) {
  const u = users.value.find((x) => x.id === id)
  if (!window.confirm('确认删除该用户？该用户的会话将失效。')) return
  try {
    await api('/api/admin/users/' + id, { method: 'DELETE' })
    showToast('已删除用户')
    userPage.value = 1
    await Promise.all([loadUsers(), fetchUsers()])
  } catch (e) {
    showToast('删除失败：' + e.message)
  }
}

async function deleteGroup(id) {
  if (!window.confirm('确认删除该分组？若分组仍绑定数据将被阻止。')) return
  try {
    await api('/api/admin/groups/' + id, { method: 'DELETE' })
    showToast('已删除分组')
    groupPage.value = 1
    await Promise.all([loadGroups(), fetchGroups()])
  } catch (e) {
    showToast('删除失败：' + e.message)
  }
}

// ── 翻页 ──
function gotoUsers(delta) {
  userPage.value += delta
  fetchUsers()
}
function gotoGroups(delta) {
  groupPage.value += delta
  fetchGroups()
}
function gotoAudit(delta) {
  auditPage.value += delta
  fetchAudit()
}

const userPages = computed(() => Math.max(1, Math.ceil(usersTotal.value / pageSize.value)))
const groupPages = computed(() => Math.max(1, Math.ceil(groupsTotal.value / pageSize.value)))
const auditPages = computed(() => Math.max(1, Math.ceil(auditTotal.value / pageSize.value)))

// 搜索 / 筛选变化 → 回到第 1 页并重新请求
watch(userSearch, () => {
  userPage.value = 1
  fetchUsers()
})
watch(groupSearch, () => {
  groupPage.value = 1
  fetchGroups()
})
watch([auditSearch, auditFilter], () => {
  auditPage.value = 1
  fetchAudit()
})
// 每页条数变化 → 三个区块回到第 1 页并重请求
watch(pageSize, () => {
  userPage.value = 1
  groupPage.value = 1
  auditPage.value = 1
  fetchUsers()
  fetchGroups()
  if (subtab.value === 'audit') fetchAudit()
})
</script>

<template>
  <div class="modal">
    <div class="modal-card wide">
      <button class="modal-close" type="button" aria-label="关闭" title="关闭" @click="emit('close')">✕</button>
      <h2>系统管理</h2>
      <nav class="subtabs">
        <button v-if="can('sys.user_manage')" class="subtab" :class="{ active: subtab === 'users' }" @click="switchSub('users')">用户</button>
        <button v-if="can('sys.group_manage')" class="subtab" :class="{ active: subtab === 'groups' }" @click="switchSub('groups')">分组</button>
        <button v-if="can('sys.audit_view')" class="subtab" :class="{ active: subtab === 'audit' }" @click="switchSub('audit')">审计日志</button>
        <button v-if="state.isGlobalAdmin" class="subtab" :class="{ active: subtab === 'perm' }" @click="switchSub('perm')">授权管理</button>
      </nav>

      <!-- 用户 -->
      <section v-show="subtab === 'users' && can('sys.user_manage')">
        <div class="toolbar key-toolbar">
          <div class="toolbar-group toolbar-actions">
            <button v-if="can('sys.user_manage')" class="btn ghost" @click="showUserBatch = true">📥 批量新增</button>
            <button v-if="can('sys.user_manage')" class="btn primary" @click="(editingUser = null, showUserForm = true)">＋ 新增用户</button>
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
            <tr v-for="u in users" :key="u.id">
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
                  <button v-if="can('sys.user_manage')" class="btn ghost small" @click="(editingUser = u, showUserForm = true)">编辑</button>
                  <button v-if="can('sys.user_manage')" class="btn danger small" @click="deleteUser(u.id)">删除</button>
                </div>
              </td>
            </tr>
            <tr v-if="!users.length"><td colspan="4" style="color:#6b7280">无匹配的用户</td></tr>
          </tbody>
        </table>
        <div class="pager" v-if="usersTotal > 0">
          <select class="pager-size" v-model="pageSize">
            <option :value="10">10</option>
            <option :value="20">20</option>
            <option :value="50">50</option>
          </select>
          <button class="btn ghost small" :disabled="userPage <= 1" @click="gotoUsers(-1)">‹ 上一页</button>
          <span class="pager-info">第 {{ userPage }} / {{ userPages }} 页 · 共 {{ usersTotal }} 条</span>
          <button class="btn ghost small" :disabled="userPage >= userPages" @click="gotoUsers(1)">下一页 ›</button>
        </div>
      </section>

      <!-- 分组 -->
      <section v-show="subtab === 'groups' && can('sys.group_manage')">
        <div class="toolbar">
          <div class="spacer"></div>
          <div class="toolbar-group">
            <input class="search-input" v-model="groupSearch" type="text" placeholder="搜索分组名…" />
          </div>
          <button v-if="can('sys.group_manage')" class="btn primary" @click="(editingGroup = null, showGroupForm = true)">＋ 新增分组</button>
        </div>
        <table class="pw-table">
          <thead>
            <tr><th>分组名</th><th>成员数</th><th>成员</th><th>操作</th></tr>
          </thead>
          <tbody>
            <tr v-for="g in groups" :key="g.id">
              <td>{{ g.name }}</td>
              <td>{{ g.member_count }}</td>
              <td>{{ g.members.map((m) => m.username).join('、') || '—' }}</td>
              <td>
                <div class="ops">
                  <button v-if="can('sys.group_manage')" class="btn ghost small" @click="(editingGroup = g, showGroupForm = true)">编辑</button>
                  <button v-if="can('sys.group_manage')" class="btn danger small" @click="deleteGroup(g.id)">删除</button>
                </div>
              </td>
            </tr>
            <tr v-if="!groups.length"><td colspan="4" style="color:#6b7280">无匹配的分组</td></tr>
          </tbody>
        </table>
        <div class="pager" v-if="groupsTotal > 0">
          <select class="pager-size" v-model="pageSize">
            <option :value="10">10</option>
            <option :value="20">20</option>
            <option :value="50">50</option>
          </select>
          <button class="btn ghost small" :disabled="groupPage <= 1" @click="gotoGroups(-1)">‹ 上一页</button>
          <span class="pager-info">第 {{ groupPage }} / {{ groupPages }} 页 · 共 {{ groupsTotal }} 条</span>
          <button class="btn ghost small" :disabled="groupPage >= groupPages" @click="gotoGroups(1)">下一页 ›</button>
        </div>
      </section>

      <!-- 审计 -->
      <section v-show="subtab === 'audit' && can('sys.audit_view')">
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
            <input class="search-input" v-model="auditSearch" type="text" placeholder="搜索用户名 / 密码文件名称 / 分组 / 操作人…" />
          </div>
        </div>
        <table class="pw-table hist-table">
          <thead>
            <tr><th>时间</th><th>动作</th><th>用户名</th><th>分组</th><th>操作人</th><th>说明</th></tr>
          </thead>
          <tbody>
            <tr v-for="r in audit" :key="r.id">
              <td>{{ fmtTime(r.changed_at) }}</td>
              <td :class="'act-' + r.action">{{ HISTORY_ACTION_LABELS[r.action] || r.action }}</td>
              <td>{{ r.username || '' }}</td>
              <td>{{ r.group_name || '—' }}</td>
              <td>{{ r.changed_by || '' }}</td>
              <td><div class="comment-cell" :title="humanizeComment(r.comment || '')">{{ humanizeComment(r.comment || '') }}</div></td>
            </tr>
            <tr v-if="!audit.length"><td colspan="6" style="color:#6b7280">无匹配的审计记录</td></tr>
          </tbody>
        </table>
        <div class="pager" v-if="auditTotal > 0">
          <select class="pager-size" v-model="pageSize">
            <option :value="10">10</option>
            <option :value="20">20</option>
            <option :value="50">50</option>
          </select>
          <button class="btn ghost small" :disabled="auditPage <= 1" @click="gotoAudit(-1)">‹ 上一页</button>
          <span class="pager-info">第 {{ auditPage }} / {{ auditPages }} 页 · 共 {{ auditTotal }} 条</span>
          <button class="btn ghost small" :disabled="auditPage >= auditPages" @click="gotoAudit(1)">下一页 ›</button>
        </div>
        <p class="audit-tip">说明：删除密码会在此生成一条「删除」记录，含操作人与用户名，便于管理员审计。</p>
      </section>

      <PermPanel v-if="subtab === 'perm'" />

      <div class="modal-actions">
        <button class="btn ghost" @click="emit('close')">关闭</button>
      </div>
    </div>

    <UserFormModal v-if="showUserForm" :user="editingUser" @close="showUserForm = false" @saved="afterUserSaved" />
    <GroupFormModal v-if="showGroupForm" :group="editingGroup" @close="showGroupForm = false" @saved="afterGroupSaved" />
    <UserBatchModal v-if="showUserBatch" @close="showUserBatch = false" @imported="loadUsers" />
  </div>
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
  width: 50px;
  flex: 0 0 50px;
  padding: 5px 8px;
  border: 1px solid #d1d5db;
  border-radius: 6px;
  background: #fff;
  font-size: 13px;
  color: #111827;
}
</style>
