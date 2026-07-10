<script setup>
import { computed, onMounted, ref } from 'vue'
import { state, api, showWait, hideWait, showToast } from '../store'

const props = defineProps({ user: { type: Object, default: null } })
const emit = defineEmits(['close', 'saved'])

const isAdd = computed(() => !props.user)
const username = ref('')
const password = ref('')
const isAdmin = ref(false)
const groupIds = ref([])
const error = ref('')
const showPw = ref(false)

onMounted(() => {
  if (props.user) {
    username.value = props.user.username
    isAdmin.value = props.user.is_admin
    groupIds.value = (props.user.groups || []).map((g) => g.id)
  }
})

function togglePw() {
  showPw.value = !showPw.value
}

async function save() {
  error.value = ''
  if (!username.value.trim()) return (error.value = '请输入用户名')
  if (isAdd.value && !password.value) return (error.value = '请输入密码')

  const payload = { username: username.value.trim(), is_admin: isAdmin.value, group_ids: groupIds.value }
  if (password.value) payload.password = password.value

  showWait(isAdd.value ? '正在创建用户…' : '正在更新用户…')
  try {
    if (isAdd.value) {
      await api('/api/admin/users', { method: 'POST', body: JSON.stringify(payload) })
      showToast('已创建用户')
    } else {
      await api('/api/admin/users/' + props.user.id, { method: 'PUT', body: JSON.stringify(payload) })
      showToast('已更新用户')
    }
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
  <div class="modal" @click.self="emit('close')">
    <div class="modal-card user-card">
      <div class="user-head">
        <div class="user-avatar">{{ isAdd ? '＋' : (props.user.username || 'U').slice(0, 1).toUpperCase() }}</div>
        <div class="user-head-meta">
          <h2>{{ isAdd ? '新增用户' : '编辑用户' }}</h2>
          <span v-if="!isAdd && props.user.is_admin" class="role-badge">管理员</span>
        </div>
      </div>

      <div class="form-section">
        <div class="form-section-title">账户信息</div>
        <label>用户名 *</label>
        <input v-model="username" type="text" :disabled="!isAdd" placeholder="登录用户名，创建后不可修改" />
        <label>{{ isAdd ? '密码 *' : '密码（留空则保持不变）' }}</label>
        <div class="secret-row">
          <input v-model="password" :type="showPw ? 'text' : 'password'" autocomplete="new-password" :placeholder="isAdd ? '新增时必填；编辑时留空表示不修改' : '留空表示不修改'" />
          <button type="button" class="btn ghost small" @click="togglePw">显示</button>
        </div>
      </div>

      <div class="form-section">
        <div class="form-section-title">权限与分组</div>
        <label class="switch-row" for="u-isadmin">
          <span class="switch-text">
            <b>管理员</b>
            <small>可管理用户与分组、查看所有分组数据</small>
          </span>
          <span class="switch">
            <input id="u-isadmin" v-model="isAdmin" type="checkbox" />
            <span class="slider"></span>
          </span>
        </label>
        <label>所属分组</label>
        <div class="checkbox-grid">
          <label v-for="g in state.groups" :key="g.id" class="checkbox-item">
            <input type="checkbox" :value="g.id" v-model="groupIds" /> {{ g.name }}
          </label>
          <span v-if="!state.groups.length" style="color:#6b7280">暂无可分配的分组</span>
        </div>
      </div>

      <div v-if="error" class="error">{{ error }}</div>
      <div class="modal-actions">
        <button class="btn ghost" @click="emit('close')">取消</button>
        <button class="btn primary" @click="save">保存</button>
      </div>
    </div>
  </div>
</template>
