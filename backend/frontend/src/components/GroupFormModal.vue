<script setup>
import { computed, onMounted, ref } from 'vue'
import { state, api, showWait, hideWait, showToast } from '../store'

const props = defineProps({ group: { type: Object, default: null } })
const emit = defineEmits(['close', 'saved'])

const isAdd = computed(() => !props.group)
const name = ref('')
const description = ref('')
const memberIds = ref([])
const error = ref('')

onMounted(() => {
  if (props.group) {
    name.value = props.group.name
    description.value = props.group.description || ''
    memberIds.value = (props.group.members || []).map((m) => m.id)
  }
})

async function save() {
  error.value = ''
  if (!name.value.trim()) return (error.value = '请输入分组名称')
  const payload = { name: name.value.trim(), description: description.value, member_ids: memberIds.value }
  showWait(isAdd.value ? '正在创建分组…' : '正在更新分组…')
  try {
    if (isAdd.value) {
      await api('/api/admin/groups', { method: 'POST', body: JSON.stringify(payload) })
      showToast('已创建分组')
    } else {
      await api('/api/admin/groups/' + props.group.id, { method: 'PUT', body: JSON.stringify(payload) })
      showToast('已更新分组')
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
    <div class="modal-card">
      <h2>{{ isAdd ? '新增分组' : '编辑分组：' + name }}</h2>
      <label>分组名称 *</label>
      <input v-model="name" type="text" />
      <label>描述</label>
      <input v-model="description" type="text" />
      <label>成员</label>
      <div class="checkbox-list">
        <label v-for="u in state.users" :key="u.id" class="checkbox-item">
          <input type="checkbox" :value="u.id" v-model="memberIds" /> {{ u.username }}
        </label>
        <span v-if="!state.users.length" style="color:#6b7280">暂无可加入的用户</span>
      </div>
      <div v-if="error" class="error">{{ error }}</div>
      <div class="modal-actions">
        <button class="btn ghost" @click="emit('close')">取消</button>
        <button class="btn primary" @click="save">保存</button>
      </div>
    </div>
  </div>
</template>
