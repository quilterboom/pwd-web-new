<script setup>
import { ref, reactive, computed, watch, onMounted } from 'vue'
import { state, showToast } from '../store'
import {
  permissionsCatalog,
  getUserPermissions,
  setUserPermissions,
  resetUserPermissions,
} from '../api/auth'

const catalog = ref([])
const selectedUid = ref(null)
const checked = reactive({}) // key -> bool
const targetIsAdmin = ref(false)
const loading = ref(false)
const saving = ref(false)

const allKeys = computed(() => catalog.value.flatMap((c) => c.items.map((i) => i.key)))
const checkedCount = computed(() => allKeys.value.filter((k) => checked[k]).length)
const targetIsGlobalAdmin = ref(false)

async function loadCatalog() {
  try {
    catalog.value = await permissionsCatalog()
    // 初始化 checked 结构
    for (const k of allKeys.value) checked[k] = true
  } catch (e) {
    showToast('加载操作目录失败：' + e.message)
  }
}

async function onSelectUser() {
  const uid = selectedUid.value
  if (!uid) {
    targetIsAdmin.value = false
    targetIsGlobalAdmin.value = false
    return
  }
  loading.value = true
  try {
    const res = await getUserPermissions(uid)
    const perms = res.permissions // null=全部可用；数组=仅清单内
    const base = perms === null ? allKeys.value : perms
    for (const k of allKeys.value) checked[k] = base.includes(k)
    const u = (state.users || []).find((x) => x.id === Number(uid))
    targetIsAdmin.value = !!(u && u.is_admin)
    targetIsGlobalAdmin.value = !!(u && u.is_admin && (!u.admin_groups || !u.admin_groups.length))
  } catch (e) {
    showToast('加载用户权限失败：' + e.message)
  } finally {
    loading.value = false
  }
}

function selectAll() {
  for (const k of allKeys.value) checked[k] = true
}
function selectNone() {
  for (const k of allKeys.value) checked[k] = false
}

async function save() {
  const uid = selectedUid.value
  if (!uid) return
  saving.value = true
  try {
    const perms = allKeys.value.filter((k) => checked[k])
    await setUserPermissions(uid, perms)
    showToast('已保存该用户的操作授权')
  } catch (e) {
    showToast('保存失败：' + e.message)
  } finally {
    saving.value = false
  }
}

async function reset() {
  const uid = selectedUid.value
  if (!uid) return
  if (!window.confirm('确认将该用户恢复为「全部操作可用」？（删除其专属授权记录）')) return
  saving.value = true
  try {
    await resetUserPermissions(uid)
    for (const k of allKeys.value) checked[k] = true
    showToast('已恢复为全部可用')
  } catch (e) {
    showToast('重置失败：' + e.message)
  } finally {
    saving.value = false
  }
}

onMounted(loadCatalog)
watch(selectedUid, onSelectUser)
</script>

<template>
  <section>
    <div class="toolbar">
      <div class="toolbar-group">
        <label class="field-label">选择用户：</label>
        <select class="search-input" v-model="selectedUid" :disabled="loading">
          <option :value="null" disabled>— 请选择用户 —</option>
          <option v-for="u in (state.users || [])" :key="u.id" :value="u.id">
            {{ u.username }}{{ u.is_admin ? '（管理员）' : '' }}
          </option>
        </select>
      </div>
      <div class="spacer"></div>
      <div class="toolbar-group" v-if="selectedUid">
        <button class="btn ghost small" type="button" @click="selectAll">全选</button>
        <button class="btn ghost small" type="button" @click="selectNone">全不选</button>
        <button class="btn ghost small" type="button" @click="reset" :disabled="saving">重置为全部可用</button>
      </div>
    </div>

    <p v-if="!selectedUid" class="perm-tip">从上方选择一名用户，勾选其允许使用的操作；未勾选的操作该用户将无法使用（后端返回 403）。</p>
    <p v-else-if="targetIsAdmin" class="perm-tip warn">
      ⚠️ {{ targetIsGlobalAdmin ? '超级管理员' : '管理员' }}不受权限限制，始终拥有全部操作权限，授权对其不生效。
    </p>

    <div v-if="selectedUid && catalog.length" class="perm-catalog">
      <div v-for="cat in catalog" :key="cat.category" class="perm-cat">
        <h4 class="perm-cat-title">{{ cat.category }}</h4>
        <div class="perm-items">
          <label v-for="item in cat.items" :key="item.key" class="perm-item">
            <input type="checkbox" v-model="checked[item.key]" :disabled="targetIsAdmin" />
            <span>{{ item.label }}</span>
          </label>
        </div>
      </div>
    </div>

    <div class="modal-actions" v-if="selectedUid">
      <span class="perm-count">已选 {{ checkedCount }} / {{ allKeys.length }} 项</span>
      <button class="btn primary" type="button" @click="save" :disabled="saving || targetIsAdmin">保存授权</button>
    </div>
  </section>
</template>

<style scoped>
.perm-tip {
  font-size: 13px;
  color: #6b7280;
  margin: 10px 0;
}
.perm-tip.warn {
  color: #b45309;
}
.perm-catalog {
  display: flex;
  flex-direction: column;
  gap: 14px;
  margin-top: 6px;
}
.perm-cat-title {
  margin: 0 0 8px;
  font-size: 14px;
  color: #111827;
  border-left: 3px solid #2563eb;
  padding-left: 8px;
}
.perm-items {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
  gap: 8px 16px;
}
.perm-item {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 14px;
  color: #374151;
  cursor: pointer;
}
.perm-count {
  font-size: 13px;
  color: #6b7280;
}
.field-label {
  font-size: 14px;
  color: #374151;
}
</style>
