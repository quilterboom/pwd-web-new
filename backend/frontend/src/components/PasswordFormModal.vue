<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { state, showWait, hideWait, showToast, showError } from '../store'
import { api } from '../api/http'

const props = defineProps({ entry: { type: Object, default: null } })
const emit = defineEmits(['close', 'saved'])

const isAdd = computed(() => !props.entry)

const form = reactive({
  username: '',
  secret: '',
  notes: '',
  comment: '',
  algorithm: 'symmetric',
  entryPassword: '',
  entryPasswordConfirm: '',
  newEntryPassword: '',
  orgkeyId: '',
  groupId: '',
})

const formError = ref('')
const lockPassword = ref('')
const lockError = ref('')
const formLocked = ref(false)
const entryLocked = ref(false) // 解锁后「解密密码」框锁定为只读
const showSecret = ref(false)
const showEntry = ref(false)

const orgkeyOptions = ref([])
const pendingOrgkeyId = ref(null)
let originalSecret = ''
let originalAlgorithm = ''
let editEntryPassword = null

/* 分组下拉直接由 state.groups 渲染；OrgKey 选项按当前算法+分组动态拉取 */
async function loadOrgkeys(preselect = null) {
  orgkeyOptions.value = []
  if (form.algorithm === 'symmetric') return
  const gid = Number(form.groupId || 0)
  if (!gid) return
  try {
    const rows = await api(`/api/orgkeys?group_id=${gid}&algorithm=${form.algorithm}`)
    orgkeyOptions.value = rows
    if (preselect != null) form.orgkeyId = String(preselect)
  } catch (e) {
    orgkeyOptions.value = []
  }
}

const showOrgkey = computed(() => form.algorithm !== 'symmetric')
const showEntryConfirm = computed(() => isAdd.value)
const showNewPw = computed(() => !isAdd.value)

function applyAlgoUI() {
  if (showOrgkey.value) loadOrgkeys(pendingOrgkeyId.value)
}

function resetForAdd() {
  form.username = ''
  form.secret = ''
  form.notes = ''
  form.comment = ''
  form.algorithm = 'symmetric'
  form.entryPassword = ''
  form.entryPasswordConfirm = ''
  form.newEntryPassword = ''
  form.orgkeyId = ''
  form.groupId = state.groups.length ? String(state.groups[0].id) : ''
  originalSecret = ''
  originalAlgorithm = ''
  editEntryPassword = null
  pendingOrgkeyId.value = null
  entryLocked.value = false
  formLocked.value = false
  formError.value = ''
  applyAlgoUI()
}

async function startEdit() {
  const rec = props.entry
  originalAlgorithm = rec.algorithm
  form.username = rec.username
  form.notes = rec.notes || ''
  form.comment = ''
  form.entryPassword = ''
  form.entryPasswordConfirm = ''
  form.newEntryPassword = ''
  form.algorithm = rec.algorithm
  form.groupId = String(rec.group_id)
  pendingOrgkeyId.value = rec.orgkey_id != null ? rec.orgkey_id : null
  formError.value = ''
  applyAlgoUI()

  if (rec.needs_password) {
    originalSecret = ''
    form.secret = ''
    formLocked.value = true
    entryLocked.value = false
  } else {
    try {
      const full = await api('/api/passwords/' + rec.id)
      originalSecret = full.secret
      form.secret = full.secret
    } catch (e) {
      showToast('加载失败：' + e.message)
    }
    formLocked.value = false
    entryLocked.value = false
  }
}

async function unlockEdit() {
  const id = props.entry.id
  const pw = lockPassword.value
  if (!pw) {
    lockError.value = '请输入当前解密密码'
    return
  }
  showWait('正在解密…')
  try {
    const full = await api('/api/passwords/' + id + '/unlock', {
      method: 'POST',
      body: JSON.stringify({ entry_password: pw }),
    })
    originalSecret = full.secret
    editEntryPassword = pw
    form.secret = full.secret
    form.entryPassword = pw
    formLocked.value = false
    // 解锁后把「解密密码」框锁为只读，禁止当场修改
    entryLocked.value = true
    lockError.value = ''
  } catch (e) {
    lockError.value = e.message
    formLocked.value = true
  } finally {
    hideWait()
  }
}

function toggleSecret() {
  showSecret.value = !showSecret.value
}
function toggleEntry() {
  showEntry.value = !showEntry.value
}

function genRandom() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#$%^&*'
  let s = ''
  for (let i = 0; i < 16; i++) s += chars[Math.floor(Math.random() * chars.length)]
  form.secret = s
  showSecret.value = true
}

async function save() {
  formError.value = ''
  const secret = form.secret
  const algo = form.algorithm
  const orgkeyId = form.orgkeyId ? Number(form.orgkeyId) : null
  if (!secret) return (formError.value = '请输入密码 / 密钥明文')
  if (!state.groups.length) return (formError.value = '你没有可用的分组，无法创建')

  const payload = {
    username: form.username.trim(),
    notes: form.notes,
    comment: form.comment,
  }

  if (isAdd.value) {
    if (!form.entryPassword) return (formError.value = '请输入解密密码')
    if (form.entryPassword !== form.entryPasswordConfirm)
      return (formError.value = '两次输入的解密密码不一致')
    const gid = Number(form.groupId)
    const uName = form.username.trim().toLowerCase()
    const dup = state.entries.find(
      (e) => e.group_id === gid && (e.username || '').trim().toLowerCase() === uName && e.algorithm === algo
    )
    if (dup)
      return (formError.value = `该分组下已存在账号「${form.username.trim()}」且加密方式相同（${algo}），请勿重复新增`)
    payload.group_id = gid
    payload.secret = secret
    payload.algorithm = algo
    payload.entry_password = form.entryPassword
    if (algo !== 'symmetric' && orgkeyId) payload.orgkey_id = orgkeyId
  } else {
    const rec = props.entry
    const needsPw = rec && rec.needs_password
    const curPw = form.entryPassword || editEntryPassword || ''
    if (needsPw && !curPw && !form.newEntryPassword)
      return (formError.value = '请输入当前解密密码才能修改')
    if (algo === 'symmetric' && !curPw && !form.newEntryPassword)
      return (formError.value = '切换到「对称加密」必须提供解密密码或新解密密码')
    if (algo !== 'symmetric' && !needsPw && !curPw && !form.newEntryPassword && !orgkeyId)
      return (formError.value = '为该记录设置解密密码后才能保存（请输入解密密码或新解密密码）')
    payload.algorithm = algo
    payload.secret = secret
    if (curPw) payload.entry_password = curPw
    if (form.newEntryPassword) payload.new_entry_password = form.newEntryPassword
    if (algo !== 'symmetric' && orgkeyId) payload.orgkey_id = orgkeyId
  }

  showWait(isAdd.value ? '正在加密保存…' : '正在解密并重新加密…')
  try {
    if (isAdd.value) {
      await api('/api/passwords', { method: 'POST', body: JSON.stringify(payload) })
      showToast('已新增')
    } else {
      await api('/api/passwords/' + props.entry.id, { method: 'PUT', body: JSON.stringify(payload) })
      showToast('已保存')
    }
    emit('saved')
  } catch (e) {
    formError.value = e.message
    showToast('保存失败：' + e.message)
  } finally {
    hideWait()
  }
}

onMounted(() => {
  if (isAdd.value) resetForAdd()
  else startEdit()
})
</script>

<template>
  <div class="modal" @click.self="emit('close')">
    <div class="modal-card">
      <h2>{{ isAdd ? '新增密码' : (props.entry && props.entry.needs_password ? '编辑密码（需先解密）' : '编辑密码') }}</h2>

      <!-- 编辑锁定区 -->
      <div v-if="formLocked" class="lock-box">
        <p class="lock-hint">🔒 该密码受「解密密码」保护，<b>先输入当前解密密码</b>才能编辑。</p>
        <div class="secret-row">
          <input v-model="lockPassword" type="password" placeholder="输入当前解密密码" autocomplete="off" @keyup.enter="unlockEdit" />
          <button type="button" class="btn primary small" @click="unlockEdit">解密并继续</button>
        </div>
        <div v-if="lockError" class="error">{{ lockError }}</div>
      </div>

      <label>账号 *</label>
      <input v-model="form.username" :disabled="formLocked" type="text" />

      <label>加密方式 *</label>
      <select v-model="form.algorithm" :disabled="formLocked" @change="applyAlgoUI">
        <option value="symmetric">对称加密（条目密码，零知识）</option>
        <option value="gpg">GPG 加密（服务端密钥 / 可选本组织密钥）</option>
        <option value="sm2">SM2 加密（国密，服务端密钥 / 可选本组织密钥）</option>
      </select>

      <label>
        解密密码 * <span class="hint">无论采用哪种加密方式都必须填写；查看 / 修改时需再次输入此密码</span>
      </label>
      <div class="secret-row">
        <input
          v-model="form.entryPassword"
          :type="showEntry ? 'text' : 'password'"
          :disabled="formLocked || entryLocked"
          :readonly="entryLocked"
          autocomplete="new-password"
        />
        <button type="button" class="btn ghost small" @click="toggleEntry">
          {{ showEntry ? '隐藏' : '显示' }}
        </button>
      </div>
      <div v-if="entryLocked" style="font-size:12px;color:#9a3412;margin-top:4px">🔒 已锁定，如需更改请用下方「新解密密码」</div>

      <label v-if="showEntryConfirm">
        确认解密密码 * <span class="hint">再次输入以确认</span>
      </label>
      <input v-if="showEntryConfirm" v-model="form.entryPasswordConfirm" :type="showEntry ? 'text' : 'password'" autocomplete="new-password" />

      <label v-if="showNewPw">新解密密码（修改后留空则沿用当前解密密码）</label>
      <input v-if="showNewPw" v-model="form.newEntryPassword" :type="showEntry ? 'text' : 'password'" autocomplete="new-password" />

      <label v-if="showOrgkey">
        加密密钥（仅 gpg / sm2，且已按所选算法筛选；留空则用服务端默认密钥）
      </label>
      <select v-if="showOrgkey" v-model="form.orgkeyId" :disabled="formLocked">
        <option value="">（默认：服务端密钥）</option>
        <option v-for="k in orgkeyOptions" :key="k.id" :value="k.id">
          {{ k.name }} · {{ k.algorithm.toUpperCase() }} {{ k.has_private ? '（含私钥）' : '（仅公钥）' }}
        </option>
      </select>
      <p v-if="showOrgkey" class="hint" style="margin:-4px 0 8px;color:#6b7280;font-size:12px;line-height:1.5">
        选择该分组下对应算法的密钥；外层用其公钥加密后，持有私钥的成员输入正确解密密码即可查看。
      </p>

      <label>所属分组 *</label>
      <select v-model="form.groupId" :disabled="formLocked || !isAdd">
        <option v-if="!state.groups.length" value="">（无可用分组，请联系管理员）</option>
        <option v-for="g in state.groups" :key="g.id" :value="String(g.id)">{{ g.name }}</option>
      </select>

      <label>
        密码明文（真实密码内容） * <span class="hint">即要保存的真实账号密码 / 密钥本身；与上方「解密密码」不同 —— 解密密码仅用于解锁本条目，请勿混淆</span>
      </label>
      <div class="secret-row">
        <input v-model="form.secret" :type="showSecret ? 'text' : 'password'" :disabled="formLocked" />
        <button type="button" class="btn ghost small" @click="toggleSecret">显示</button>
        <button type="button" class="btn ghost small" @click="genRandom">随机</button>
      </div>

      <label>备注</label>
      <textarea v-model="form.notes" rows="3" :disabled="formLocked"></textarea>

      <label>变更说明（可选，记入修改记录）</label>
      <input v-model="form.comment" type="text" placeholder="例如：季度轮换" :disabled="formLocked" />

      <div class="modal-actions">
        <button class="btn ghost" @click="emit('close')">取消</button>
        <button class="btn primary" :disabled="formLocked" @click="save">保存</button>
      </div>
      <div v-if="formError" class="error">{{ formError }}</div>
    </div>
  </div>
</template>
