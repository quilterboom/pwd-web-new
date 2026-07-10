<script setup>
import { ref } from 'vue'
import { state, api, showWait, hideWait, showToast, showError } from '../store'
import { groupName } from '../utils'

const emit = defineEmits(['close', 'saved'])

const name = ref('')
const algorithm = ref('gpg')
const groupId = ref(state.groups.length ? String(state.groups[0].id) : '')
const pub = ref('')
const priv = ref('')
const passphrase = ref('')
const showPass = ref(false)
const showPriv = ref(false)
const passRow = ref(false)
const error = ref('')

function applyPassUI() {
  const hasPriv = priv.value.trim().length > 0
  passRow.value = algorithm.value === 'gpg' && hasPriv
}

async function save() {
  error.value = ''
  if (!name.value.trim()) return (error.value = '请输入密钥名称')
  if (!pub.value) return (error.value = '请粘贴公钥内容')
  if (!groupId.value) return (error.value = '请选择所属分组')
  showWait('正在校验并导入密钥…')
  try {
    await api('/api/orgkeys/import', {
      method: 'POST',
      body: JSON.stringify({
        name: name.value.trim(),
        algorithm: algorithm.value,
        group_id: Number(groupId.value),
        public_key: pub.value,
        private_key: priv.value,
        private_passphrase: passphrase.value || '',
      }),
    })
    showToast(priv.value ? '已导入公钥 + 私钥' : '已导入公钥（无私钥）')
    emit('saved')
    emit('close')
  } catch (e) {
    error.value = e.message
    showError(e.message || '导入失败')
  } finally {
    hideWait()
  }
}

function onAlgoChange() {
  applyPassUI()
}
function onPrivInput() {
  applyPassUI()
}
function togglePass() {
  showPass.value = !showPass.value
}
function togglePriv() {
  showPriv.value = !showPriv.value
}
</script>

<template>
  <div class="modal">
    <div class="modal-card">
      <button class="modal-close" type="button" aria-label="关闭" title="关闭" @click="emit('close')">✕</button>
      <h2>导入密钥</h2>
      <label>密钥名称 *</label>
      <input v-model="name" type="text" placeholder="如：合作方公开密钥" />
      <label>加密算法 *</label>
      <select v-model="algorithm" @change="onAlgoChange">
        <option value="gpg">GPG (OpenPGP)</option>
        <option value="sm2">SM2 (国密)</option>
      </select>
      <label>所属分组 *</label>
      <select v-model="groupId">
        <option v-if="!state.groups.length" value="">（无可用分组，请联系管理员）</option>
        <option v-for="g in state.groups" :key="g.id" :value="String(g.id)">{{ g.name }}</option>
      </select>
      <label>公钥 * <span class="hint">GPG: ASCII armored PEM；SM2: 64 个十六进制字符</span></label>
      <textarea v-model="pub" rows="6" placeholder="-----BEGIN PGP PUBLIC KEY BLOCK-----&#10;…或 SM2 公钥字符串"></textarea>
      <label>私钥 <span class="hint">可选；只导入公钥也可</span></label>
      <textarea v-model="priv" rows="6" placeholder="-----BEGIN PGP PRIVATE KEY BLOCK-----&#10;…或 SM2 私钥字符串" @input="onPrivInput"></textarea>
      <label v-if="passRow">GPG 私钥口令 <span class="hint">受 passphrase 保护的私钥必填；未保护则留空</span></label>
      <div v-if="passRow" class="secret-row">
        <input v-model="passphrase" :type="showPass ? 'text' : 'password'" autocomplete="off" placeholder="输入该 GPG 私钥的口令" />
        <button type="button" class="btn ghost small" @click="togglePass">显示</button>
      </div>
      <p class="hint" style="margin-top:6px">
        提示：私钥本身是否受口令保护由 <code>gpg --list-packets</code> 或 <code>pgpdump</code> 查看 <code>protect</code> 字段。
        本系统会保留该口令以便后续解密 / 签名使用；口令会与服务端其它数据一起持久化（admin 可见）。
      </p>
      <div class="modal-actions">
        <button class="btn ghost" @click="emit('close')">取消</button>
        <button class="btn primary" @click="save">导入</button>
      </div>
      <div v-if="error" class="error">{{ error }}</div>
    </div>
  </div>
</template>
